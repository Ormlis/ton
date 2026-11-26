/*
 * Copyright (c) 2025-2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "auto/tl/ton_api.hpp"
#include "keys/encryptor.h"
#include "td/utils/overloaded.h"

#include "bus.h"
#include "payload.h"
#include "types.h"

namespace ton::validator::consensus {

const PeerValidator& PeerValidatorId::get_using(const Bus& bus) const {
  return bus.validator_set[idx_];
}

td::StringBuilder& operator<<(td::StringBuilder& stream, const PeerValidatorId& id) {
  return stream << "validator " << id.value();
}

bool check_consensus_signature(const PublicKey& key, ValidatorSessionId session, td::Slice data, td::Slice signature) {
  auto signed_data = create_serialize_tl_object<tl::dataToSign>(session, td::BufferSlice(data));
  TD_PERF_COUNTER(check_signature_consensus);
  auto encryptor = key.create_encryptor();
  if (encryptor.is_error()) {
    return false;
  }
  return encryptor.move_as_ok()->check_signature(signed_data, signature, td::SignatureDomain::Consensus).is_ok();
}

bool PeerValidator::check_signature(ValidatorSessionId session, td::Slice data, td::Slice signature) const {
  return check_consensus_signature(key, session, data, signature);
}

td::StringBuilder& operator<<(td::StringBuilder& stream, const PeerValidator& peer_validator) {
  return stream << peer_validator.idx << " (id " << peer_validator.short_id << " adnl " << peer_validator.adnl_id
                << ")";
}

CandidateId CandidateId::from_tl(const tl::CandidateIdRef& tl_parent) {
  return CandidateId{static_cast<td::uint32>(tl_parent->slot_), tl_parent->hash_};
}

tl::CandidateIdRef CandidateId::to_tl() const {
  return create_tl_object<tl::candidateId>(slot, hash);
}

td::StringBuilder& operator<<(td::StringBuilder& stream, const CandidateId& id) {
  return stream << "{" << id.slot << ", " << id.hash << ", ?}";
}

td::StringBuilder& operator<<(td::StringBuilder& stream, const ParentId& id) {
  if (id.has_value()) {
    return stream << *id;
  } else {
    return stream << "consensus genesis";
  }
}

tl::CandidateParentRef CandidateId::parent_id_to_tl(ParentId parent) {
  if (!parent) {
    return create_tl_object<tl::candidateWithoutParents>();
  } else {
    return create_tl_object<tl::candidateParent>(parent->to_tl());
  }
}

ParentId CandidateId::tl_to_parent_id(const tl::CandidateParentRef& tl_parent) {
  ParentId id;
  auto without_parents_fn = [&](const tl::candidateWithoutParents&) {};
  auto parent_fn = [&](const tl::candidateParent& parent) { id = CandidateId::from_tl(parent.id_); };
  ton_api::downcast_call(*tl_parent, td::overloaded(without_parents_fn, parent_fn));
  return id;
}

static auto tl_block_ids(const BlockReferences& ids) {
  std::vector<tl_object_ptr<ton_api::tonNode_blockIdExt>> result;
  for (const auto& id : ids) {
    result.push_back(create_tl_block_id(id));
  }
  return result;
}

CandidateHashData CandidateHashData::from(const CandidateContents& contents, ParentId parent) {
  CandidateHashData data{{}, {}, parent};
  if (auto refs = std::get_if<BlockReferences>(&contents)) {
    data.blocks = *refs;
  } else {
    for (const auto& block : std::get<CandidateBlocks>(contents)) {
      data.blocks.push_back(block.id);
      data.collated_file_hashes.push_back(block.collated_file_hash);
    }
  }
  return data;
}

CandidateId CandidateHashData::build_id_with(td::uint32 slot) const {
  return CandidateId{slot, get_tl_object_sha_bits256(to_tl())};
}

tl::CandidateHashDataRef CandidateHashData::to_tl() const {
  if (blocks.size() > 1) {
    return create_tl_object<ton_api::consensus_candidateHashDataGroup>(
        tl_block_ids(blocks), std::vector<td::Bits256>(collated_file_hashes), CandidateId::parent_id_to_tl(parent));
  }
  CHECK(blocks.size() == 1);
  if (collated_file_hashes.empty()) {
    return create_tl_object<tl::candidateHashDataEmpty>(create_tl_block_id(blocks.front()), parent->to_tl());
  }
  return create_tl_object<tl::candidateHashDataOrdinary>(
      create_tl_block_id(blocks.front()), collated_file_hashes.front(), CandidateId::parent_id_to_tl(parent));
}

td::Status check_delegation(const Delegation& delegation, const PeerValidator& leader, td::uint32 slot,
                            const Bus& bus) {
  auto collator_id = adnl::AdnlNodeIdShort{delegation.collator_key.compute_short_id()};
  td::uint32 window_start = slot - slot % bus.config.slots_per_leader_window;
  auto to_sign = create_serialize_tl_object<tl::delegationToSign>(window_start, collator_id.bits256_value());
  if (!leader.check_signature(bus.session_id, to_sign, delegation.signature)) {
    return td::Status::Error("Delegation signature is not valid");
  }
  return td::Status::OK();
}

std::optional<Delegation> Delegation::from_tl(tl::DelegationRef tl_delegation) {
  if (!tl_delegation) {
    return std::nullopt;
  }
  return Delegation{PublicKey{tl_delegation->collator_key_}, std::move(tl_delegation->signature_)};
}

tl::DelegationRef Delegation::to_tl() const {
  return create_tl_object<tl::delegation>(collator_key.tl(), signature.clone());
}

td::Result<CandidateRef> Candidate::deserialize(td::Slice data, const Bus& bus,
                                                std::optional<td::uint32> expected_slot) {
  if (!bus.group_members.empty() && data.size() > Bus::max_group_candidate_bytes) {
    return td::Status::Error("Shard group candidate exceeds wire size limit");
  }
  if (auto maybe_broadcast = fetch_tl_object<tl::CandidateData>(data, true); maybe_broadcast.is_ok()) {
    return deserialize_data(maybe_broadcast.move_as_ok(), std::nullopt, bus, expected_slot);
  }
  TRY_RESULT(wrapper, fetch_tl_object<tl::candidate>(data, true));
  return deserialize_data(std::move(wrapper->data_), Delegation::from_tl(std::move(wrapper->delegation_)), bus,
                          expected_slot);
}

td::Result<CandidateRef> Candidate::deserialize_from_broadcast(td::Slice data, Signer signer, const Bus& bus,
                                                               td::uint32 expected_slot) {
  if (!bus.group_members.empty() && data.size() > Bus::max_group_candidate_bytes) {
    return td::Status::Error("Shard group broadcast exceeds wire size limit");
  }
  TRY_RESULT(broadcast, fetch_tl_object<tl::CandidateData>(data, true));
  return deserialize_data(std::move(broadcast), std::move(signer), bus, expected_slot);
}

td::Result<Candidate::DecodedMember> Candidate::decode_member(td::BufferSlice encoded, ShardIdFull shard,
                                                              const PublicKey& leader, td::uint32 max_block_size,
                                                              td::uint32 max_collated_data_size) {
  auto limit =
      static_cast<int>(std::min<td::uint64>(0x7fffffff, td::uint64(max_block_size) + max_collated_data_size + 1024));
  TRY_RESULT(decoded, deserialize_payload(encoded, limit));
  auto& candidate = decoded.payload;
  if (!candidate->src_.is_zero()) {
    return td::Status::Error("src field of the candidate broadcast must be null");
  }
  if (candidate->data_.size() > max_block_size || candidate->collated_data_.size() > max_collated_data_size) {
    return td::Status::Error(PSTRING() << "Too big candidate broadcast with data_size=" << candidate->data_.size()
                                       << ", collated_data_size=" << candidate->collated_data_.size());
  }
  if (decoded.roots->block_root->get_hash().as_bits256() != candidate->root_hash_) {
    return td::Status::Error("Candidate block root hash mismatch");
  }
  BlockIdExt id{BlockId{shard, static_cast<BlockSeqno>(candidate->round_)}, candidate->root_hash_,
                decoded.roots->block_file_hash};
  BlockCandidate block{Ed25519_PublicKey{leader.ed25519_value().raw()}, id, decoded.roots->collated_file_hash,
                       std::move(candidate->data_), std::move(candidate->collated_data_)};
  return DecodedMember{std::move(block), std::move(decoded.roots), std::move(encoded)};
}

namespace {
td::Result<const PeerValidator*> candidate_leader(td::uint32 slot, const Candidate::Signer* signer, const Bus& bus) {
  const auto& leader = bus.collator_schedule->expected_collator_for(slot).get_using(bus);
  if (signer) {
    if (auto peer = std::get_if<PeerValidatorId>(signer); peer && *peer != leader.idx) {
      return td::Status::Error("Candidate broadcast source does not match expected leader");
    }
  }
  return &leader;
}

struct ParsedCandidate {
  td::uint32 slot;
  ParentId parent;
  std::variant<BlockReferences, std::vector<Candidate::DecodedMember>> contents;
  td::BufferSlice signature;

  td::Result<CandidateRef> verify(std::optional<Candidate::Signer> signer, const PeerValidator& leader, const Bus& bus,
                                  std::optional<CandidateId> expected_id = {}) && {
    CandidateContents block;
    std::vector<td::BufferSlice> encoded;
    std::vector<CandidateRootsRef> roots;
    if (auto* refs = std::get_if<BlockReferences>(&contents)) {
      block = std::move(*refs);
    } else {
      auto& members = std::get<std::vector<Candidate::DecodedMember>>(contents);
      if (members.size() != (bus.group_members.empty() ? 1 : bus.group_members.size())) {
        return td::Status::Error("Wrong number of candidate members");
      }
      CandidateBlocks blocks;
      for (size_t i = 0; i < members.size(); ++i) {
        auto& member = members[i];
        if (!bus.group_members.empty()) {
          if (member.block.id.shard_full() != bus.group_members[i]) {
            return td::Status::Error("Wrong shard in group candidate");
          }
          encoded.push_back(std::move(member.encoded));
        }
        blocks.push_back(std::move(member.block));
        roots.push_back(std::move(member.roots));
      }
      block = std::move(blocks);
    }
    auto id = CandidateHashData::from(block, parent).build_id_with(slot);
    if (expected_id && id != *expected_id) {
      return td::Status::Error("Shard group candidate hash mismatch");
    }
    auto signed_data = serialize_tl_object(id.to_tl(), true);
    std::optional<Delegation> delegation;
    if (signer && std::holds_alternative<Delegation>(*signer)) {
      delegation = std::get<Delegation>(std::move(*signer));
      TRY_STATUS(check_delegation(*delegation, leader, slot, bus));
      if (!check_consensus_signature(delegation->collator_key, bus.session_id, signed_data, signature)) {
        return td::Status::Error("Delegated candidate broadcast signature is not valid");
      }
    } else if (!leader.check_signature(bus.session_id, signed_data, signature)) {
      return td::Status::Error("Candidate broadcast signature is not valid");
    }
    return td::make_ref<Candidate>(id, parent, leader.idx, std::move(block), std::move(signature),
                                   std::move(delegation), std::move(encoded), std::move(roots));
  }
};
}  // namespace

td::Result<CandidateRef> Candidate::from_group_parts(CandidateId id, ParentId parent,
                                                     std::vector<DecodedMember> members, td::BufferSlice signature,
                                                     Signer signer, const Bus& bus) {
  if (bus.group_members.empty()) {
    return td::Status::Error("Unexpected group candidate");
  }
  TRY_RESULT(leader, candidate_leader(id.slot, &signer, bus));
  return ParsedCandidate{id.slot, parent, std::move(members), std::move(signature)}.verify(std::move(signer), *leader,
                                                                                           bus, id);
}

td::Result<CandidateRef> Candidate::deserialize_data(tl::CandidateDataRef broadcast, std::optional<Signer> signer,
                                                     const Bus& bus, std::optional<td::uint32> expected_slot) {
  td::uint32 slot = 0;
  ton_api::downcast_call(*broadcast, [&](auto& b) { slot = static_cast<td::uint32>(b.slot_); });
  if (expected_slot && *expected_slot != slot) {
    return td::Status::Error("Candidate broadcast has unexpected slot");
  }
  TRY_RESULT(leader, candidate_leader(slot, signer ? &*signer : nullptr, bus));
  auto decode = [&](td::BufferSlice encoded, ShardIdFull shard) {
    return decode_member(std::move(encoded), shard, leader->key, bus.config.max_block_size,
                         bus.config.max_collated_data_size);
  };
  auto empty_fn = [&](tl::empty& b) -> td::Result<ParsedCandidate> {
    if (!bus.group_members.empty()) {
      return td::Status::Error("Single-block reference in a shard group session");
    }
    return ParsedCandidate{slot, CandidateId::from_tl(b.parent_), BlockReferences{create_block_id(b.block_)},
                           std::move(b.signature_)};
  };
  auto ordinary_fn = [&](tl::block& b) -> td::Result<ParsedCandidate> {
    if (!bus.group_members.empty()) {
      return td::Status::Error("Single block in a shard group session");
    }
    TRY_RESULT(member, decode(std::move(b.candidate_), bus.shard));
    std::vector<DecodedMember> members;
    members.push_back(std::move(member));
    return ParsedCandidate{slot, CandidateId::tl_to_parent_id(b.parent_), std::move(members), std::move(b.signature_)};
  };
  auto group_fn = [&](ton_api::consensus_blockGroup& b) -> td::Result<ParsedCandidate> {
    if (bus.group_members.empty() || b.candidates_.size() != bus.group_members.size()) {
      return td::Status::Error("Wrong number of shard group members");
    }
    std::vector<DecodedMember> members;
    for (size_t i = 0; i < b.candidates_.size(); ++i) {
      TRY_RESULT(member, decode(std::move(b.candidates_[i]), bus.group_members[i]));
      members.push_back(std::move(member));
    }
    return ParsedCandidate{slot, CandidateId::tl_to_parent_id(b.parent_), std::move(members), std::move(b.signature_)};
  };
  auto group_empty_fn = [&](ton_api::consensus_emptyGroup& b) -> td::Result<ParsedCandidate> {
    if (bus.group_members.empty() || b.blocks_.size() != bus.group_members.size()) {
      return td::Status::Error("Incomplete shard group reference");
    }
    BlockReferences refs;
    for (size_t i = 0; i < b.blocks_.size(); ++i) {
      refs.push_back(create_block_id(b.blocks_[i]));
      if (refs.back().shard_full() != bus.group_members[i]) {
        return td::Status::Error("Wrong shard in empty group candidate");
      }
    }
    return ParsedCandidate{slot, CandidateId::from_tl(b.parent_), std::move(refs), std::move(b.signature_)};
  };
  td::Result<ParsedCandidate> result;
  ton_api::downcast_call(*broadcast,
                         [&](auto& b) { result = td::overloaded(empty_fn, ordinary_fn, group_fn, group_empty_fn)(b); });
  TRY_RESULT(parsed, std::move(result));
  return std::move(parsed).verify(std::move(signer), *leader, bus);
}

BlockIdExt Candidate::block_id() const {
  return is_empty() ? std::get<BlockReferences>(block).front() : blocks().front().id;
}

BlockReferences Candidate::block_ids() const {
  return hash_data().blocks;
}

CandidateHashData Candidate::hash_data() const {
  return CandidateHashData::from(block, parent_id);
}

td::Result<td::BufferSlice> Candidate::encode_block(const BlockCandidate& candidate, CandidateRootsRef roots) {
  auto payload =
      create_tl_object<ton_api::validatorSession_candidate>(td::Bits256{}, candidate.id.seqno(), candidate.id.root_hash,
                                                            candidate.data.clone(), candidate.collated_data.clone());
  return serialize_payload({std::move(payload), std::move(roots)});
}

std::vector<td::BufferSlice> Candidate::encoded_blocks() const {
  std::vector<td::BufferSlice> payloads;
  if (encoded_members_.empty()) {
    for (size_t i = 0; i < blocks().size(); ++i) {
      payloads.push_back(encode_block(blocks()[i], roots_for(i)).move_as_ok());
    }
  } else {
    for (const auto& encoded : encoded_members_) {
      payloads.push_back(encoded.clone());
    }
  }
  return payloads;
}

tl::CandidateDataRef Candidate::to_data_tl() const {
  if (is_empty()) {
    const auto& refs = std::get<BlockReferences>(block);
    if (refs.size() > 1) {
      return create_tl_object<ton_api::consensus_emptyGroup>(id.slot, parent_id->to_tl(), tl_block_ids(refs),
                                                             signature.clone());
    }
    return create_tl_object<tl::empty>(id.slot, parent_id->to_tl(), create_tl_block_id(refs.front()),
                                       signature.clone());
  }
  auto payloads = encoded_blocks();
  if (payloads.size() > 1) {
    return create_tl_object<ton_api::consensus_blockGroup>(id.slot, CandidateId::parent_id_to_tl(parent_id),
                                                           std::move(payloads), signature.clone());
  }
  return create_tl_object<tl::block>(id.slot, CandidateId::parent_id_to_tl(parent_id), std::move(payloads.front()),
                                     signature.clone());
}

td::BufferSlice Candidate::serialize() const {
  if (!delegation.has_value()) {
    return serialize_for_broadcast();
  }
  return create_serialize_tl_object<tl::candidate>(1, to_data_tl(), delegation->to_tl());
}

td::BufferSlice Candidate::serialize_for_broadcast() const {
  return serialize_tl_object(to_data_tl(), true);
}

bool Candidate::is_empty() const {
  return std::holds_alternative<BlockReferences>(block);
}

adnl::AdnlNodeIdShort Candidate::collated_by(const Bus& bus) const {
  if (delegation) {
    return adnl::AdnlNodeIdShort{delegation->collator_key.compute_short_id()};
  }
  return leader.get_using(bus).adnl_id;
}

stats::Event::Event() : ts_(td::Clocks::system()), monotonic_ts_(td::Timestamp::now().at()) {
}

}  // namespace ton::validator::consensus
