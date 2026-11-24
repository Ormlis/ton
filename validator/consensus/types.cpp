/*
 * Copyright (c) 2025-2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "auto/tl/ton_api.hpp"
#include "keys/encryptor.h"
#include "td/utils/overloaded.h"

#include "bus.h"
#include "checksum.h"
#include "payload.h"

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
  return encryptor.move_as_ok()->check_signature(signed_data, signature).is_ok();
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
    return deserialize_data(maybe_broadcast.move_as_ok(), std::nullopt, bus, std::nullopt, expected_slot);
  }
  TRY_RESULT(wrapper, fetch_tl_object<tl::candidate>(data, true));
  return deserialize_data(std::move(wrapper->data_), Delegation::from_tl(std::move(wrapper->delegation_)), bus,
                          std::nullopt, expected_slot);
}

td::Result<CandidateRef> Candidate::deserialize_from_broadcast(td::Slice data, Signer signer, const Bus& bus,
                                                               td::uint32 expected_slot) {
  if (!bus.group_members.empty() && data.size() > Bus::max_group_candidate_bytes) {
    return td::Status::Error("Shard group broadcast exceeds wire size limit");
  }
  TRY_RESULT(broadcast, fetch_tl_object<tl::CandidateData>(data, true));
  return deserialize_broadcast_data(std::move(broadcast), std::move(signer), bus, expected_slot);
}

td::Result<CandidateRef> Candidate::deserialize_broadcast_data(tl::CandidateDataRef broadcast, Signer signer,
                                                               const Bus& bus, td::uint32 expected_slot) {
  auto validator_fn = [&](PeerValidatorId validator) {
    return deserialize_data(std::move(broadcast), std::nullopt, bus, validator, expected_slot);
  };
  auto delegation_fn = [&](Delegation delegation) {
    return deserialize_data(std::move(broadcast), std::move(delegation), bus, std::nullopt, expected_slot);
  };
  return std::visit(td::overloaded(validator_fn, delegation_fn), std::move(signer));
}

td::Result<CandidateRef> Candidate::deserialize_data(tl::CandidateDataRef broadcast,
                                                     std::optional<Delegation> delegation, const Bus& bus,
                                                     std::optional<PeerValidatorId> src,
                                                     std::optional<td::uint32> expected_slot) {
  struct ExtractedData {
    td::uint32 slot;
    ParentId parent_id;
    CandidateContents block;
    td::BufferSlice signature;
  };
  td::Result<ExtractedData> maybe_data;

  PeerValidator leader;
  auto set_check_leader = [&](td::uint32 slot) -> td::Status {
    if (expected_slot.has_value() && expected_slot != slot) {
      return td::Status::Error("Candidate broadcast has unexpected slot");
    }
    leader = bus.collator_schedule->expected_collator_for(slot).get_using(bus);
    if (leader.idx != src.value_or(leader.idx)) {
      return td::Status::Error("Candidate broadcast source does not match expected leader");
    }
    return td::Status::OK();
  };

  auto empty_fn = [&](tl::empty& empty_broadcast) -> td::Result<ExtractedData> {
    auto slot = static_cast<td::uint32>(empty_broadcast.slot_);
    TRY_STATUS(set_check_leader(slot));

    if (!bus.group_members.empty()) {
      return td::Status::Error("Single-block reference in a shard group session");
    }
    return ExtractedData{slot, CandidateId::from_tl(empty_broadcast.parent_),
                         BlockReferences{create_block_id(empty_broadcast.block_)},
                         std::move(empty_broadcast.signature_)};
  };

  auto decode_member = [&](td::Slice payload, ShardIdFull shard) -> td::Result<BlockCandidate> {
    TRY_RESULT(candidate, deserialize_payload(payload, static_cast<int>(std::min<td::uint64>(
                                                           0x7fffffff, td::uint64(bus.config.max_block_size) +
                                                                           bus.config.max_collated_data_size + 1024))));

    if (!candidate->src_.is_zero()) {
      return td::Status::Error("src field of the candidate broadcast must be null");
    }

    if (candidate->data_.size() > bus.config.max_block_size ||
        candidate->collated_data_.size() > bus.config.max_collated_data_size) {
      return td::Status::Error(PSTRING() << "Too big candidate broadcast with data_size=" << candidate->data_.size()
                                         << ", collated_data_size=" << candidate->collated_data_.size());
    }

    BlockIdExt block_id{
        BlockId{shard, static_cast<BlockSeqno>(candidate->round_)},
        candidate->root_hash_,
        td::sha256_bits256(candidate->data_.as_slice()),
    };

    auto collated_file_hash = td::sha256_bits256(candidate->collated_data_.as_slice());

    Ed25519_PublicKey creator{leader.key.ed25519_value().raw()};

    return BlockCandidate{creator, block_id, collated_file_hash, std::move(candidate->data_),
                          std::move(candidate->collated_data_)};
  };

  auto ordinary_fn = [&](tl::block& b) -> td::Result<ExtractedData> {
    auto slot = static_cast<td::uint32>(b.slot_);
    TRY_STATUS(set_check_leader(slot));
    if (!bus.group_members.empty()) {
      return td::Status::Error("Single block in a shard group session");
    }
    TRY_RESULT(member, decode_member(b.candidate_, bus.shard));
    CandidateBlocks blocks;
    blocks.push_back(std::move(member));
    return ExtractedData{slot, CandidateId::tl_to_parent_id(b.parent_), std::move(blocks), std::move(b.signature_)};
  };
  auto group_fn = [&](ton_api::consensus_blockGroup& b) -> td::Result<ExtractedData> {
    auto slot = static_cast<td::uint32>(b.slot_);
    TRY_STATUS(set_check_leader(slot));
    if (bus.group_members.empty() || b.candidates_.size() != bus.group_members.size()) {
      return td::Status::Error("Wrong number of shard group members");
    }
    CandidateBlocks blocks;
    for (size_t i = 0; i < b.candidates_.size(); ++i) {
      TRY_RESULT(member, decode_member(b.candidates_[i], bus.group_members[i]));
      blocks.push_back(std::move(member));
    }
    return ExtractedData{slot, CandidateId::tl_to_parent_id(b.parent_), std::move(blocks), std::move(b.signature_)};
  };
  auto group_empty_fn = [&](ton_api::consensus_emptyGroup& b) -> td::Result<ExtractedData> {
    auto slot = static_cast<td::uint32>(b.slot_);
    TRY_STATUS(set_check_leader(slot));
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
    return ExtractedData{slot, CandidateId::from_tl(b.parent_), std::move(refs), std::move(b.signature_)};
  };
  ton_api::downcast_call(
      *broadcast, [&](auto& b) { maybe_data = td::overloaded(empty_fn, ordinary_fn, group_fn, group_empty_fn)(b); });
  TRY_RESULT(parsed, std::move(maybe_data));

  auto id = CandidateHashData::from(parsed.block, parsed.parent_id).build_id_with(parsed.slot);
  auto signed_data = serialize_tl_object(id.to_tl(), true);

  if (delegation.has_value()) {
    TRY_STATUS(check_delegation(*delegation, leader, parsed.slot, bus));
    if (!check_consensus_signature(delegation->collator_key, bus.session_id, signed_data, parsed.signature)) {
      return td::Status::Error("Delegated candidate broadcast signature is not valid");
    }
  } else if (!leader.check_signature(bus.session_id, signed_data, parsed.signature)) {
    return td::Status::Error("Candidate broadcast signature is not valid");
  }

  return td::make_ref<Candidate>(id, parsed.parent_id, leader.idx, std::move(parsed.block), std::move(parsed.signature),
                                 std::move(delegation));
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

td::Result<td::BufferSlice> Candidate::encode_block(const BlockCandidate& candidate) {
  return serialize_payload(
      create_tl_object<ton_api::validatorSession_candidate>(td::Bits256{}, candidate.id.seqno(), candidate.id.root_hash,
                                                            candidate.data.clone(), candidate.collated_data.clone()));
}

std::vector<td::BufferSlice> Candidate::encoded_blocks() const {
  std::vector<td::BufferSlice> payloads;
  if (encoded_members_.empty()) {
    for (const auto& member : blocks()) {
      payloads.push_back(encode_block(member).move_as_ok());
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
