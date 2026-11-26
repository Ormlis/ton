/*
 * Copyright (c) 2025-2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include <variant>

#include "adnl/adnl-node-id.hpp"
#include "keys/keys.hpp"
#include "ton/ton-types.h"
#include "validator/candidate-roots.h"

namespace ton::validator::consensus {

namespace tl {

using overlayId = ton_api::consensus_overlayId;
using OverlayIdRef = tl_object_ptr<overlayId>;

using dataToSign = ton_api::consensus_dataToSign;
using DataToSignRef = tl_object_ptr<dataToSign>;

using candidateId = ton_api::consensus_candidateId;
using CandidateIdRef = tl_object_ptr<candidateId>;

using candidateParent = ton_api::consensus_candidateParent;
using candidateWithoutParents = ton_api::consensus_candidateWithoutParents;
using CandidateParent = ton_api::consensus_CandidateParent;
using CandidateParentRef = tl_object_ptr<CandidateParent>;

using candidateHashDataOrdinary = ton_api::consensus_candidateHashDataOrdinary;
using candidateHashDataEmpty = ton_api::consensus_candidateHashDataEmpty;
using CandidateHashData = ton_api::consensus_CandidateHashData;
using CandidateHashDataRef = tl_object_ptr<CandidateHashData>;

using block = ton_api::consensus_block;
using empty = ton_api::consensus_empty;
using CandidateData = ton_api::consensus_CandidateData;
using CandidateDataRef = tl_object_ptr<CandidateData>;

using delegation = ton_api::consensus_delegation;
using DelegationRef = tl_object_ptr<delegation>;
using delegationToSign = ton_api::consensus_delegationToSign;
using candidate = ton_api::consensus_candidate;
using pleaseCollatePrepare = ton_api::consensus_pleaseCollatePrepare;
using pleaseCollate = ton_api::consensus_pleaseCollate;
using broadcastExtra = ton_api::consensus_broadcastExtra;
using broadcastExtraLegacy = ton_api::consensus_broadcastExtraLegacy;
using BroadcastExtra = ton_api::consensus_BroadcastExtra;

}  // namespace tl

class Bus;
struct PeerValidator;

class PeerValidatorId {
 public:
  PeerValidatorId() : idx_(std::numeric_limits<size_t>::max()) {
  }

  explicit PeerValidatorId(size_t idx) : idx_(idx) {
  }

  size_t value() const {
    return idx_;
  }

  const PeerValidator& get_using(const Bus& bus) const;

  std::strong_ordering operator<=>(const PeerValidatorId& other) const = default;

 private:
  size_t idx_;
};

td::StringBuilder& operator<<(td::StringBuilder& stream, const PeerValidatorId& id);

[[nodiscard]] bool check_consensus_signature(const PublicKey& key, ValidatorSessionId session, td::Slice data,
                                             td::Slice signature);

struct Delegation;
[[nodiscard]] td::Status check_delegation(const Delegation& delegation, const PeerValidator& leader, td::uint32 slot,
                                          const Bus& bus);

struct PeerValidator {
  [[nodiscard]] bool check_signature(ValidatorSessionId session, td::Slice data, td::Slice signature) const;

  bool operator==(const PeerValidator& other) const = default;

  PeerValidatorId idx;
  PublicKey key;
  PublicKeyHash short_id;
  adnl::AdnlNodeIdShort adnl_id;
  ValidatorWeight weight;
};

td::StringBuilder& operator<<(td::StringBuilder& stream, const PeerValidator& peer_validator);

struct ProtocolMessage {
  ProtocolMessage(td::BufferSlice data) : data(std::move(data)) {
  }

  template <typename T>
  ProtocolMessage(const tl_object_ptr<T>& object) : data(serialize_tl_object(object, true)) {
  }

  td::BufferSlice data;
};

struct CandidateId {
  static CandidateId from_tl(const tl::CandidateIdRef& tl_parent);
  static tl::CandidateParentRef parent_id_to_tl(std::optional<CandidateId> parent);
  static std::optional<CandidateId> tl_to_parent_id(const tl::CandidateParentRef& tl_parent);

  tl::CandidateIdRef to_tl() const;
  std::strong_ordering operator<=>(const CandidateId&) const = default;

  td::uint32 slot{0};
  Bits256 hash{};
};

using ParentId = std::optional<CandidateId>;

td::StringBuilder& operator<<(td::StringBuilder& stream, const CandidateId& id);
td::StringBuilder& operator<<(td::StringBuilder& stream, const ParentId& id);

using BlockReferences = std::vector<BlockIdExt>;
using CandidateBlocks = std::vector<BlockCandidate>;
using CandidateContents = std::variant<BlockReferences, CandidateBlocks>;

struct CandidateHashData {
  BlockReferences blocks;
  std::vector<FileHash> collated_file_hashes;
  ParentId parent;

  static CandidateHashData from(const CandidateContents& contents, ParentId parent);
  CandidateId build_id_with(td::uint32 slot) const;
  tl::CandidateHashDataRef to_tl() const;
};

struct Delegation {
  static std::optional<Delegation> from_tl(tl::DelegationRef tl_delegation);

  tl::DelegationRef to_tl() const;
  Delegation clone() const {
    return {collator_key, signature.clone()};
  }

  PublicKey collator_key;
  td::BufferSlice signature;
};

struct Candidate : td::CntObject {
  using Signer = std::variant<PeerValidatorId, Delegation>;

  static td::Result<td::Ref<Candidate>> deserialize(td::Slice data, const Bus& bus,
                                                    std::optional<td::uint32> expected_slot = std::nullopt);
  static td::Result<td::Ref<Candidate>> deserialize_from_broadcast(td::Slice data, Signer signer, const Bus& bus,
                                                                   td::uint32 expected_slot);

  static td::Result<td::Ref<Candidate>> deserialize_broadcast_data(tl::CandidateDataRef data, Signer signer,
                                                                   const Bus& bus, td::uint32 expected_slot);
  std::vector<td::BufferSlice> encoded_blocks() const;
  static td::Result<td::BufferSlice> encode_block(const BlockCandidate& block, CandidateRootsRef roots = {});

  Candidate(CandidateId id, ParentId parent_id, PeerValidatorId leader, CandidateContents block,
            td::BufferSlice signature, std::optional<Delegation> delegation = std::nullopt,
            std::vector<td::BufferSlice> encoded_members = {}, std::vector<CandidateRootsRef> member_roots = {})
      : encoded_members_(std::move(encoded_members))
      , id(id)
      , parent_id(std::move(parent_id))
      , leader(leader)
      , block(std::move(block))
      , signature(std::move(signature))
      , delegation(std::move(delegation))
      , member_roots(std::move(member_roots)) {
    CHECK(!is_empty() || this->parent_id.has_value());
    CHECK(this->member_roots.empty() || (!is_empty() && this->member_roots.size() == blocks().size()));
  }

  BlockIdExt block_id() const;
  BlockReferences block_ids() const;
  const CandidateBlocks& blocks() const {
    return std::get<CandidateBlocks>(block);
  }
  CandidateRootsRef roots_for(size_t i) const {
    return member_roots.empty() ? CandidateRootsRef{} : member_roots.at(i);
  }
  CandidateHashData hash_data() const;
  td::BufferSlice serialize() const;
  td::BufferSlice serialize_for_broadcast() const;
  bool is_empty() const;
  adnl::AdnlNodeIdShort collated_by(const Bus& bus) const;

 private:
  static td::Result<td::Ref<Candidate>> deserialize_data(tl::CandidateDataRef data,
                                                         std::optional<Delegation> delegation, const Bus& bus,
                                                         std::optional<PeerValidatorId> src,
                                                         std::optional<td::uint32> expected_slot);

  tl::CandidateDataRef to_data_tl() const;
  std::vector<td::BufferSlice> encoded_members_;

 public:
  CandidateId id;
  ParentId parent_id;
  PeerValidatorId leader;
  CandidateContents block;
  td::BufferSlice signature;
  std::optional<Delegation> delegation;
  std::vector<CandidateRootsRef> member_roots;  // In shard order when decoded from the wire.
};

using CandidateRef = td::Ref<Candidate>;

class CollatorSchedule : public td::CntObject {
 public:
  virtual PeerValidatorId expected_collator_for(td::uint32 slot) const = 0;

  [[nodiscard]] bool is_expected_collator(PeerValidatorId id, td::uint32 slot) const {
    return expected_collator_for(slot) == id;
  }
};

namespace stats {

namespace tl {

using Event = ton_api::consensus_stats_Event;
using EventRef = tl_object_ptr<Event>;

}  // namespace tl

class Event {
 public:
  Event();

  virtual ~Event() = default;

  virtual tl::EventRef to_tl() const = 0;
  virtual std::string to_string() const = 0;

  double ts() const {
    return ts_;
  }
  double monotonic_ts() const {
    return monotonic_ts_;
  }

 protected:
  double ts_;
  // Local-only clock for Prometheus duration arithmetic. `ts_` remains Unix time because it is
  // serialized into consensus traces; carrying both avoids making NTP adjustment part of latency.
  double monotonic_ts_;
};

template <typename Collector>
class CollectibleEvent : public Event {
 public:
  virtual void collect_to(Collector& collector) const = 0;
};

}  // namespace stats

}  // namespace ton::validator::consensus
