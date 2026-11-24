/*
 * Copyright (c) 2026, TON CORE TECHNOLOGIES CO. L.L.C
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <map>
#include <set>

#include "validator/fabric.h"

namespace ton::validator {

// An idle member can be woken by any sender. All idle mailboxes together end this candidate.
class ShardGroupExchange final : public td::actor::Actor {
 public:
  struct Transfer {
    ShardIdFull destination;
    LogicalTime lt;
    Ref<vm::Cell> envelope;
  };
  using Transfers = std::vector<Transfer>;

  explicit ShardGroupExchange(size_t size) : size_(size) {
  }
  void publish(Transfers outgoing);
  void exchange(ShardIdFull member, Transfers outgoing, bool finished, td::Promise<Transfers> promise);
  void cancel();

 private:
  size_t size_;
  std::set<ShardIdFull> finished_;
  std::map<ShardIdFull, td::Promise<Transfers>> waiting_;
  std::map<ShardIdFull, Transfers> incoming_;
};

// A direct message must not pass an older ordinary message for the same source and destination.
class ShardGroupMessageOrder {
 public:
  using Route = std::pair<AccountIdPrefixFull, AccountIdPrefixFull>;
  td::Status add_parent(Ref<vm::Cell> state, ShardIdFull group);
  std::set<BlockSeqno> referenced_masterchain_states() const;
  void set_shard_end_lt(BlockSeqno seqno, const block::compute_shard_end_lt_func_t& end_lt);
  void index_parents();
  bool can_deliver(const Route& route, LogicalTime lt);
  bool record(const Route& route, LogicalTime lt, bool direct);

 private:
  struct Times {
    LogicalTime first_queued = ~LogicalTime{0};
    LogicalTime last_direct = 0;
  };
  std::map<Route, Times> times_;
  std::vector<Ref<vm::Cell>> parent_queues_;
  std::map<ShardIdFull, vm::Dictionary> parent_receipts_;
  std::vector<block::MsgProcessedUptoCollection> parent_processed_;
  std::map<AccountIdPrefixFull, bool> indexed_hops_;
  bool scan(vm::AugmentedDictionary& queue, size_t& budget);
  bool index_hop(AccountIdPrefixFull hop);
};

// Immutable dictionaries from the exact blocks in the signed candidate.
struct ShardGroupMessages {
  struct Descriptors {
    BlockIdExt block;
    Ref<vm::Cell> in, out;
  };
  std::map<ShardIdFull, Descriptors> descriptors;
  static td::Result<std::shared_ptr<const ShardGroupMessages>> extract(const std::vector<BlockCandidate>& blocks,
                                                                       const std::vector<ShardIdFull>& members);
  bool has_peer_record(AccountIdPrefixFull peer, bool incoming, td::ConstBitPtr key, const vm::Cell& envelope) const;
};

}  // namespace ton::validator
