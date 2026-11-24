/*
 * Copyright (c) 2026, TON CORE TECHNOLOGIES CO. L.L.C
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <map>
#include <optional>
#include <set>

#include "td/utils/CancellationToken.h"
#include "td/utils/Timer.h"
#include "validator/fabric.h"

namespace ton::validator {

// Include the validator's receipt lookup in the proof of the previous state.
bool visit_early_import_receipt(vm::Dictionary& previous_receipts, Ref<vm::Cell> envelope);

// Peer transfers and live externals share an input deadline. Buffered work can still be drained afterwards.
class ShardGroupExchange final : public td::actor::Actor {
 public:
  struct Transfer {
    ShardIdFull destination;
    LogicalTime lt;
    Ref<vm::Cell> envelope;
  };
  using Transfers = std::vector<Transfer>;
  struct Work {
    Transfers transfers;
    // Present when the external queue can be drained. A peer offer interrupts the drain.
    std::optional<td::CancellationToken> external_reader;
    double wait_externals_time = 0;  // Total time all members were idle, returned on completion.
  };

  ShardGroupExchange(size_t size, td::Timestamp input_deadline) : size_(size), input_deadline_(input_deadline) {
  }
  void external_queue_ready(ShardIdFull member, bool closed);
  void offer(Transfer transfer);
  void wait_for_work(ShardIdFull member, bool accept_transfers, bool accept_externals, td::Promise<Work> promise);
  void cancel();

 private:
  struct Member {
    Transfers inbox;
    td::Promise<Work> waiter;
    td::CancellationTokenSource interrupt_externals;
    bool reading_externals = false;
    bool accept_externals = false;
    bool accept_transfers = true;
    bool readable = false;
    bool closed = false;
    bool finished = false;
  };
  size_t size_;
  const td::Timestamp input_deadline_;
  td::Timer external_wait_{true};
  std::map<ShardIdFull, Member> members_;
  void dispatch();
  void start_up() override {
    alarm_timestamp() = input_deadline_;
  }
  void alarm() override {
    dispatch();
  }
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
