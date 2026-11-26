/*
 * Copyright (c) 2026, TON CORE TECHNOLOGIES CO. L.L.C
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/boc.h"

#include "shard-group.h"

namespace ton::validator {

bool visit_early_import_receipt(vm::Dictionary& previous_receipts, Ref<vm::Cell> envelope) {
  td::BitArray<352> queue_key;
  if (!block::compute_out_msg_queue_key(std::move(envelope), queue_key)) {
    return false;
  }
  // A receipt key is the queue key without the workchain. The lookup also records an absent key's path.
  previous_receipts.lookup(queue_key.bits() + 32, 320);
  return true;
}

td::Status ShardGroupMessageOrder::add_parent(Ref<vm::Cell> state, ShardIdFull group) {
  try {
    block::gen::ShardStateUnsplit::Record shard;
    block::gen::OutMsgQueueInfo::Record qinfo;
    if (!tlb::unpack_cell(std::move(state), shard) || !tlb::unpack_cell(shard.out_msg_queue_info, qinfo)) {
      return td::Status::Error("Invalid shard group parent queues");
    }
    ShardIdFull owner;
    if (!block::tlb::t_ShardIdent.unpack(shard.shard_id.write(), owner)) {
      return td::Status::Error("Invalid parent shard identifier");
    }
    auto processed = block::MsgProcessedUptoCollection::unpack(owner, std::move(qinfo.proc_info));
    if (!processed) {
      return td::Status::Error("Invalid parent processed frontier");
    }
    parent_processed_.push_back(std::move(*processed));
    if (qinfo.extra.write().fetch_long(1)) {
      block::gen::OutMsgQueueData::Record data;
      Ref<vm::Cell> root;
      if (!block::unpack_queue_extra(*qinfo.extra, data, &root)) {
        return td::Status::Error("Invalid parent shard group queue data");
      }
      if (root.not_null()) {
        parent_receipts_.emplace(owner, vm::Dictionary(std::move(root), 320));
      }
    }
    vm::AugmentedDictionary queue(std::move(qinfo.out_queue), 352, block::tlb::aug_OutMsgQueue);
    td::BitArray<96> prefix;
    prefix.bits().store_int(group.workchain, 32);
    (prefix.bits() + 32).store_uint(group.shard, 64);
    // All hops between two group addresses preserve the group's common prefix.
    if (!queue.cut_prefix_subdict(prefix.bits(), 32 + group.pfx_len())) {
      return td::Status::Error("Invalid shard group queue prefix");
    }
    if (!queue.is_empty()) {
      parent_queues_.push_back(queue.get_root_cell());
    }
  } catch (const vm::VmError& e) {
    return e.as_status();
  } catch (const vm::VmVirtError& e) {
    return e.as_status();
  }
  return td::Status::OK();
}

std::set<BlockSeqno> ShardGroupMessageOrder::referenced_masterchain_states() const {
  std::set<BlockSeqno> result;
  if (!parent_queues_.empty()) {
    for (const auto& frontier : parent_processed_) {
      for (const auto& entry : frontier.list) {
        result.insert(entry.mc_seqno);
      }
    }
  }
  return result;
}

void ShardGroupMessageOrder::set_shard_end_lt(BlockSeqno seqno, const block::compute_shard_end_lt_func_t& end_lt) {
  for (auto& frontier : parent_processed_) {
    for (auto& entry : frontier.list) {
      if (entry.mc_seqno == seqno) {
        entry.compute_shard_end_lt = end_lt;
      }
    }
  }
}

// Keep unresolved older transfers in route order. Receipts in the same parent cut already prove execution.
bool ShardGroupMessageOrder::scan(vm::AugmentedDictionary& queue, size_t& budget) {
  return queue.check_for_each_extra([&](Ref<vm::CellSlice> value, Ref<vm::CellSlice>, td::ConstBitPtr key, int) {
    if (!budget) {
      return false;
    }
    --budget;
    for (auto& [owner, receipts] : parent_receipts_) {
      if (shard_contains(owner,
                         AccountIdPrefixFull{static_cast<WorkchainId>(key.get_int(32)), (key + 32).get_uint(64)}) &&
          receipts.lookup(key + 32, 320).not_null()) {
        return true;
      }
    }
    block::EnqueuedMsgDescr msg;
    if (!msg.unpack(value.write())) {
      return false;
    }
    for (const auto& frontier : parent_processed_) {
      if (shard_contains(frontier.owner, msg.dest_prefix_) && frontier.can_check_processed() &&
          frontier.already_processed(msg)) {
        return true;
      }
    }
    times_[{msg.src_prefix_, msg.dest_prefix_}].first_queued = 0;
    return true;
  });
}

void ShardGroupMessageOrder::index_parents() {
  size_t budget = 1024;
  std::erase_if(parent_queues_, [&](const auto& root) {
    vm::AugmentedDictionary queue(root, 352, block::tlb::aug_OutMsgQueue);
    return budget && scan(queue, budget);
  });
}

bool ShardGroupMessageOrder::index_hop(AccountIdPrefixFull hop) {
  auto [it, inserted] = indexed_hops_.try_emplace(hop, true);
  if (inserted) {
    td::BitArray<96> key;
    key.bits().store_int(hop.workchain, 32);
    (key.bits() + 32).store_uint(hop.account_id_prefix, 64);
    size_t budget = 1024;
    for (const auto& root : parent_queues_) {
      vm::AugmentedDictionary queue(root, 352, block::tlb::aug_OutMsgQueue);
      if (!queue.cut_prefix_subdict(key.bits(), 96) || !scan(queue, budget)) {
        it->second = false;
        break;
      }
    }
  }
  return it->second;
}

bool ShardGroupMessageOrder::can_deliver(const Route& route, LogicalTime lt) {
  if (!parent_queues_.empty()) {
    // A canonical basechain hop substitutes a whole number of destination nibbles. This also covers transfers
    // enqueued before a split or merge. A saturated individual hop only delays routes that could use that hop.
    AccountIdPrefixFull previous;
    for (int bits = 32; bits <= 96; bits += 4) {
      auto hop = block::interpolate_addr(route.first, route.second, bits);
      if (hop != previous && !index_hop(hop)) {
        return false;
      }
      previous = hop;
    }
  }
  auto it = times_.find(route);
  return it == times_.end() || lt <= it->second.first_queued;
}

bool ShardGroupMessageOrder::record(const Route& route, LogicalTime lt, bool direct) {
  auto& times = times_[route];
  if (direct) {
    times.last_direct = std::max(times.last_direct, lt);
    return can_deliver(route, times.last_direct);
  }
  times.first_queued = std::min(times.first_queued, lt);
  return times.last_direct == 0 || times.last_direct <= times.first_queued;
}

void ShardGroupExchange::external_queue_ready(ShardIdFull member, bool closed) {
  auto& state = members_[member];
  if (state.finished || state.closed) {
    return;
  }
  state.readable = true;
  state.closed = closed;
  if (state.waiter) {
    dispatch();
  }
}

void ShardGroupExchange::offer(Transfer transfer) {
  if (input_deadline_.is_in_past()) {
    return;
  }
  auto& destination = members_[transfer.destination];
  if (destination.finished || !destination.accept_transfers) {
    return;
  }
  destination.inbox.push_back(std::move(transfer));
  if (destination.reading_externals) {
    // The reader may already hold an item. Resume it even if the queue has since closed.
    destination.readable = true;
    destination.interrupt_externals.cancel();
  }
  if (destination.waiter) {
    dispatch();
  }
}

void ShardGroupExchange::wait_for_work(ShardIdFull member, bool accept_transfers, bool accept_externals,
                                       td::Promise<Work> promise) {
  auto& state = members_[member];
  state.reading_externals = false;
  state.waiter = std::move(promise);
  state.accept_externals = accept_externals;
  state.accept_transfers = accept_transfers;
  if (!accept_transfers) {
    state.inbox.clear();
  }
  dispatch();
}

void ShardGroupExchange::dispatch() {
  external_wait_.pause();
  bool past_cutoff = input_deadline_.is_in_past();
  size_t idle = 0;
  bool waiting_for_externals = false;
  for (auto& [_, state] : members_) {
    if (state.finished) {
      ++idle;
    } else if (state.waiter) {
      if (past_cutoff && !state.closed) {
        // One final read covers notifications in flight at the cutoff.
        state.closed = true;
        state.readable = true;
      }
      if (!state.inbox.empty()) {
        state.waiter.set_value({std::exchange(state.inbox, {}), {}});
        continue;
      }
      if (state.accept_externals && state.readable) {
        state.readable = false;
        state.reading_externals = true;
        state.waiter.set_value({{}, state.interrupt_externals.get_cancellation_token()});
        continue;
      }
      ++idle;
      if (state.accept_externals && !state.closed) {
        waiting_for_externals = true;
      } else if (past_cutoff || !state.accept_transfers) {
        state.finished = true;
        state.waiter.set_value({{}, {}, external_wait_.elapsed()});
      }
    }
  }
  if (idle != size_) {
    return;
  }
  if (waiting_for_externals) {
    external_wait_.resume();
    return;
  }
  for (auto& [_, state] : members_) {
    state.finished = true;
    state.waiter.set_value({{}, {}, external_wait_.elapsed()});
  }
}

void ShardGroupExchange::cancel() {
  for (auto& [_, state] : members_) {
    state.interrupt_externals.cancel();
    state.waiter.set_error(td::Status::Error(ErrorCode::cancelled, "Shard group collation cancelled"));
  }
  stop();
}

td::Result<std::shared_ptr<const ShardGroupMessages>> ShardGroupMessages::extract(
    const std::vector<BlockCandidate>& blocks, const std::vector<ShardIdFull>& members,
    const std::vector<CandidateRootsRef>& roots) {
  CHECK(roots.empty() || roots.size() == blocks.size());
  if (members.empty() || members.size() != blocks.size()) {
    return td::Status::Error("Incomplete shard group");
  }
  auto view = std::make_shared<ShardGroupMessages>();
  BlockIdExt mc;
  UnixTime time = 0;
  try {
    for (size_t i = 0; i < members.size(); ++i) {
      const auto& candidate = blocks[i];
      Ref<vm::Cell> root;
      if (roots.empty()) {
        TRY_RESULT_ASSIGN(root, vm::std_boc_deserialize(candidate.data));
      } else {
        root = roots[i]->block_root;
      }
      block::gen::Block::Record blk;
      block::gen::BlockInfo::Record info;
      block::gen::BlockExtra::Record extra;
      if (candidate.id.shard_full() != members[i] || candidate.id.root_hash != root->get_hash().bits() ||
          !tlb::unpack_cell(root, blk) || !tlb::unpack_cell(blk.info, info) || !tlb::unpack_cell(blk.extra, extra)) {
        return td::Status::Error("Invalid block in shard group");
      }
      TRY_RESULT(header, block::get_block_header_info(root, candidate.id));
      if (i && (header.mc_blkid != mc || info.gen_utime != time)) {
        return td::Status::Error("Different masterchain references or timestamps in shard group");
      }
      mc = header.mc_blkid;
      time = info.gen_utime;
      view->descriptors.emplace(members[i], Descriptors{candidate.id, extra.in_msg_descr, extra.out_msg_descr});
    }
  } catch (const vm::VmError& e) {
    return e.as_status();
  } catch (const vm::VmVirtError& e) {
    return e.as_status();
  }
  return std::shared_ptr<const ShardGroupMessages>(std::move(view));
}

bool ShardGroupMessages::has_peer_record(AccountIdPrefixFull peer, bool incoming, td::ConstBitPtr key,
                                         const vm::Cell& envelope) const {
  for (const auto& [shard, desc] : descriptors) {
    if (!shard_contains(shard, peer)) {
      continue;
    }
    const vm::AugmentationData& aug =
        incoming ? static_cast<const vm::AugmentationData&>(block::tlb::aug_InMsgDescrDefault)
                 : static_cast<const vm::AugmentationData&>(block::tlb::aug_OutMsgDescrDefault);
    vm::AugmentedDictionary dict(vm::load_cell_slice_ref(incoming ? desc.in : desc.out), 256, aug);
    auto record = dict.lookup(key, 256);
    return record.not_null() &&
           (incoming ? block::gen::t_InMsg.get_tag(*record) == block::gen::InMsg::msg_import_group
                     : block::gen::t_OutMsg.get_tag(*record) == block::gen::OutMsg::msg_export_new) &&
           record->have_refs(2) && record->prefetch_ref()->get_hash() == envelope.get_hash();
  }
  return false;
}

}  // namespace ton::validator
