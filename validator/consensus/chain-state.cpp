/*
 * Copyright (c) 2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "crypto/block/block-auto.h"
#include "crypto/vm/cells/MerkleUpdate.h"
#include "td/utils/format.h"
#include "ton/ton-io.hpp"
#include "validator/fabric.h"
#include "validator/impl/shard-group.h"

#include "chain-state.h"

namespace ton::validator::consensus {

td::actor::Task<td::Ref<ChainState>> ChainState::from_manager(td::actor::ActorId<ManagerFacade> manager,
                                                              ShardIdFull shard, std::vector<BlockIdExt> blocks) {
  if (blocks.size() == 1 && blocks[0].seqno() == 0) {
    CHECK(blocks[0].shard_full() == shard);
    auto state =
        co_await td::actor::ask(manager, &ManagerFacade::wait_block_state_root, blocks[0], td::Timestamp::in(10.0));
    co_return td::make_ref<ChainState>(ZerostateTip{blocks[0], state});
  }

  std::vector<td::actor::StartedTask<td::Ref<vm::Cell>>> wait_state_root;
  std::vector<td::actor::StartedTask<td::Ref<BlockData>>> wait_block_data;
  for (auto block : blocks) {
    wait_state_root.push_back(
        td::actor::ask(manager, &ManagerFacade::wait_block_state_root, block, td::Timestamp::in(10.0)));
    if (block.seqno() != 0) {
      wait_block_data.push_back(
          td::actor::ask(manager, &ManagerFacade::wait_block_data, block, td::Timestamp::in(10.0)));
    }
  }
  auto states = co_await td::actor::all(std::move(wait_state_root));
  auto blocks_data = co_await td::actor::all(std::move(wait_block_data));

  if (blocks.size() == 2) {
    auto shard_0 = shard_child(shard_parent(blocks[0].shard_full()), true);
    auto shard_1 = shard_child(shard_parent(blocks[0].shard_full()), false);
    CHECK(blocks[0].shard_full() == shard_0 && blocks[1].shard_full() == shard_1);

    co_return td::make_ref<ChainState>(BeforeMergeTip{
        .left = NormalTip{blocks_data[0], states[0]},
        .right = NormalTip{blocks_data[1], states[1]},
    });
  } else {
    CHECK(blocks.size() == 1);
    if (shard == blocks[0].shard_full()) {
      co_return td::make_ref<ChainState>(NormalTip{blocks_data[0], states[0]});
    } else {
      CHECK(shard_is_parent(blocks[0].shard_full(), shard));
      co_return td::make_ref<ChainState>(BeforeSplitTip{NormalTip{blocks_data[0], states[0]}});
    }
  }
}

td::actor::Task<td::Ref<ChainState>> ChainState::from_group(td::actor::ActorId<ManagerFacade> manager,
                                                            ShardIdFull shard, std::vector<ShardIdFull> members,
                                                            std::vector<BlockIdExt> blocks) {
  if (members.empty()) {
    co_return co_await from_manager(manager, shard, std::move(blocks));
  }
  if (blocks.size() != members.size()) {
    co_return td::Status::Error("Incomplete shard group state");
  }
  std::vector<td::actor::StartedTask<td::Ref<ChainState>>> tasks;
  for (size_t i = 0; i < members.size(); ++i) {
    if (blocks[i].shard_full() != members[i]) {
      co_return td::Status::Error("Shard group state has an unexpected member");
    }
    tasks.push_back(from_manager(manager, members[i], {blocks[i]}).start());
  }
  co_return td::make_ref<ChainState>(co_await td::actor::all(std::move(tasks)));
}

ChainState::ChainState(std::vector<td::Ref<ChainState>> members)
    : members_(std::move(members)), tip_(members_.front()->tip_) {
}

td::actor::Task<ChainStateRef> ChainState::apply_group(ChainStateRef parent, CandidateRef candidate) {
  const auto& blocks = candidate->blocks();
  CHECK(!parent->members_.empty() && blocks.size() == parent->members_.size());
  auto apply_member = [](ChainStateRef previous, CandidateRef group, size_t i) -> td::actor::Task<ChainStateRef> {
    auto roots = group->roots_for(i);
    co_return previous->apply(group->blocks()[i], roots.not_null() ? roots->block_root : Ref<vm::Cell>{});
  };
  std::vector<td::actor::StartedTask<ChainStateRef>> tasks;
  tasks.reserve(blocks.size());
  for (size_t i = 0; i < blocks.size(); ++i) {
    auto task = apply_member(parent->members_[i], candidate, i);
    task.set_executor(td::actor::Executor::on_scheduler());
    tasks.push_back(std::move(task).start());
  }
  co_return td::make_ref<ChainState>(co_await td::actor::all(std::move(tasks)));
}

std::vector<BlockIdExt> ChainState::block_ids() const {
  if (!members_.empty()) {
    std::vector<BlockIdExt> ids;
    for (const auto& member : members_) {
      ids.push_back(member->block_ids().front());
    }
    return ids;
  }
  return std::visit([](const auto& tip) { return tip.block_ids(); }, tip_);
}

std::vector<td::Ref<BlockData>> ChainState::block_data() const {
  return std::visit([](const auto& tip) { return tip.block_data(); }, tip_);
}

std::vector<td::Ref<vm::Cell>> ChainState::state() const {
  return std::visit([](const auto& tip) { return tip.states(); }, tip_);
}

td::actor::Task<std::shared_ptr<const ShardGroupMessageOrder>> ChainState::group_message_order(
    td::actor::ActorId<ManagerFacade> manager, td::Ref<MasterchainState> head) const {
  CHECK(!members_.empty());
  auto group = members_.front()->block_ids().front().shard_full();
  for (size_t n = members_.size(); n > 1; n /= 2) {
    group = shard_parent(group);
  }
  auto order = std::make_shared<ShardGroupMessageOrder>();
  for (const auto& member : members_) {
    CO_TRY(order->add_parent(member->root_, group));
  }
  // Resolve only the snapshots named by the authenticated parent frontiers. Using the newest shard end_lt
  // here would allow a newer processed cursor to skip a message that its snapshot could not yet see.
  auto seqnos = order->referenced_masterchain_states();
  if (!seqnos.empty() && head.is_null()) {
    head = co_await td::actor::ask(manager, &ManagerFacade::group_masterchain_state);
  }
  std::map<BlockSeqno, td::actor::StartedTask<td::Ref<vm::Cell>>> requests;
  for (auto seqno : seqnos) {
    if (seqno != head->get_seqno()) {
      BlockIdExt id;
      if (!head->get_old_mc_block_id(seqno, id)) {
        co_return td::Status::Error(ErrorCode::notready,
                                    "Shard group parent references an unavailable masterchain state");
      }
      requests.emplace(seqno,
                       td::actor::ask(manager, &ManagerFacade::wait_block_state_root, id, td::Timestamp::in(10)));
    }
  }
  try {
    for (auto seqno : seqnos) {
      auto root = seqno == head->get_seqno() ? head->root_cell() : co_await std::move(requests.at(seqno));
      auto shards = block::ShardConfig::extract_shard_hashes_dict(root);
      if (!shards) {
        co_return td::Status::Error("Invalid shard layout for a processed frontier");
      }
      order->set_shard_end_lt(seqno, block::ShardConfig(shards->get_root_cell()).get_compute_shard_end_lt_func());
    }
    order->index_parents();
  } catch (const vm::VmError& e) {
    co_return e.as_status();
  } catch (const vm::VmVirtError& e) {
    co_return e.as_status();
  }
  co_return std::shared_ptr<const ShardGroupMessageOrder>(std::move(order));
}

BlockSeqno ChainState::next_seqno() const {
  return std::visit([](const auto& tip) { return tip.next_seqno(); }, tip_);
}

bool ChainState::is_before_split() const {
  if (!members_.empty()) {
    return std::any_of(members_.begin(), members_.end(), [](const auto& state) { return state->is_before_split(); });
  }
  if (auto normal_tip = std::get_if<NormalTip>(&tip_)) {
    block::gen::Block::Record blk;
    block::gen::BlockInfo::Record info;
    bool rc = tlb::unpack_cell(normal_tip->block->root_cell(), blk) && tlb::unpack_cell(blk.info, info);
    CHECK(rc);
    return info.before_split;
  }

  return false;
}

std::optional<BlockIdExt> ChainState::as_normal() const {
  if (auto normal_tip = std::get_if<NormalTip>(&tip_)) {
    return normal_tip->block->block_id();
  }
  return std::nullopt;
}

BlockIdExt ChainState::assert_normal() const {
  CHECK(std::holds_alternative<NormalTip>(tip_));
  return std::get<NormalTip>(tip_).block->block_id();
}

#if TD_MSVC
[[noreturn]] void unreachable() {
  __assume(0);
}
#else
[[noreturn]] void unreachable() {
  __builtin_unreachable();
}
#endif

td::Ref<ChainState> ChainState::apply(const BlockCandidate& candidate, td::Ref<vm::Cell> block_root) const {
  try {
    auto block = create_block(candidate.id, candidate.data.clone(), std::move(block_root)).move_as_ok();

    block::gen::Block::Record rec;
    bool rc = block::gen::unpack_cell(block->root_cell(), rec);
    LOG_CHECK(rc) << "Failed to unpack block " << candidate.id;

    auto state = vm::MerkleUpdate::apply(root_, rec.state_update).ensure().move_as_ok();

    return td::Ref<ChainState>(new ChainState{NormalTip{block, state}}, td::Ref<ChainState>::acquire_t{});
  } catch (vm::CellBuilder::CellCreateError& e) {
    LOG(FATAL) << "Failed to apply Merkle update of " << candidate.id << ": CellCreateError";
    unreachable();
  } catch (vm::CellBuilder::CellWriteError& e) {
    LOG(FATAL) << "Failed to apply Merkle update of " << candidate.id << ": CellWriteError";
    unreachable();
  } catch (vm::VmError& e) {
    LOG(FATAL) << "Failed to apply block " << candidate.id << ": VmError: " << e.as_status();
    unreachable();
  }
}

td::Ref<vm::Cell> ChainState::BeforeMergeTip::root() const {
  td::Ref<vm::Cell> result;
  bool rc = block::gen::t_ShardState.cell_pack_split_state(result, left.state, right.state);
  CHECK(rc);
  return result;
}

ChainState::ChainState(Tip tip) : tip_(std::move(tip)) {
  root_ = std::visit([](const auto& tip) { return tip.root(); }, this->tip_);
}

td::StringBuilder& operator<<(td::StringBuilder& sb, const ChainState& state) {
  std::vector<std::string> blocks;
  for (const auto& block : state.block_ids()) {
    blocks.push_back(block.to_str());
  }

  return sb << "ChainState{tip=" << blocks << "}";
}

}  // namespace ton::validator::consensus
