/*
 * Copyright (c) 2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "td/actor/coro_task.h"
#include "validator/interfaces/block.h"

#include "manager-facade.h"
#include "types.h"

namespace ton::validator::consensus {

class ChainState : public td::CntObject {
 public:
  struct NormalTip {
    td::Ref<BlockData> block;
    td::Ref<vm::Cell> state;

    BlockSeqno next_seqno() const {
      return block->block_id().seqno() + 1;
    }

    std::vector<BlockIdExt> block_ids() const {
      return {block->block_id()};
    }

    std::vector<td::Ref<BlockData>> block_data() const {
      return {block};
    }

    std::vector<td::Ref<vm::Cell>> states() const {
      return {state};
    }

    td::Ref<vm::Cell> root() const {
      return state;
    }
  };

  struct BeforeMergeTip {
    NormalTip left;
    NormalTip right;

    BlockSeqno next_seqno() const {
      return std::max(left.next_seqno(), right.next_seqno());
    }

    std::vector<BlockIdExt> block_ids() const {
      return {left.block->block_id(), right.block->block_id()};
    }

    std::vector<td::Ref<BlockData>> block_data() const {
      return {left.block, right.block};
    }

    std::vector<td::Ref<vm::Cell>> states() const {
      return {left.state, right.state};
    }

    td::Ref<vm::Cell> root() const;
  };

  struct BeforeSplitTip {
    NormalTip tip;

    BlockSeqno next_seqno() const {
      return tip.next_seqno();
    }

    std::vector<BlockIdExt> block_ids() const {
      return {tip.block->block_id()};
    }

    std::vector<td::Ref<BlockData>> block_data() const {
      return {tip.block};
    }

    std::vector<td::Ref<vm::Cell>> states() const {
      return {tip.state};
    }

    td::Ref<vm::Cell> root() const {
      return tip.state;
    }
  };

  struct ZerostateTip {
    BlockIdExt id;
    td::Ref<vm::Cell> state;

    BlockSeqno next_seqno() const {
      return 1;
    }

    std::vector<BlockIdExt> block_ids() const {
      return {id};
    }

    std::vector<td::Ref<BlockData>> block_data() const {
      return {};
    }

    std::vector<td::Ref<vm::Cell>> states() const {
      return {state};
    }

    td::Ref<vm::Cell> root() const {
      return state;
    }
  };

  using Tip = std::variant<NormalTip, BeforeMergeTip, BeforeSplitTip, ZerostateTip>;

  static td::actor::Task<td::Ref<ChainState>> from_manager(td::actor::ActorId<ManagerFacade> manager, ShardIdFull shard,
                                                           std::vector<BlockIdExt> blocks);

  static td::actor::Task<td::Ref<ChainState>> from_group(td::actor::ActorId<ManagerFacade> manager, ShardIdFull shard,
                                                         std::vector<ShardIdFull> members,
                                                         std::vector<BlockIdExt> blocks);
  explicit ChainState(Tip tip);
  explicit ChainState(std::vector<td::Ref<ChainState>> members);
  const ChainState& member(size_t i) const {
    return members_.empty() ? *this : *members_.at(i);
  }
  static td::actor::Task<td::Ref<ChainState>> apply_group(td::Ref<ChainState> parent, CandidateRef candidate);

  std::vector<BlockIdExt> block_ids() const;
  std::vector<td::Ref<BlockData>> block_data() const;
  std::vector<td::Ref<vm::Cell>> state() const;
  td::actor::Task<std::shared_ptr<const ShardGroupMessageOrder>> group_message_order(
      td::actor::ActorId<ManagerFacade> manager, td::Ref<MasterchainState> head = {}) const;

  BlockSeqno next_seqno() const;
  bool is_before_split() const;
  std::optional<BlockIdExt> as_normal() const;
  BlockIdExt assert_normal() const;

  td::Ref<ChainState> apply(const BlockCandidate& candidate, td::Ref<vm::Cell> block_root = {}) const;

 private:
  std::vector<td::Ref<ChainState>> members_;
  Tip tip_;
  td::Ref<vm::Cell> root_;
};

using ChainStateRef = td::Ref<ChainState>;

td::StringBuilder& operator<<(td::StringBuilder& sb, const ChainState& state);

}  // namespace ton::validator::consensus
