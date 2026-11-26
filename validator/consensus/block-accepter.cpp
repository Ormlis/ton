/*
 * Copyright (c) 2025-2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "validator/full-node.h"

#include "bus.h"
#include "stats.h"

namespace ton::validator::consensus {

namespace {

class BlockAccepterImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TON_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  td::actor::Task<> process(BusHandle, std::shared_ptr<FinalizeBlock> event) {
    auto& bus = *owning_bus();
    std::vector<td::Ref<BlockData>> blocks;
    for (size_t i = 0; i < event->candidate->blocks().size(); ++i) {
      const auto& block = event->candidate->blocks()[i];
      auto roots = event->candidate->roots_for(i);
      blocks.push_back(
          CO_TRY(create_block(block.id, block.data.clone(), roots.not_null() ? roots->block_root : Ref<vm::Cell>{})));
    }
    int broadcast_mode = 0;
    if (td::uint64(blocks.front()->block_id().seqno()) + 8 > last_mc_finalized_seqno_) {
      broadcast_mode = fullnode::FullNode::broadcast_mode_custom;
      if (!bus.is_collator) {
        broadcast_mode |= fullnode::FullNode::broadcast_mode_protected;
      }
    }
    co_await td::actor::ask(bus.manager, &ManagerFacade::accept_blocks, std::move(blocks),
                            event->candidate->leader.value(), event->signatures, broadcast_mode, true);
    owning_bus().publish<TraceEvent>(stats::BlockAccepted::create(event->candidate));
    co_return {};
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const BlockFinalizedInMasterchain> event) {
    last_mc_finalized_seqno_ = std::max(event->block.seqno(), last_mc_finalized_seqno_);
  }

 private:
  BlockSeqno last_mc_finalized_seqno_ = 0;
};

}  // namespace

void BlockAccepter::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<BlockAccepterImpl>("BlockAccepter");
}

}  // namespace ton::validator::consensus
