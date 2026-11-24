/*
 * Copyright (c) 2025-2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "td/actor/coro_utils.h"
#include "validator/impl/shard-group.h"

#include "bus.h"
#include "stats.h"
#include "utils.h"

namespace td {

td::StringBuilder& operator<<(td::StringBuilder& sb, const std::optional<ton::BlockIdExt>& id) {
  if (id.has_value()) {
    sb << id->to_str();
  } else {
    sb << "genesis";
  }
  return sb;
}

}  // namespace td

namespace ton::validator::consensus {

namespace {

class BlockValidatorImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TON_RUNTIME_DEFINE_EVENT_HANDLER();

  static bool should_be_spawned(const Bus& bus) {
    return bus.is_validator();
  }

  void tear_down() override {
    for (auto& p : next_block_promises_) {
      p.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
    }
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const Start> event) {
    on_new_accepted_block(event->state->as_normal());
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const FinalizeBlock> event) {
    on_new_accepted_block(event->candidate->block_id());
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const BlockFinalizedInMasterchain> event) {
    if (event->block.shard_full() != owning_bus()->shard || event->block.seqno() == 0) {
      return;
    }
    on_new_accepted_block(event->block);
  }

  template <>
  td::actor::Task<ValidateCandidateResult> process(BusHandle, std::shared_ptr<ValidationRequest> event) {
    auto& bus = *owning_bus();

    owning_bus().publish<TraceEvent>(stats::ValidationStarted::create(event->candidate->id));

    auto empty_fn = [&](const BlockReferences& refs) -> td::actor::Task<ValidateCandidateResult> {
      if (!event->state->as_normal() || refs != event->state->block_ids()) {
        co_return CandidateReject{
            .reason = "Wrong referenced block in empty candidate",
            .proof = td::BufferSlice(),
        };
      }
      co_return CandidateAccept{};
    };
    auto block_fn = [&](const CandidateBlocks& blocks) -> td::actor::Task<ValidateCandidateResult> {
      if (bus.shard.is_masterchain()) {
        auto expected_seqno = event->state->as_normal();
        while (last_accepted_block_ < expected_seqno) {
          auto [awaiter, promise] = td::actor::StartedTask<>::make_bridge();
          next_block_promises_.push_back(std::move(promise));
          co_await std::move(awaiter);
        }
        if (expected_seqno < last_accepted_block_) {
          co_return td::Status::Error(PSTRING()
                                      << "Candidate " << event->candidate->id << " builds upon " << expected_seqno
                                      << " but we already finalized " << last_accepted_block_);
        }
      }

      std::shared_ptr<const ShardGroupMessages> messages;
      std::shared_ptr<const ShardGroupMessageOrder> order;
      if (!bus.group_members.empty()) {
        auto view = ShardGroupMessages::extract(blocks, bus.group_members);
        if (view.is_error()) {
          co_return CandidateReject{view.move_as_error().to_string(), {}};
        }
        messages = view.move_as_ok();
        order = co_await event->state->group_message_order(bus.manager);
        std::optional<double> timestamp;
        for (const auto& block : blocks) {
          auto t = get_candidate_gen_utime_exact(block);
          if (t.is_error() || (timestamp && *timestamp != t.ok())) {
            co_return CandidateReject{"Different generation times in shard group", {}};
          }
          timestamp = t.ok();
        }
      }
      std::vector<td::actor::StartedTask<ValidateCandidateResult>> validations;
      for (size_t i = 0; i < blocks.size(); ++i) {
        const ChainState& state = event->state->member(i);
        ValidateParams params{
            .shard = bus.group_members.empty() ? bus.shard : bus.group_members[i],
            .min_masterchain_block_id = state.min_mc_block_id(),
            .prev = state.block_ids(),
            .local_validator_id = bus.local_id->short_id,
            .group_messages = messages,
            .group_message_order = order,
            .prev_block_state_roots = state.state(),
        };
        validations.push_back(td::actor::ask(bus.manager, &ManagerFacade::validate_block_candidate, blocks[i].clone(),
                                             std::move(params), td::Timestamp::in(60.0)));
      }
      CandidateAccept accepted{};
      for (auto& result : co_await td::actor::all(std::move(validations))) {
        if (result.has<CandidateReject>()) {
          co_return std::move(result);
        }
        accepted.ok_from_utime = std::max(accepted.ok_from_utime, result.get<CandidateAccept>().ok_from_utime);
      }
      co_return accepted;
    };
    auto validation_result = co_await std::visit(td::overloaded(block_fn, empty_fn), event->candidate->block);

    owning_bus().publish<TraceEvent>(stats::ValidationFinished::create(event->candidate->id));

    if (validation_result.has<CandidateReject>()) {
      if (event->candidate->leader == bus.local_id->idx) {
        LOG(ERROR) << "BUG! Candidate " << event->candidate->id
                   << " is self-rejected: " << validation_result.get<CandidateReject>().reason;
      }
      co_return validation_result;
    }

    td::Timestamp ok_from = td::Timestamp::at_unix(validation_result.get<CandidateAccept>().ok_from_utime);
    if (!ok_from.is_in_past()) {
      LOG(INFO) << "Candidate " << event->candidate->id << " has timestamp in the future, wait for " << ok_from.in()
                << " s";
      co_await td::actor::coro_sleep(ok_from);
    }
    co_return validation_result;
  }

 private:
  void on_new_accepted_block(std::optional<BlockIdExt> block) {
    if (last_accepted_block_ < block) {
      last_accepted_block_ = block;
      auto next_block_promises = std::move(next_block_promises_);
      for (auto& promise : next_block_promises) {
        promise.set_value({});
      }
    }
  }

  std::optional<BlockIdExt> last_accepted_block_;
  std::vector<td::Promise<>> next_block_promises_;
};

}  // namespace

void BlockValidator::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<BlockValidatorImpl>("BlockValidator");
}

}  // namespace ton::validator::consensus
