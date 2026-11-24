/*
 * Copyright (c) 2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <cmath>

#include "block/block-auto.h"
#include "td/actor/SharedFuture.h"
#include "td/actor/coro_task.h"
#include "td/actor/coro_utils.h"
#include "validator/impl/shard-group.h"

#include "stats.h"
#include "window-producer.h"

namespace ton::validator::consensus {

namespace {
using ExternalMessages = td::PersistentTreap<td::Bits256, td::Unit>;
struct GeneratedRound {
  std::vector<GeneratedCandidate> members;
  std::vector<td::BufferSlice> encoded_members;
};
using GeneratedRoundRef = std::shared_ptr<GeneratedRound>;

struct GeneratedMember {
  GeneratedCandidate block;
  td::BufferSlice encoded;
};

td::actor::Task<GeneratedMember> collate_member(BusHandle bus, CollateParams params, td::CancellationToken token) {
  auto exchange = params.group_exchange;
  auto result = co_await td::actor::ask(bus->manager, &ManagerFacade::collate_block, std::move(params), token).wrap();
  if (result.is_error()) {
    if (!exchange.empty()) {
      td::actor::send_closure(exchange, &ShardGroupExchange::cancel);
    }
    co_return result.move_as_error();
  }
  GeneratedMember member{result.move_as_ok(), {}};
  if (!exchange.empty()) {
    co_await td::actor::detach_from_actor();
    member.encoded = CO_TRY(Candidate::encode_block(member.block.candidate));
  }
  co_return std::move(member);
}

td::actor::Task<GeneratedRoundRef> collate_round(BusHandle bus, ChainStateRef state, CollateParams common,
                                                 std::vector<ExternalMessages> processed, td::CancellationToken token) {
  const auto& members = bus->group_members;
  if (!members.empty()) {
    common.group_members = members;
    common.group_mc_state = co_await td::actor::ask(bus->manager, &ManagerFacade::group_masterchain_state);
    common.group_message_order = co_await state->group_message_order(bus->manager, common.group_mc_state);
    auto min_utime = common.group_mc_state->get_unix_time();
    for (size_t i = 0; i < members.size(); ++i) {
      block::gen::ShardStateUnsplit::Record prev;
      if (!tlb::unpack_cell(state->member(i).state().front(), prev)) {
        co_return td::Status::Error("Invalid previous state in shard group");
      }
      min_utime = std::max(min_utime, prev.gen_utime);
    }
    common.utime =
        std::max(common.utime.value(), double(min_utime) + (common.group_mc_state->get_global_version() < 13));
  }
  for (int attempt = 0;; ++attempt) {
    td::actor::ActorOwn<ShardGroupExchange> exchange;
    if (!members.empty()) {
      auto input_deadline = common.wait_externals_until ? common.wait_externals_until : common.external_msg_timeout();
      exchange = td::actor::create_actor<ShardGroupExchange>("shard-group-exchange", members.size(), input_deadline);
      common.group_exchange = exchange.get();
      common.attempt_idx = attempt;
    }
    std::vector<td::actor::StartedTask<GeneratedMember>> tasks;
    for (size_t i = 0; i < processed.size(); ++i) {
      auto params = common;
      const auto& member = state->member(i);
      params.shard = members.empty() ? bus->shard : members[i];
      params.prev = member.block_ids();
      params.prev_block_data = member.block_data();
      params.prev_block_state_roots = member.state();
      params.processed_external_messages = processed[i];
      tasks.push_back(collate_member(bus, std::move(params), token).start());
    }
    auto result = co_await td::actor::all(std::move(tasks)).wrap();
    if (result.is_ok()) {
      auto round = std::make_shared<GeneratedRound>();
      size_t wire_bytes = 1024;
      for (auto& member : result.ok_ref()) {
        round->members.push_back(std::move(member.block));
        if (!members.empty()) {
          wire_bytes += member.encoded.size() + 8;
          round->encoded_members.push_back(std::move(member.encoded));
        }
      }
      if (wire_bytes <= Bus::max_group_candidate_bytes) {
        co_return round;
      }
      result = td::Status::Error("Shard group exceeds the candidate resolution size limit");
    }
    if (members.empty() || token || common.hard_timeout.is_in_past() || attempt + 1 >= CollateParams::max_attempts) {
      co_return result.move_as_error();
    }
    LOG(WARNING) << "Retrying collation of the complete shard group: " << result.error();
  }
}
}  // namespace

td::actor::Task<> produce_window(BusHandle bus_handle, ProduceWindowContext ctx) {
  auto& bus = *bus_handle;

  ChainStateRef state = ctx.state;
  ParentId parent = ctx.base;
  bool block_generation_active = false;
  td::actor::SharedFuture<GeneratedRoundRef> block_generation;
  td::uint32 block_generation_target_slot = 0;
  std::vector<ExternalMessages> processed_external_messages(std::max<size_t>(1, bus.group_members.size()));

  std::chrono::milliseconds hard_timeout = std::max(ctx.target_rate * 3, std::chrono::milliseconds(60'000));
  std::chrono::milliseconds start_collate_before =
      bus.shard.is_masterchain() ? std::chrono::milliseconds(0) : ctx.target_rate;
  td::Timestamp slot_start = ctx.start_time;

  for (td::uint32 slot = ctx.start_slot; !ctx.is_superseded() && slot < ctx.end_slot; ++slot) {
    co_await td::actor::coro_sleep(slot_start - start_collate_before);
    if (ctx.is_superseded()) {
      break;
    }
    bool is_first_block = !parent.has_value();
    if (!block_generation_active && (!ctx.should_generate_empty_block(state) || is_first_block)) {
      block_generation_active = true;
      block_generation_target_slot = slot;
      CollateParams params{
          .shard = bus.shard,
          .min_masterchain_block_id = state->min_mc_block_id(),
          .prev = {},
          .creator = Ed25519_PublicKey{ctx.leader.key.ed25519_value().raw()},
          .first_in_window = slot == ctx.start_slot,
          .utime = slot_start.at_unix(),
          .hard_timeout = slot_start + hard_timeout,
      };
      if (bus.shard.is_masterchain()) {
        params.soft_timeout = slot_start + ctx.target_rate;
      } else {
        params.soft_timeout = bus.group_members.empty() ? slot_start : slot_start + ctx.target_rate;
        params.wait_externals_until = slot_start;
      }
      if (ctx.collator_node_id) {
        params.collator_node_id = *ctx.collator_node_id;
      }
      // Timestamped before the dispatch, so the mark is when collation was launched rather than
      // when the manager's queue got around to it; published after it, so no observer or reporter
      // turn is enqueued ahead of the request it is timing.
      auto collate_started = stats::CollateStarted::create(slot, slot_start);
      block_generation =
          collate_round(bus_handle, state, std::move(params), processed_external_messages, ctx.cancellation_token)
              .start();
      bus_handle.publish<TraceEvent>(std::move(collate_started));
    }
    co_await td::actor::coro_sleep(slot_start);

    GeneratedRoundRef generated_candidate;
    std::optional<td::uint32> attempted_collation_target;
    if (block_generation_active) {
      attempted_collation_target = block_generation_target_slot;
      auto r_candidate =
          co_await td::actor::await_with_timeout(block_generation.get(), slot_start + ctx.target_rate).wrap();
      // The first block in the session cannot be empty
      bool allow_empty = !is_first_block && ctx.allow_empty_on_generation_failure();
      if (r_candidate.is_error() && !allow_empty) {
        LOG(WARNING) << "Generating the first block: "
                     << (r_candidate.error().code() == td::actor::AWAIT_TIMEOUT_CODE ? "takes too long"
                                                                                     : r_candidate.error().to_string())
                     << ", don't generate empty block "
                     << (is_first_block ? "(first block)" : "(no finalized blocks for too long)");
        --slot;
        if (r_candidate.error().code() != td::actor::AWAIT_TIMEOUT_CODE) {
          block_generation_active = false;
          co_await td::actor::coro_sleep(td::Timestamp::in(0.1));
        }
        slot_start = std::max(slot_start, td::Timestamp::now());
        continue;
      }
      if (r_candidate.is_ok()) {
        generated_candidate = r_candidate.move_as_ok();
        block_generation_active = false;
      } else if (r_candidate.error().code() == td::actor::AWAIT_TIMEOUT_CODE) {
        generated_candidate.reset();
        LOG(WARNING) << "Generating an empty block for slot " << slot << ": block collation takes too long";
      } else {
        generated_candidate.reset();
        LOG(WARNING) << "Generating an empty block for slot " << slot << ": collation error: " << r_candidate.error();
        block_generation_active = false;
      }
    } else {
      generated_candidate.reset();
      LOG(WARNING) << "Generating an empty block for slot " << slot << ": new_seqno=" << state->next_seqno();
    }
    if (ctx.is_superseded()) {
      break;
    }

    CandidateId id;
    CandidateContents block;
    if (generated_candidate) {
      CHECK(attempted_collation_target.has_value());
      CandidateBlocks blocks;
      double finished_at_monotonic = 0.0;
      for (size_t i = 0; i < generated_candidate->members.size(); ++i) {
        auto& member = generated_candidate->members[i];
        td::actor::send_closure(bus.manager, &ManagerFacade::cache_block_candidate, member.candidate.clone());
        processed_external_messages[i] = std::move(member.processed_external_messages);
        finished_at_monotonic = std::max(finished_at_monotonic, member.collated_at_monotonic);
        blocks.push_back(std::move(member.candidate));
      }
      state = state->apply_blocks(blocks);
      block = std::move(blocks);
      id = CandidateHashData::from(block, parent).build_id_with(slot);
      if (!std::isfinite(finished_at_monotonic) || finished_at_monotonic <= 0.0) {
        // Synthetic/test ManagerFacade implementations may still return candidates without the
        // local telemetry field. Preserve correct ordering instead of using the steady-clock
        // epoch; production collators set it before fulfilling the promise.
        finished_at_monotonic = td::Timestamp::now().at();
      }
      bus_handle.publish<TraceEvent>(
          stats::CollateFinished::create(*attempted_collation_target, slot_start, id, finished_at_monotonic));
    } else {
      CHECK(parent.has_value());
      block = state->block_ids();
      id = CandidateHashData::from(block, parent).build_id_with(slot);
      // Preserve the launch slot even when a carried future changed from timeout to a terminal
      // error above and block_generation_active was cleared before we got here.
      auto target_slot = attempted_collation_target.value_or(slot);
      bus_handle.publish<TraceEvent>(stats::CollatedEmpty::create(target_slot, id));
    }

    auto id_to_sign = serialize_tl_object(id.to_tl(), true);
    auto data_to_sign = create_serialize_tl_object<tl::dataToSign>(bus.session_id, std::move(id_to_sign));
    auto signature =
        co_await td::actor::ask(bus.keyring, &keyring::Keyring::sign_message, ctx.signing_key, std::move(data_to_sign));
    std::optional<Delegation> delegation;
    if (ctx.delegation.has_value()) {
      delegation = ctx.delegation->clone();
    }
    std::vector<td::BufferSlice> encoded;
    if (generated_candidate) {
      encoded = std::move(generated_candidate->encoded_members);
    }
    auto candidate = td::make_ref<Candidate>(id, parent, ctx.leader.idx, std::move(block), std::move(signature),
                                             std::move(delegation), std::move(encoded));
    if (ctx.is_superseded()) {
      break;
    }
    bus_handle.publish<CandidateGenerated>(candidate);
    bus_handle.publish<CandidateReceived>(candidate);
    bus_handle.publish<TraceEvent>(stats::CandidateReceived::create(candidate, true));
    parent = id;

    slot_start += ctx.target_rate;
  }

  co_return {};
}

}  // namespace ton::validator::consensus
