/*
 * Copyright (c) 2026, TON CORE TECHNOLOGIES CO. L.L.C
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include "block/mc-config.h"
#include "block/signature-set.h"
#include "consensus/types.h"
#include "keys/encryptor.h"
#include "td/actor/BackpressureQueue.h"
#include "td/actor/TestScheduler.h"
#include "td/utils/tests.h"
#include "tl-utils/tl-utils.hpp"
#include "ton/ton-shard.h"
#include "validator/impl/shard-group.h"

namespace ton::validator::consensus {
namespace {

td::Bits256 hash_for(unsigned i) {
  auto bits = td::Bits256::zero();
  bits.bits().store_uint(i, 32);
  return bits;
}

TEST(ShardGroups, CommitteeSelection) {
  block::TotalValidatorSet pool{0, 100, 16};
  for (int i = 0; i < pool.total; ++i) {
    pool.list.emplace_back(hash_for(i + 1), 1, pool.total_weight++);
  }
  block::CatchainValidatorsConfig ordinary{100, 100, 100, 4};
  auto grouped = ordinary;
  grouped.member_depth = 3;
  grouped.group_levels = 2;
  auto root = shard_child(ShardIdFull{basechainId}, true);
  auto member = shard_child(shard_child(root, true), false);
  for (unsigned epoch : {9u, 10u}) {
    auto expected = block::Config::do_compute_validator_set(ordinary, root, pool, epoch);
    ASSERT_EQ(4u, expected.size());
    for (auto shard : grouped.group_members(member)) {
      ASSERT_TRUE(expected == block::Config::do_compute_validator_set(grouped, shard, pool, epoch));
    }
    auto neighbor = shard_child(shard_child(shard_sibling(root), true), false);
    ASSERT_TRUE(expected != block::Config::do_compute_validator_set(grouped, neighbor, pool, epoch));
  }
}

TEST(ShardGroups, QueuedTransfersKeepTheirOrder) {
  ShardGroupMessageOrder::Route route{{basechainId, 9}, {basechainId, 40}};
  ShardGroupMessageOrder::Route other{{basechainId, 9}, {basechainId, 41}};
  ShardGroupMessageOrder order;
  ASSERT_TRUE(order.record(route, 56, false));
  ASSERT_TRUE(order.record(route, 52, true));
  ASSERT_TRUE(order.can_deliver(other, 90));
  ASSERT_TRUE(!order.can_deliver(route, 60));
  ASSERT_TRUE(!order.record(route, 60, true));
  // OutMsgDescr is traversed in message-hash order on a verifier.
  ShardGroupMessageOrder reversed;
  ASSERT_TRUE(reversed.record(route, 60, true));
  ASSERT_TRUE(!reversed.record(route, 56, false));
}

TEST(ShardGroups, LateExternalWakesAnIdleGroup) {
  using Exchange = ShardGroupExchange;
  using Externals = Exchange::Externals;
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<> {
    auto sender = shard_child(ShardIdFull{basechainId}, true), receiver = shard_sibling(sender);
    auto cutoff = td::Timestamp::in(1);
    auto exchange = td::actor::create_actor<Exchange>("exchange", 2, cutoff);
    td::actor::BackpressureQueue<int> inputs("externals", 1, [id = exchange.get(), sender](bool closed) {
      td::actor::send_closure(id, &Exchange::external_queue_ready, sender, closed);
    });
    auto next = [&](ShardIdFull shard, Externals ext, Exchange::Transfers outgoing = {}) {
      return td::actor::ask(exchange, &Exchange::exchange, shard, std::move(outgoing), true, ext);
    };
    auto a = next(sender, Externals::wait), b = next(receiver, Externals::done);
    co_await scheduler.wait_sync_work();
    ASSERT_TRUE(!a.await_ready() && !b.await_ready());
    ASSERT_TRUE(co_await inputs.push(42));
    ASSERT_TRUE((co_await std::move(a)).read_externals);
    ASSERT_EQ(42, co_await inputs.try_pop());
    a = next(sender, Externals::wait, {{receiver, 123, {}}});
    ASSERT_EQ(123u, (co_await std::move(b)).transfers.at(0).lt);
    b = next(receiver, Externals::done);
    co_await scheduler.wait_sync_work();
    ASSERT_TRUE(!a.await_ready() && !b.await_ready());
    scheduler.advance_time_to(cutoff);
    ASSERT_TRUE((co_await std::move(a)).read_externals);
    ASSERT_TRUE(co_await inputs.push(43));
    auto last = co_await next(sender, Externals::wait);
    ASSERT_TRUE(!last.read_externals && last.transfers.empty());
    ASSERT_EQ(1.0, last.wait_externals_time);
    ASSERT_TRUE((co_await std::move(b)).transfers.empty());
    co_return td::Unit{};
  });
}

TEST(ShardGroups, GroupProofs) {
  PrivateKey key{privkeys::Ed25519::random()};
  auto pub = key.compute_public_key();
  auto signer = key.create_decryptor().move_as_ok();
  std::vector<ValidatorDescr> validators{{Ed25519_PublicKey{pub.ed25519_value().raw()}, 1}};
  auto set = td::make_ref<block::ValidatorSet>(7, ShardIdFull{basechainId}, std::move(validators));
  auto session = hash_for(1);
  auto sign = [&](const CandidateHashData& data) {
    auto id = data.build_id_with(11).to_tl();
    auto vote = create_serialize_tl_object<ton_api::consensus_simplex_finalizeVote>(std::move(id));
    return signer->sign(create_serialize_tl_object<ton_api::consensus_dataToSign>(session, std::move(vote)))
        .move_as_ok();
  };
  auto certificate = [&](const CandidateHashData& data, td::BufferSlice sig) {
    std::vector<BlockSignature> signatures;
    signatures.emplace_back(pub.compute_short_id().bits256_value(), std::move(sig));
    return block::BlockSignatureSet::create_simplex(std::move(signatures), 7, set->get_validator_set_hash(), session,
                                                    11, data.to_tl());
  };

  auto shards = block::CatchainValidatorsConfig::group_members_at({basechainId, 1ULL << 62}, 1);
  CandidateHashData round{{}, {}, CandidateId{10, hash_for(2)}};
  for (auto shard : shards) {
    round.blocks.emplace_back(basechainId, shard.shard, 11, hash_for(3), hash_for(4));
    round.collated_file_hashes.push_back(hash_for(5));
  }
  auto verify = [&](const CandidateHashData& claimed) {
    auto proof = certificate(claimed, sign(round));
    return proof->check_signatures(set, round.blocks.front()).is_ok();
  };
  ASSERT_TRUE(verify(round));
  auto other = round;
  other.blocks.back().root_hash = hash_for(6);
  ASSERT_TRUE(!verify(other));
  other = round;
  other.collated_file_hashes.back() = hash_for(7);
  ASSERT_TRUE(!verify(other));
}

}  // namespace
}  // namespace ton::validator::consensus
