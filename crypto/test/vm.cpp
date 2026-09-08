/*
    This file is part of TON Blockchain Library.

    TON Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TON Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TON Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
*/
#include <array>
#include <memory>
#include <set>
#include <vector>

#include "common/bigint.hpp"
#include "fift/utils.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/base64.h"
#include "td/utils/tests.h"
#include "vm/cp0.h"
#include "vm/boc.h"
#include "vm/cells/UsageCell.h"
#include "vm/dict.h"
#include "vm/vm.h"

std::string run_vm(td::Ref<vm::Cell> cell) {
  vm::init_vm().ensure();
  vm::DictionaryBase::get_empty_dictionary();

  class Logger : public td::LogInterface {
   public:
    void append(td::CSlice slice) override {
      res.append(slice.data(), slice.size());
    }
    std::string res;
  };
  static Logger logger;
  logger.res = "";
  td::set_log_fatal_error_callback([](td::CSlice message) { td::default_log_interface->append(logger.res); });
  vm::VmLog log{&logger, td::LogOptions::plain()};
  log.log_options.level = 4;
  log.log_options.fix_newlines = true;
  log.log_mask |= vm::VmLog::DumpStack;

  auto total_data_cells_before = vm::DataCell::get_total_data_cells();
  SCOPE_EXIT {
    auto total_data_cells_after = vm::DataCell::get_total_data_cells();
    ASSERT_EQ(total_data_cells_before, total_data_cells_after);
  };

  vm::Stack stack;
  try {
    vm::GasLimits gas_limit(1000, 1000);

    vm::run_vm_code(vm::load_cell_slice_ref(cell), stack, 0 /*flags*/, nullptr /*data*/, std::move(log) /*VmLog*/,
                    nullptr, &gas_limit);
  } catch (...) {
    LOG(FATAL) << "catch unhandled exception";
  }
  return logger.res;  // must be a copy
}

td::Ref<vm::Cell> to_cell(const unsigned char *buff, int bits) {
  return vm::CellBuilder().store_bits(buff, bits, 0).finalize();
}
void test_run_vm(td::Ref<vm::Cell> code) {
  auto a = run_vm(code);
  auto b = run_vm(code);
  ASSERT_EQ(a, b);
  REGRESSION_VERIFY(a);
}

void test_run_vm(td::Slice code_hex) {
  unsigned char buff[128];
  int bits = (int)td::bitstring::parse_bitstring_hex_literal(buff, sizeof(buff), code_hex.begin(), code_hex.end());
  CHECK(bits >= 0);
  test_run_vm(to_cell(buff, bits));
}

void test_run_vm_raw(td::Slice code64) {
  auto code = td::base64_decode(code64).move_as_ok();
  if (code.size() > 127) {
    code.resize(127);
  }
  test_run_vm(vm::CellBuilder().store_bytes(code).finalize());
}

TEST(VM, simple) {
  test_run_vm("ABCBABABABA");
}

TEST(VM, memory_leak_old) {
  test_run_vm("90787FDB3B");
}

TEST(VM, memory_leak) {
  test_run_vm("90707FDB3B");
}

TEST(VM, bug_div_short_any) {
  test_run_vm("6883FF73A98D");
}
TEST(VM, assert_pfx_dict_lookup) {
  test_run_vm("778B04216D73F43E018B04591277F473");
}

TEST(VM, assert_lookup_prefix) {
  test_run_vm("78E58B008B028B04010000016D90ED5272F43A755D77F4A8");
}

TEST(VM, assert_code_not_null) {
  test_run_vm("76ED40DE");
}

TEST(VM, bug_exec_dict_getnear) {
  test_run_vm("8B048B00006D72F47573655F6D656D6D656D8B007F");
}

TEST(VM, bug_stack_overflow) {
  test_run_vm("72A93AF8");
}

TEST(VM, assert_extract_minmax_key) {
  test_run_vm("6D6DEB21807AF49C2180EB21807AF41C");
}

TEST(VM, memory_leak_new) {
  test_run_vm("72E5ED40DB3603");
}

TEST(VM, unhandled_exception_1) {
  test_run_vm("70EDA2ED00");
}

TEST(VM, unhandled_exception_2) {
  // infinite loop now
  test_run_vm("EBEDB4");
}

TEST(VM, unhandled_exception_3) {
  // infinite loop now
  test_run_vm("EBEDC0");
}

TEST(VM, unhandled_exception_4) {
  test_run_vm("7F853EA1C8CB3E");
}

TEST(VM, unhandled_exception_5) {
  test_run_vm("738B04016D21F41476A721F49F");
}

TEST(VM, infinity_loop_1) {
  test_run_vm_raw("f3r4AJGQ6rDraIQ=");
}
TEST(VM, infinity_loop_2) {
  test_run_vm_raw("kpTt7ZLrig==");
}

TEST(VM, oom_1) {
  test_run_vm_raw("bXflX/BvDw==");
}

TEST(VM, bigint) {
  td::StringBuilder sb({}, true);

  using word_t = td::BigIntInfo::word_t;
  std::vector<word_t> numbers{1,
                              -1,
                              2,
                              -2,
                              100,
                              -100,
                              std::numeric_limits<word_t>::max(),
                              std::numeric_limits<word_t>::min(),
                              std::numeric_limits<word_t>::max() - 1,
                              std::numeric_limits<word_t>::min() + 1};
  for (auto x : numbers) {
    for (auto y : numbers) {
      word_t a;
      word_t b;
      td::BigIntInfo::set_mul(&a, &b, x, y);
      sb << "set_mul " << x << " * " << y << " = " << a << " " << b << "\n";
      td::BigIntInfo::add_mul(&a, &b, x, y);
      sb << "add_mul " << x << " " << y << " = " << a << " " << b << "\n";
      td::BigIntInfo::sub_mul(&a, &b, x, y);
      sb << "sub_mul " << x << " " << y << " = " << a << " " << b << "\n";
    }
  }
  auto base = td::BigIntInfo::Base;
  std::vector<word_t> lo_numbers{1, -1, 2, -2, 100, -100, base - 1, base - 2, -base + 1, -base + 2};
  for (auto x : numbers) {
    for (auto y : lo_numbers) {
      for (auto z : numbers) {
        word_t a;
        word_t b;
        td::BigIntInfo::dbl_divmod(&a, &b, x, y, z);
        sb << "dbl_divmod " << x << " " << y << " / " << z << " = " << a << " " << b << "\n";
      }
    }
  }

  REGRESSION_VERIFY(sb.as_cslice());
}

TEST(VM, report3_1) {
  //WA: expect (1, 2, 6, 3)
  td::Slice test1 =
      R"A(
CONT:<{
DEPTH
}>
3 SETNUMARGS
c0 POPCTR
1 INT
2 INT
3 INT
4 INT
5 INT
6 INT
4 RETURNARGS
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_2) {
  td::Slice test1 =
      R"A(
CONT:<{
DEPTH
}>
2 SETNUMARGS
c0 POPCTR
1 INT
2 INT
3 INT
4 INT
2 RETARGS
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_3) {
  // WA: expect (9)
  td::Slice test1 =
      R"A(
CONT:<{
 8 INT
}>
c0 POPCTR
CONT:<{
 9 INT
}>
c1 POPCTR
0 INT
BRANCH
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_4) {
  td::Slice test1 =
      R"A(
CONT:<{
1 INT
2 INT
3 INT
2 RETARGS
}>
CALLX
ADD
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_6) {
  // WA: expect StackOverflow
  td::Slice test1 =
      R"A(
10 INT
20 INT
30 INT
CONT:<{
  DEPTH
  40 INT
  SWAP
}>
2 SETNUMARGS
3 1 CALLXARGS
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

//TEST(VM, report3_ce) {
//td::Slice test1 =
//R"A(
//s16 POP
//s16 PUSH
//s0 s16 XCHG
//)A";
//test_run_vm(fift::compile_asm(test1).move_as_ok());
//}

TEST(VM, report3_int_overflow_1) {
  td::Slice test1 =
      R"A(
4 INT
16 INT
-115792089237316195423570985008687907853269984665640564039457584007913129639936 INT
MULDIVMOD
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}
TEST(VM, report3_int_overflow_2) {
  td::Slice test1 =
      R"A(
4 INT
16 INT
-115792089237316195423570985008687907853269984665640564039457584007913129639936 INT
MULDIVR
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_qnot) {
  td::Slice test1 =
      R"A(
PUSHNAN
QNOT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_1) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  2 INT
}>
ATEXITALT
CONT:<{
 1 INT
 RETALT
 -1 INT
}>
AGAIN
3 INT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_2) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  2 INT
}>
ATEXITALT
CONT:<{
 1 INT
 RETALT
 -1 INT
}>
UNTIL
3 INT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_3) {
  //WA
  td::Slice test1 =
      R"A(
1 INT
CONT:<{
  UNTILEND
  RET
  -1 INT
}>
CALLX
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_4) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  2 INT
}>
ATEXITALT
CONT:<{
  1 INT
  RETALT
  -1 PUSHINT
}>
CONT:<{
  -1 INT
}>
WHILE
3 INT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}
TEST(VM, report3_loop_5) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  1 INT
  2 INT
}>
ATEXITALT
3 INT
AGAINEND
DEC
DUP
IFRET
DROP
RETALT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_6) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  1 INT
  2 INT
}>
3 INT
AGAINEND
DEC
DUP
IFRET
DROP
ATEXITALT
RETALT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

namespace {

class DeferredSumAugmentation final : public vm::dict::AugmentationData {
 public:
  explicit DeferredSumAugmentation(bool variable = true) : variable_(variable) {
  }
  bool fail_fork{false};
  bool skip_extra(vm::CellSlice& cs) const override {
    return variable_ ? cs.have(4) && cs.advance(static_cast<unsigned>(cs.fetch_ulong(4)) * 8) : cs.advance(64);
  }
  bool eval_leaf(vm::CellBuilder& cb, vm::CellSlice& value) const override {
    return value.have(32) && store(cb, value.prefetch_ulong(32));
  }
  bool eval_fork(vm::CellBuilder& cb, vm::CellSlice& left, vm::CellSlice& right) const override {
    return !fail_fork && store(cb, read(left) + read(right));
  }
  bool eval_empty(vm::CellBuilder& cb) const override {
    return store(cb, 0);
  }

 private:
  bool variable_;
  bool store(vm::CellBuilder& cb, td::uint64 value) const {
    if (!variable_) {
      return cb.store_long_bool(value, 64);
    }
    unsigned bytes = 0;
    for (auto rest = value; rest; rest >>= 8) {
      ++bytes;
    }
    return cb.store_long_bool(bytes, 4) && cb.store_long_bool(value, bytes * 8);
  }
  td::uint64 read(vm::CellSlice& cs) const {
    return cs.fetch_ulong(variable_ ? static_cast<unsigned>(cs.fetch_ulong(4)) * 8 : 64);
  }
};

td::Ref<vm::Cell> deferred_value(unsigned balance, unsigned version) {
  auto payload = vm::CellBuilder{}.store_long(version, 32).finalize_novm();
  return vm::CellBuilder{}.store_long(balance, 32).store_ref(payload).finalize_novm();
}

void assert_deferred_roots(vm::AugmentedDictionary& serial, vm::AugmentedDictionary& deferred) {
  auto left = serial.get_root_cell();
  auto right = deferred.get_root_cell();
  ASSERT_EQ(left.is_null(), right.is_null());
  if (left.not_null()) {
    ASSERT_EQ(left->get_hash(), right->get_hash());
    auto a = vm::std_boc_serialize(left).move_as_ok();
    auto b = vm::std_boc_serialize(right).move_as_ok();
    ASSERT_EQ(a.as_slice(), b.as_slice());
  }
}

}  // namespace

TEST(VM, deferred_replacements_preserve_checkpoint_stats_and_eager_usage) {
  for (int width : {16, 256}) {
    for (bool variable : {false, true}) {
      DeferredSumAugmentation augmentation{variable};
      vm::AugmentedDictionary original{width, augmentation};
      std::vector<td::BitArray<256>> keys(96);
      for (unsigned i = 0; i < keys.size(); ++i) {
        keys[i].set_zero();
        keys[i].bits().store_uint(i * 601, 16);
        ASSERT_TRUE(original.set(keys[i].bits(), width, vm::load_cell_slice(deferred_value(i, i))));
      }
      auto serial_usage = std::make_shared<vm::CellUsageTree>();
      auto deferred_usage = std::make_shared<vm::CellUsageTree>();
      std::set<vm::CellHash> serial_loaded, deferred_loaded;
      serial_usage->set_cell_load_callback([&](const vm::LoadedCell& cell) {
        serial_loaded.insert(cell.data_cell->get_hash());
      });
      deferred_usage->set_cell_load_callback([&](const vm::LoadedCell& cell) {
        deferred_loaded.insert(cell.data_cell->get_hash());
      });
      vm::AugmentedDictionary serial{vm::UsageCell::create(original.get_root_cell(), serial_usage->root_ptr()),
                                     width, augmentation, false};
      vm::AugmentedDictionary deferred{vm::UsageCell::create(original.get_root_cell(), deferred_usage->root_ptr()),
                                       width, augmentation, false};
      vm::AugmentedDictionary::DeferredReplacements batch{deferred};
      vm::NewCellStorageStat serial_proof, deferred_proof;
      for (unsigned operation = 0; operation < 195; ++operation) {
        // Empty checkpoints, repeated keys, repeated values, shuffled full-width paths,
        // shrinking/growing augmentations, and an incomplete last batch.
        if (operation / 16 != 3 && operation / 16 != 8) {
          unsigned index = operation * 37 % keys.size();
          auto value = vm::load_cell_slice(deferred_value(operation % 5 == 0 ? 0 : 255 + operation, operation % 17));
          serial_proof.add_proof(value.prefetch_ref(), serial_usage.get());
          deferred_proof.add_proof(value.prefetch_ref(), deferred_usage.get());
          ASSERT_TRUE(serial.set(keys[index].bits(), width, value));
          ASSERT_TRUE(batch.replace(keys[index].bits(), width, value));
          // Match usage after each transaction, not just at the proof checkpoint.
          ASSERT_TRUE(serial_loaded == deferred_loaded);
        }
        if ((operation + 1) % 16 == 0) {
          batch.flush();
          assert_deferred_roots(serial, deferred);
          serial_proof.add_proof(serial.get_root_cell(), serial_usage.get());
          deferred_proof.add_proof(deferred.get_root_cell(), deferred_usage.get());
          ASSERT_TRUE(serial_proof.get_proof_stat() == deferred_proof.get_proof_stat());
          ASSERT_TRUE(serial_loaded == deferred_loaded);
        }
      }
      batch.flush();
      assert_deferred_roots(serial, deferred);
    }
  }
}

TEST(VM, deferred_replacements_fix_leaf_and_parent_byte_boundaries) {
  DeferredSumAugmentation augmentation;
  for (bool leaf_boundary : {false, true}) {
    vm::AugmentedDictionary serial{16, augmentation};
    td::BitArray<16> a, b{-1};
    a.set_zero();
    ASSERT_TRUE(serial.set(a, vm::load_cell_slice(deferred_value(leaf_boundary ? 255 : 100, 1))));
    ASSERT_TRUE(serial.set(b, vm::load_cell_slice(deferred_value(leaf_boundary ? 0 : 155, 2))));
    vm::AugmentedDictionary deferred{serial};
    auto old_bits = vm::load_cell_slice(serial.get_root_cell()).size();
    vm::AugmentedDictionary::DeferredReplacements batch{deferred};
    auto value = vm::load_cell_slice(deferred_value(leaf_boundary ? 256 : 101, 3));
    ASSERT_TRUE(serial.set(a, value));
    ASSERT_TRUE(batch.replace(a.bits(), 16, value));
    batch.flush();
    assert_deferred_roots(serial, deferred);
    ASSERT_EQ(vm::load_cell_slice(deferred.get_root_cell()).size(), old_bits + 8);
  }
}

TEST(VM, deferred_replacements_preserve_hash_deduplication) {
  DeferredSumAugmentation augmentation;
  vm::AugmentedDictionary serial{16, augmentation};
  td::BitArray<16> key{1};
  auto a = vm::load_cell_slice(deferred_value(1, 1));
  auto b = vm::load_cell_slice(deferred_value(2, 2));
  ASSERT_TRUE(serial.set(key, a));
  vm::AugmentedDictionary deferred{serial};
  vm::AugmentedDictionary::DeferredReplacements batch{deferred};
  auto usage = std::make_shared<vm::CellUsageTree>();
  vm::NewCellStorageStat serial_proof, deferred_proof;
  for (unsigned step = 0; step < 6; ++step) {
    const auto& value = step % 3 == 1 ? b : a;
    ASSERT_TRUE(serial.set(key, value));
    ASSERT_TRUE(batch.replace(key.bits(), 16, value));
    batch.flush();
    assert_deferred_roots(serial, deferred);
    auto before = deferred_proof.get_proof_stat();
    serial_proof.add_proof(serial.get_root_cell(), usage.get());
    deferred_proof.add_proof(deferred.get_root_cell(), usage.get());
    ASSERT_TRUE(serial_proof.get_proof_stat() == deferred_proof.get_proof_stat());
    if (step >= 2) {
      ASSERT_EQ(deferred_proof.get_proof_stat().cells, before.cells);
      ASSERT_EQ(deferred_proof.get_proof_stat().internal_refs, before.internal_refs + 1);
    }
  }
}

TEST(VM, deferred_replacements_flush_before_topology_fallback) {
  DeferredSumAugmentation augmentation;
  for (unsigned fallback_at : {0u, 15u, 16u, 19u, 31u}) {
    vm::AugmentedDictionary serial{16, augmentation};
    std::array<td::BitArray<16>, 3> keys{td::BitArray<16>{1}, td::BitArray<16>{2}, td::BitArray<16>{3}};
    for (unsigned i = 0; i < 2; ++i) {
      ASSERT_TRUE(serial.set(keys[i], vm::load_cell_slice(deferred_value(i + 1, i))));
    }
    auto usage = std::make_shared<vm::CellUsageTree>();
    vm::AugmentedDictionary deferred{serial};
    auto batch = std::make_unique<vm::AugmentedDictionary::DeferredReplacements>(deferred);
    vm::NewCellStorageStat serial_proof, deferred_proof;
    for (unsigned operation = 0; operation < 48; ++operation) {
      auto value = vm::load_cell_slice(deferred_value(operation + 255, operation));
      if (operation == fallback_at) {
        ASSERT_TRUE(!batch->replace(keys[2].bits(), 16, value));
        batch->flush();
        batch.reset();
        ASSERT_TRUE(serial.set(keys[2], value));
        ASSERT_TRUE(deferred.set(keys[2], value));
      } else if (operation == fallback_at + 1) {
        ASSERT_TRUE(serial.lookup_delete(keys[2]).not_null());
        ASSERT_TRUE(deferred.lookup_delete(keys[2]).not_null());
      } else {
        auto& key = keys[operation % 2];
        ASSERT_TRUE(serial.set(key, value));
        ASSERT_TRUE(batch ? batch->replace(key.bits(), 16, value) : deferred.set(key, value));
      }
      if ((operation + 1) % 16 == 0) {
        if (batch) {
          batch->flush();
        }
        assert_deferred_roots(serial, deferred);
        serial_proof.add_proof(serial.get_root_cell(), usage.get());
        deferred_proof.add_proof(deferred.get_root_cell(), usage.get());
        ASSERT_TRUE(serial_proof.get_proof_stat() == deferred_proof.get_proof_stat());
      }
    }
  }
}

TEST(VM, deferred_replacements_failures_do_not_publish_partial_root) {
  DeferredSumAugmentation augmentation;
  vm::AugmentedDictionary dictionary{16, augmentation};
  td::BitArray<16> a{1}, b{2}, missing{3};
  auto value = vm::load_cell_slice(deferred_value(255, 1));
  {
    vm::AugmentedDictionary::DeferredReplacements empty{dictionary};
    ASSERT_TRUE(!empty.replace(a.bits(), 16, value));
    empty.flush();
    ASSERT_TRUE(dictionary.is_empty());
  }
  ASSERT_TRUE(dictionary.set(a, value));
  ASSERT_TRUE(dictionary.set(b, value));
  auto root = dictionary.get_root_cell();
  vm::AugmentedDictionary::DeferredReplacements batch{dictionary};
  ASSERT_TRUE(!batch.replace(a.bits(), 15, value));
  ASSERT_TRUE(!batch.replace(missing.bits(), 16, value));
  ASSERT_TRUE(batch.replace(a.bits(), 16, vm::load_cell_slice(deferred_value(256, 2))));
  ASSERT_TRUE(dictionary.get_root_cell().get() == root.get());
  augmentation.fail_fork = true;
  bool threw = false;
  try {
    batch.flush();
  } catch (const vm::VmError&) {
    threw = true;
  }
  ASSERT_TRUE(threw);
  ASSERT_TRUE(dictionary.get_root_cell().get() == root.get());
}
