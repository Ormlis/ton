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
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <openssl/opensslv.h>

#include "crypto/Ed25519.h"
#include "td/utils/BigNum.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/base64.h"
#include "td/utils/misc.h"

#if TD_HAVE_OPENSSL

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "td/utils/ThreadSafeCounter.h"

namespace td {

namespace {

// Experiment switch; the cache algorithm below is copied from combined-fast-collation.
bool verification_cache_enabled() {
  static const bool enabled = [] {
    const char *value = std::getenv("TON_ED25519_CACHE");
    return value == nullptr || Slice{value} != "0";
  }();
  return enabled;
}

constexpr size_t kVerificationCacheMessageLimit = 128;
constexpr size_t kVerificationCacheSlotCount = 1 << 16;
static_assert((kVerificationCacheSlotCount & (kVerificationCacheSlotCount - 1)) == 0);

uint64 rotate_left(uint64 value, unsigned shift) {
  return (value << shift) | (value >> (64 - shift));
}

void sip_round(uint64 &v0, uint64 &v1, uint64 &v2, uint64 &v3) {
  v0 += v1;
  v1 = rotate_left(v1, 13);
  v1 ^= v0;
  v0 = rotate_left(v0, 32);
  v2 += v3;
  v3 = rotate_left(v3, 16);
  v3 ^= v2;
  v0 += v3;
  v3 = rotate_left(v3, 21);
  v3 ^= v0;
  v2 += v1;
  v1 = rotate_left(v1, 17);
  v1 ^= v2;
  v2 = rotate_left(v2, 32);
}

uint64 load_little_endian_64(const unsigned char *data) {
  return static_cast<uint64>(data[0]) | (static_cast<uint64>(data[1]) << 8) | (static_cast<uint64>(data[2]) << 16) |
         (static_cast<uint64>(data[3]) << 24) | (static_cast<uint64>(data[4]) << 32) |
         (static_cast<uint64>(data[5]) << 40) | (static_cast<uint64>(data[6]) << 48) |
         (static_cast<uint64>(data[7]) << 56);
}

uint64 sip_hash_2_4(const unsigned char *data, size_t size, uint64 key0, uint64 key1) {
  uint64 v0 = key0 ^ 0x736f6d6570736575ULL;
  uint64 v1 = key1 ^ 0x646f72616e646f6dULL;
  uint64 v2 = key0 ^ 0x6c7967656e657261ULL;
  uint64 v3 = key1 ^ 0x7465646279746573ULL;

  const auto *end = data + (size & ~static_cast<size_t>(7));
  while (data != end) {
    uint64 word = load_little_endian_64(data);
    v3 ^= word;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= word;
    data += 8;
  }

  uint64 tail = static_cast<uint64>(size) << 56;
  switch (size & 7) {
    case 7:
      tail |= static_cast<uint64>(data[6]) << 48;
      [[fallthrough]];
    case 6:
      tail |= static_cast<uint64>(data[5]) << 40;
      [[fallthrough]];
    case 5:
      tail |= static_cast<uint64>(data[4]) << 32;
      [[fallthrough]];
    case 4:
      tail |= static_cast<uint64>(data[3]) << 24;
      [[fallthrough]];
    case 3:
      tail |= static_cast<uint64>(data[2]) << 16;
      [[fallthrough]];
    case 2:
      tail |= static_cast<uint64>(data[1]) << 8;
      [[fallthrough]];
    case 1:
      tail |= static_cast<uint64>(data[0]);
      [[fallthrough]];
    case 0:
      break;
  }

  v3 ^= tail;
  sip_round(v0, v1, v2, v3);
  sip_round(v0, v1, v2, v3);
  v0 ^= tail;
  v2 ^= 0xff;
  sip_round(v0, v1, v2, v3);
  sip_round(v0, v1, v2, v3);
  sip_round(v0, v1, v2, v3);
  sip_round(v0, v1, v2, v3);
  return v0 ^ v1 ^ v2 ^ v3;
}

// A canonical payload has no padding and a zeroed data tail.  Consequently a
// successful cache lookup always compares every correctness-relevant byte, not
// just the adversary-resistant table index hash.
struct VerificationCachePayload {
  uint64 generation;
  uint64 hash;
  uint64 data_size;
  std::array<unsigned char, Ed25519::PublicKey::LENGTH> public_key;
  std::array<unsigned char, 64> signature;
  std::array<unsigned char, kVerificationCacheMessageLimit> data;
};

static_assert(offsetof(VerificationCachePayload, generation) == 0);
static_assert(offsetof(VerificationCachePayload, hash) == 8);
static_assert(offsetof(VerificationCachePayload, data_size) == 16);
static_assert(offsetof(VerificationCachePayload, public_key) == 24);
static_assert(offsetof(VerificationCachePayload, signature) == 56);
static_assert(offsetof(VerificationCachePayload, data) == 120);
static_assert(sizeof(VerificationCachePayload) == 248);
static_assert(sizeof(VerificationCachePayload) % sizeof(uint64) == 0);
constexpr size_t kVerificationCachePayloadWords = sizeof(VerificationCachePayload) / sizeof(uint64);

// Plain seqlock payload accesses have a C++ data race even on hardware where
// torn reads are detected by the sequence.  Every runtime access to these BSS
// words goes through a lock-free atomic_ref: this preserves the same x86 MOV-
// based snapshot, makes concurrency defined C++, and avoids millions of
// constexpr std::atomic construction steps for the large table.
static_assert(std::atomic_ref<uint64>::is_always_lock_free);
static_assert(alignof(uint64) >= std::atomic_ref<uint64>::required_alignment);

struct alignas(64) VerificationCacheSlot {
  uint64 sequence{0};
  std::array<uint64, kVerificationCachePayloadWords> payload{};
};

static_assert(sizeof(VerificationCacheSlot) == 256);
static_assert(alignof(VerificationCacheSlot) == 64);

struct VerificationCacheTable {
  std::array<VerificationCacheSlot, kVerificationCacheSlotCount> slots{};
};

// Constant initialization leaves the 16 MiB table in BSS.  There is no first-
// verification sweep and untouched pages need not become resident.
constinit VerificationCacheTable verification_cache_table{};

class Ed25519VerificationCache {
 public:
  struct Lookup {
    VerificationCachePayload expected{};
    bool cacheable{false};
    bool hit{false};
  };

  Ed25519VerificationCache() {
    std::array<unsigned char, sizeof(hash_key_)> random_key{};
    if (RAND_bytes(random_key.data(), static_cast<int>(random_key.size())) == 1) {
      std::memcpy(hash_key_.data(), random_key.data(), random_key.size());
      hash_key_ready_ = true;
    }
  }

  Lookup lookup(Slice public_key, Slice data, Slice signature) {
    if (data.size() > kVerificationCacheMessageLimit || !hash_key_ready_) {
      counters_.add(Bypass, 1);
      return {};
    }

    Lookup result;
    uint64 generation = generation_.load(std::memory_order_acquire);
    result.expected = make_payload(generation, public_key, data, signature);
    result.cacheable = true;
    auto &slot = slot_for(result.expected.hash);

    uint64 sequence_before = atomic(slot.sequence).load(std::memory_order_acquire);
    if (sequence_before & 1) {
      counters_.add(Miss, 1);
      return result;
    }

    auto snapshot = load_payload(slot);
    // Keep every payload load before the validation read on weakly ordered
    // architectures.  This is a compiler barrier only on x86.
    std::atomic_thread_fence(std::memory_order_acquire);
    uint64 sequence_after = atomic(slot.sequence).load(std::memory_order_acquire);
    if (sequence_before != sequence_after || (sequence_after & 1) ||
        generation_.load(std::memory_order_acquire) != generation) {
      counters_.add(Miss, 1);
      return result;
    }

    if (std::memcmp(&snapshot, &result.expected, sizeof(snapshot)) == 0) {
      counters_.add(Hit, 1);
      result.hit = true;
      return result;
    }
    counters_.add(Miss, 1);
    return result;
  }

  void insert(Lookup lookup) {
    if (!lookup.cacheable) {
      return;
    }
    uint64 generation = generation_.load(std::memory_order_acquire);
    lookup.expected.generation = generation;
    auto &slot = slot_for(lookup.expected.hash);
    auto sequence_word = atomic(slot.sequence);
    uint64 sequence = sequence_word.load(std::memory_order_relaxed);
    if (sequence & 1) {
      counters_.add(WriteContention, 1);
      return;
    }
    if (!sequence_word.compare_exchange_strong(sequence, sequence + 1, std::memory_order_acq_rel,
                                               std::memory_order_relaxed)) {
      counters_.add(WriteContention, 1);
      return;
    }

    bool evicted = atomic(slot.payload[0]).load(std::memory_order_relaxed) == generation;
    store_payload(slot, lookup.expected);
    sequence_word.store(sequence + 2, std::memory_order_release);
    counters_.add(Insert, 1);
    if (evicted) {
      counters_.add(Eviction, 1);
    }
  }

  Ed25519::VerificationCacheStats get_stats() {
    Ed25519::VerificationCacheStats result;
    result.hits = counter_sum(Hit);
    result.misses = counter_sum(Miss);
    result.bypasses = counter_sum(Bypass);
    result.inserts = counter_sum(Insert);
    result.evictions = counter_sum(Eviction);
    result.write_contentions = counter_sum(WriteContention);
    return result;
  }

  void clear() {
    // Wrapping would make entries from the first generation visible again.
    // Reaching it requires 2^64 process-local test/administrative clears.
    uint64 generation = generation_.load(std::memory_order_relaxed);
    while (true) {
      CHECK(generation != std::numeric_limits<uint64>::max());
      if (generation_.compare_exchange_weak(generation, generation + 1, std::memory_order_acq_rel,
                                            std::memory_order_relaxed)) {
        break;
      }
    }
    counters_.clear();
  }

  void reset_stats() {
    counters_.clear();
  }

 private:
  enum Counter : size_t { Hit, Miss, Bypass, Insert, Eviction, WriteContention, CounterCount };

  static std::atomic_ref<uint64> atomic(uint64 &word) {
    return std::atomic_ref<uint64>(word);
  }

  static VerificationCachePayload load_payload(VerificationCacheSlot &slot) {
    VerificationCachePayload result;
    auto *destination = reinterpret_cast<unsigned char *>(&result);
    for (size_t i = 0; i < kVerificationCachePayloadWords; ++i) {
      uint64 word = atomic(slot.payload[i]).load(std::memory_order_relaxed);
      std::memcpy(destination + i * sizeof(word), &word, sizeof(word));
    }
    return result;
  }

  static void store_payload(VerificationCacheSlot &slot, const VerificationCachePayload &payload) {
    const auto *source = reinterpret_cast<const unsigned char *>(&payload);
    for (size_t i = 0; i < kVerificationCachePayloadWords; ++i) {
      uint64 word;
      std::memcpy(&word, source + i * sizeof(word), sizeof(word));
      atomic(slot.payload[i]).store(word, std::memory_order_relaxed);
    }
  }

  VerificationCachePayload make_payload(uint64 generation, Slice public_key, Slice data, Slice signature) const {
    VerificationCachePayload result{};
    result.generation = generation;
    result.data_size = data.size();
    std::memcpy(result.public_key.data(), public_key.ubegin(), result.public_key.size());
    std::memcpy(result.signature.data(), signature.ubegin(), result.signature.size());
    if (!data.empty()) {
      std::memcpy(result.data.data(), data.ubegin(), data.size());
    }
    const auto *hash_begin = reinterpret_cast<const unsigned char *>(&result.data_size);
    size_t hash_size = sizeof(result.data_size) + result.public_key.size() + result.signature.size() + data.size();
    result.hash = sip_hash_2_4(hash_begin, hash_size, hash_key_[0], hash_key_[1]);
    return result;
  }

  static VerificationCacheSlot &slot_for(uint64 hash) {
    return verification_cache_table.slots[hash & (kVerificationCacheSlotCount - 1)];
  }

  uint64 counter_sum(Counter counter) const {
    auto value = counters_.sum(counter);
    CHECK(value >= 0);
    return static_cast<uint64>(value);
  }

  std::array<uint64, 2> hash_key_{};
  bool hash_key_ready_{false};
  std::atomic<uint64> generation_{1};
  td::ThreadSafeMultiCounter<CounterCount> counters_;
};

Ed25519VerificationCache &ed25519_verification_cache() {
  static Ed25519VerificationCache cache;
  return cache;
}

}  // namespace

Ed25519::PublicKey::PublicKey(SecureString octet_string) : octet_string_(std::move(octet_string)) {
}

SecureString Ed25519::PublicKey::as_octet_string() const {
  return octet_string_.copy();
}

Ed25519::PrivateKey::PrivateKey(SecureString octet_string) : octet_string_(std::move(octet_string)) {
}

SecureString Ed25519::PrivateKey::as_octet_string() const {
  return octet_string_.copy();
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
namespace detail {

static Result<SecureString> X25519_key_from_PKEY(EVP_PKEY *pkey, bool is_private) {
  auto func = is_private ? &EVP_PKEY_get_raw_private_key : &EVP_PKEY_get_raw_public_key;
  size_t len = 0;
  if (func(pkey, nullptr, &len) == 0) {
    return Status::Error("Failed to get raw key length");
  }
  CHECK(len == 32);

  SecureString result(len);
  if (func(pkey, result.as_mutable_slice().ubegin(), &len) == 0) {
    return Status::Error("Failed to get raw key");
  }
  return std::move(result);
}

static EVP_PKEY *X25519_key_to_PKEY(Slice key, bool is_private) {
  auto func = is_private ? &EVP_PKEY_new_raw_private_key : &EVP_PKEY_new_raw_public_key;
  return func(EVP_PKEY_ED25519, nullptr, key.ubegin(), key.size());
}

static Result<SecureString> X25519_pem_from_PKEY(EVP_PKEY *pkey, bool is_private, std::optional<Slice> o_password) {
  BIO *mem_bio = BIO_new(BIO_s_mem());
  SCOPE_EXIT {
    BIO_vfree(mem_bio);
  };
  if (is_private) {
    auto *chipher = o_password ? EVP_aes_256_cbc() : nullptr;
    const unsigned char *password = o_password ? o_password->ubegin() : nullptr;
    size_t password_size = o_password ? o_password->size() : 0;
    PEM_write_bio_PrivateKey(mem_bio, pkey, chipher, const_cast<unsigned char *>(password),
                             narrow_cast<int>(password_size), nullptr, nullptr);
  } else {
    PEM_write_bio_PUBKEY(mem_bio, pkey);
  }
  char *data_ptr = nullptr;
  auto data_size = BIO_get_mem_data(mem_bio, &data_ptr);
  return std::string(data_ptr, data_size);
}

static int password_cb(char *buf, int size, int rwflag, void *u) {
  auto &password = *reinterpret_cast<Slice *>(u);
  auto password_size = narrow_cast<int>(password.size());
  if (size < password_size) {
    return -1;
  }
  if (rwflag == 0) {
    MutableSlice(buf, size).copy_from(password);
  }
  return password_size;
}

static EVP_PKEY *X25519_pem_to_PKEY(Slice pem, Slice password) {
  BIO *mem_bio = BIO_new_mem_buf(pem.ubegin(), narrow_cast<int>(pem.size()));
  SCOPE_EXIT {
    BIO_vfree(mem_bio);
  };

  return PEM_read_bio_PrivateKey(mem_bio, nullptr, password_cb, &password);
}

}  // namespace detail
#endif

Result<Ed25519::PrivateKey> Ed25519::generate_private_key() {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_ED25519, nullptr);
  if (pctx == nullptr) {
    return Status::Error("Can't create EVP_PKEY_CTX");
  }
  SCOPE_EXIT {
    EVP_PKEY_CTX_free(pctx);
  };

  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    return Status::Error("Can't init keygen");
  }

  EVP_PKEY *pkey = nullptr;
  if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    return Status::Error("Can't generate random private key");
  }
  SCOPE_EXIT {
    EVP_PKEY_free(pkey);
  };

  TRY_RESULT(private_key, detail::X25519_key_from_PKEY(pkey, true));
  return std::move(private_key);
#else
  return Status::Error("Unsupported");
#endif
}

Result<Ed25519::PublicKey> Ed25519::PrivateKey::get_public_key() const {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  auto pkey = detail::X25519_key_to_PKEY(octet_string_, true);
  if (pkey == nullptr) {
    return Status::Error("Can't import private key");
  }
  SCOPE_EXIT {
    EVP_PKEY_free(pkey);
  };

  TRY_RESULT(key, detail::X25519_key_from_PKEY(pkey, false));
  return Ed25519::PublicKey(std::move(key));
#else
  return Status::Error("Unsupported");
#endif
}

Result<SecureString> Ed25519::PrivateKey::as_pem(Slice password) const {
  return as_pem(std::optional<td::Slice>(password));
}
Result<SecureString> Ed25519::PrivateKey::as_pem() const {
  return as_pem(std::nullopt);
}
Result<SecureString> Ed25519::PrivateKey::as_pem(std::optional<td::Slice> o_password) const {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  auto pkey = detail::X25519_key_to_PKEY(octet_string_, true);
  if (pkey == nullptr) {
    return Status::Error("Can't import private key");
  }
  SCOPE_EXIT {
    EVP_PKEY_free(pkey);
  };

  return detail::X25519_pem_from_PKEY(pkey, true, o_password);
#else
  return Status::Error("Unsupported");
#endif
}

Result<Ed25519::PrivateKey> Ed25519::PrivateKey::from_pem(Slice pem, Slice password) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  auto pkey = detail::X25519_pem_to_PKEY(pem, password);
  if (pkey == nullptr) {
    return Status::Error("Can't import private key from pem");
  }
  TRY_RESULT(key, detail::X25519_key_from_PKEY(pkey, true));
  return Ed25519::PrivateKey(std::move(key));
#else
  return Status::Error("Unsupported");
#endif
}

struct Ed25519::PreparedPrivateKey {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  explicit PreparedPrivateKey(EVP_PKEY *pkey) : pkey_(pkey) {
  }
  EVP_PKEY *pkey_ = nullptr;
  PreparedPrivateKey(const PreparedPrivateKey &) = delete;
  PreparedPrivateKey(const PreparedPrivateKey &&) = delete;
  PreparedPrivateKey &operator=(const PreparedPrivateKey &) = delete;
  PreparedPrivateKey &operator=(const PreparedPrivateKey &&) = delete;
  ~PreparedPrivateKey() {
    if (pkey_ != nullptr) {
      EVP_PKEY_free(pkey_);
      pkey_ = nullptr;
    }
  }
#endif
};

Result<std::shared_ptr<const Ed25519::PreparedPrivateKey>> Ed25519::PrivateKey::prepare() const {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  auto pkey = detail::X25519_key_to_PKEY(octet_string_, true);
  if (pkey == nullptr) {
    return Status::Error("Can't import private key");
  }
  return std::make_shared<Ed25519::PreparedPrivateKey>(pkey);
#else
  return Status::Error("Unsupported");
#endif
}

Result<SecureString> Ed25519::PrivateKey::sign(const PreparedPrivateKey &prepared_private_key, Slice data) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  CHECK(prepared_private_key.pkey_ != nullptr);
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr) {
    return Status::Error("Can't create EVP_MD_CTX");
  }
  SCOPE_EXIT {
    EVP_MD_CTX_free(md_ctx);
  };

  if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, prepared_private_key.pkey_) <= 0) {
    return Status::Error("Can't init DigestSign");
  }

  SecureString res(64, '\0');
  size_t len = 64;
  if (EVP_DigestSign(md_ctx, res.as_mutable_slice().ubegin(), &len, data.ubegin(), data.size()) <= 0) {
    return Status::Error("Can't sign data");
  }
  return std::move(res);
#else
  return Status::Error("Unsupported");
#endif
}

Result<SecureString> Ed25519::PrivateKey::sign(Slice data) const {
  // Counted here rather than in the PreparedPrivateKey overload so the cost includes importing the
  // key, which is what every caller pays today and what verify_signature measures on its side.
  TD_PERF_COUNTER(Ed25519_sign);
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  auto pkey = detail::X25519_key_to_PKEY(octet_string_, true);
  if (pkey == nullptr) {
    return Status::Error("Can't import private key");
  }
  return sign(PreparedPrivateKey(pkey), data);
#else
  return Status::Error("Unsupported");
#endif
}

Status Ed25519::PublicKey::verify_signature(Slice data, Slice signature) const {
  TD_PERF_COUNTER(Ed25519_verify_signature);
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  // A positive exact entry proves that this same 32-byte key imported and
  // verified before.  Malformed lengths bypass this fast path and retain the
  // untouched legacy import/context/error order below.
  Ed25519VerificationCache::Lookup cache_lookup;
  const bool cache_enabled = verification_cache_enabled();
  if (cache_enabled && octet_string_.size() == LENGTH && signature.size() == 64) {
    cache_lookup = ed25519_verification_cache().lookup(octet_string_, data, signature);
    if (cache_lookup.hit) {
      return Status::OK();
    }
  }

  auto pkey = detail::X25519_key_to_PKEY(octet_string_, false);
  if (pkey == nullptr) {
    return Status::Error("Can't import public key");
  }
  SCOPE_EXIT {
    EVP_PKEY_free(pkey);
  };

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr) {
    return Status::Error("Can't create EVP_MD_CTX");
  }
  SCOPE_EXIT {
    EVP_MD_CTX_free(md_ctx);
  };

  if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
    return Status::Error("Can't init DigestVerify");
  }

  if (EVP_DigestVerify(md_ctx, signature.ubegin(), signature.size(), data.ubegin(), data.size()) == 1) {
    if (cache_enabled) {
      ed25519_verification_cache().insert(std::move(cache_lookup));
    }
    return Status::OK();
  }
  return Status::Error("Wrong signature");
#else
  return Status::Error("Unsupported");
#endif
}

Ed25519::VerificationCacheStats Ed25519::get_verification_cache_stats() {
  return ed25519_verification_cache().get_stats();
}

void Ed25519::clear_verification_cache() {
  ed25519_verification_cache().clear();
}

void Ed25519::reset_verification_cache_stats() {
  ed25519_verification_cache().reset_stats();
}

Result<SecureString> Ed25519::compute_shared_secret(const PublicKey &public_key, const PrivateKey &private_key) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  BigNum p = BigNum::from_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed").move_as_ok();
  auto public_y = public_key.as_octet_string();
  MutableSlice pub_slc = public_y.as_mutable_slice();
  if (pub_slc.size() != PublicKey::LENGTH) {
    return Status::Error("Wrong public key");
  }
  pub_slc[31] = static_cast<char>(public_y[31] & 127);
  BigNum y = BigNum::from_le_binary(public_y);
  BigNum y2 = y.clone();
  y += 1;
  y2 -= 1;

  BigNumContext context;

  BigNum::mod_sub(y2, p, y2, p, context);

  BigNum inverse_y_plus_1;
  TRY_STATUS(BigNum::mod_inverse(inverse_y_plus_1, y2, p, context));

  BigNum u;
  BigNum::mod_mul(u, y, inverse_y_plus_1, p, context);

  auto pr_key = private_key.as_octet_string();
  if (pr_key.size() != PrivateKey::LENGTH) {
    return Status::Error("Wrong private key");
  }
  unsigned char buf[64];
  SHA512(Slice(pr_key).ubegin(), pr_key.size(), buf);
  buf[0] &= 248;
  buf[31] &= 127;
  buf[31] |= 64;

  auto pkey_private = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, buf, 32);
  if (pkey_private == nullptr) {
    return Status::Error("Can't import private key");
  }
  SCOPE_EXIT {
    EVP_PKEY_free(pkey_private);
  };

  auto pub_key = u.to_le_binary(PublicKey::LENGTH);
  auto pkey_public = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, Slice(pub_key).ubegin(), pub_key.size());
  if (pkey_public == nullptr) {
    return Status::Error("Can't import public key");
  }
  SCOPE_EXIT {
    EVP_PKEY_free(pkey_public);
  };

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey_private, nullptr);
  if (ctx == nullptr) {
    return Status::Error("Can't create EVP_PKEY_CTX");
  }
  SCOPE_EXIT {
    EVP_PKEY_CTX_free(ctx);
  };

  if (EVP_PKEY_derive_init(ctx) <= 0) {
    return Status::Error("Can't init derive");
  }
  if (EVP_PKEY_derive_set_peer(ctx, pkey_public) <= 0) {
    return Status::Error("Can't init derive");
  }

  size_t result_len = 0;
  if (EVP_PKEY_derive(ctx, nullptr, &result_len) <= 0) {
    return Status::Error("Can't get result length");
  }
  if (result_len != 32) {
    return Status::Error("Unexpected result length");
  }

  SecureString result(result_len, '\0');
  if (EVP_PKEY_derive(ctx, result.as_mutable_slice().ubegin(), &result_len) <= 0) {
    return Status::Error("Failed to compute shared secret");
  }
  return std::move(result);
#else
  return Status::Error("Unsupported");
#endif
}

Result<SecureString> Ed25519::get_public_key(Slice private_key) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  if (private_key.size() != PrivateKey::LENGTH) {
    return Status::Error("Invalid X25519 private key");
  }
  auto pkey_private = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.ubegin(), private_key.size());
  if (pkey_private == nullptr) {
    return Status::Error("Invalid X25519 private key");
  }
  SCOPE_EXIT {
    EVP_PKEY_free(pkey_private);
  };

  size_t len = 0;
  if (EVP_PKEY_get_raw_public_key(pkey_private, nullptr, &len) == 0) {
    return Status::Error("Failed to get raw key length");
  }
  CHECK(len == PublicKey::LENGTH);

  SecureString result(len);
  if (EVP_PKEY_get_raw_public_key(pkey_private, result.as_mutable_slice().ubegin(), &len) == 0) {
    return Status::Error("Failed to get raw key");
  }
  return std::move(result);
#else
  return Status::Error("Unsupported");
#endif
}

int Ed25519::version() {
  return OPENSSL_VERSION_NUMBER;
}

}  // namespace td

#endif
