// Wrapper for RocksDB InlineSkipList to provide unified benchmark interface
#pragma once

#include "../../third_party/rocksdb/inlineskiplist.h"

#include <cstdint>
#include <cstring>
#include <string>

namespace bench {

// Bytewise comparator for benchmark keys
// Key format: [4-byte key_len][key_data][4-byte val_len][val_data]
struct BenchComparator {
  using DecodedType = const char*;

  int operator()(const char* a, const char* b) const {
    uint32_t len_a, len_b;
    memcpy(&len_a, a, sizeof(uint32_t));
    memcpy(&len_b, b, sizeof(uint32_t));

    size_t min_len = len_a < len_b ? len_a : len_b;
    int cmp = memcmp(a + 4, b + 4, min_len);
    if (cmp != 0) return cmp;
    if (len_a < len_b) return -1;
    if (len_a > len_b) return 1;
    return 0;
  }

  DecodedType decode_key(const char* key) const {
    return key;
  }
};

class RocksDBWrapper {
 public:
  static constexpr bool kThreadSafe = true;
  static constexpr const char* kName = "rocksdb";

  RocksDBWrapper()
      : allocator_(),
        list_(BenchComparator(), &allocator_, 12, 4) {}  // height=12, branch=4

  void insert(const char* key, size_t key_len,
              const char* value, size_t value_len) {
    // Encode: [key_len:4][key][value_len:4][value]
    size_t total = 4 + key_len + 4 + value_len;
    char* buf = list_.AllocateKey(total);

    uint32_t klen = static_cast<uint32_t>(key_len);
    uint32_t vlen = static_cast<uint32_t>(value_len);

    memcpy(buf, &klen, 4);
    memcpy(buf + 4, key, key_len);
    memcpy(buf + 4 + key_len, &vlen, 4);
    memcpy(buf + 8 + key_len, value, value_len);

    list_.InsertConcurrently(buf);
  }

  bool get(const char* key, size_t key_len, std::string* value) {
    // Build lookup key (just key part)
    size_t lookup_size = 4 + key_len + 4;  // key + empty value
    char lookup[256];  // Stack buffer for small keys
    char* lookup_buf = key_len < 248 ? lookup : new char[lookup_size];

    uint32_t klen = static_cast<uint32_t>(key_len);
    uint32_t vlen = 0;
    memcpy(lookup_buf, &klen, 4);
    memcpy(lookup_buf + 4, key, key_len);
    memcpy(lookup_buf + 4 + key_len, &vlen, 4);

    rocksdb::InlineSkipList<BenchComparator>::Iterator iter(&list_);
    iter.Seek(lookup_buf);

    if (lookup_buf != lookup) delete[] lookup_buf;

    if (!iter.Valid()) return false;

    // Check if key matches
    const char* found = iter.key();
    uint32_t found_len;
    memcpy(&found_len, found, sizeof(uint32_t));

    if (found_len != key_len || memcmp(found + 4, key, key_len) != 0) {
      return false;
    }

    // Extract value
    if (value) {
      uint32_t val_len;
      memcpy(&val_len, found + 4 + key_len, sizeof(uint32_t));
      value->assign(found + 8 + key_len, val_len);
    }
    return true;
  }

  // Note: RocksDB InlineSkipList doesn't support true deletion
  // We insert a tombstone-like entry (empty value marker)
  void remove(const char* key, size_t key_len) {
    // Insert with empty value acts as tombstone
    insert(key, key_len, nullptr, 0);
  }

  // Update is re-insert (new allocation)
  void update(const char* key, size_t key_len,
              const char* value, size_t value_len) {
    insert(key, key_len, value, value_len);
  }

  size_t memory_usage() const {
    return allocator_.MemoryUsage();
  }

  class Iterator {
   public:
    explicit Iterator(const RocksDBWrapper* wrapper)
        : iter_(&wrapper->list_) {}

    bool valid() const { return iter_.Valid(); }

    void next() { iter_.Next(); }

    void seek_to_first() { iter_.SeekToFirst(); }

    const char* key_data() const {
      return iter_.key() + 4;  // Skip length prefix
    }

    size_t key_size() const {
      uint32_t len;
      memcpy(&len, iter_.key(), sizeof(uint32_t));
      return len;
    }

   private:
    mutable rocksdb::InlineSkipList<BenchComparator>::Iterator iter_;
  };

  Iterator new_iterator() const {
    return Iterator(this);
  }

 private:
  rocksdb::SimpleArena allocator_;
  rocksdb::InlineSkipList<BenchComparator> list_;
};

}  // namespace bench
