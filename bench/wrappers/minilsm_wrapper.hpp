// Wrapper for minilsm SkipList to provide unified benchmark interface
#pragma once

#include "../../src/arena.hpp"
#include "../../src/key.hpp"
#include "../../src/skiplist.hpp"
#include "../../src/slice.hpp"

#include <atomic>
#include <cstdint>
#include <string>

namespace bench {

class MinilsmWrapper {
 public:
  static constexpr bool kThreadSafe = true;
  static constexpr const char* kName = "minilsm";

  MinilsmWrapper() : arena_(), list_(&arena_), sequence_(0) {}

  void insert(const char* key, size_t key_len,
              const char* value, size_t value_len) {
    minilsm::InternalKey ikey(
        minilsm::Slice(key, key_len),
        sequence_.fetch_add(1, std::memory_order_relaxed),
        minilsm::KeyType::Put);
    list_.insert(ikey, minilsm::Slice(value, value_len));
  }

  bool get(const char* key, size_t key_len, std::string* value) {
    return list_.get(minilsm::Slice(key, key_len), value);
  }

  // Delete via tombstone (minilsm is append-only)
  void remove(const char* key, size_t key_len) {
    minilsm::InternalKey ikey(
        minilsm::Slice(key, key_len),
        sequence_.fetch_add(1, std::memory_order_relaxed),
        minilsm::KeyType::Delete);
    list_.insert(ikey, minilsm::Slice());
  }

  // Update is just another insert with higher sequence
  void update(const char* key, size_t key_len,
              const char* value, size_t value_len) {
    insert(key, key_len, value, value_len);
  }

  size_t memory_usage() const {
    return arena_.memory_usage();
  }

  class Iterator {
   public:
    explicit Iterator(const MinilsmWrapper* wrapper)
        : iter_(&wrapper->list_) {}

    bool valid() const { return iter_.valid(); }

    void next() { iter_.next(); }

    void seek_to_first() { iter_.seek_to_first(); }

    const char* key_data() const {
      return iter_.key().user_key.data();
    }

    size_t key_size() const {
      return iter_.key().user_key.size();
    }

   private:
    minilsm::SkipList::Iterator iter_;
  };

  Iterator new_iterator() const {
    return Iterator(this);
  }

 private:
  minilsm::Arena arena_;
  minilsm::SkipList list_;
  std::atomic<uint64_t> sequence_;
};

}  // namespace bench
