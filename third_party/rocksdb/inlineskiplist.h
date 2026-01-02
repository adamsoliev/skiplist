// Simplified InlineSkipList based on RocksDB's implementation
// Original: Copyright (c) 2011-present, Facebook, Inc. (GPLv2 + Apache 2.0)
// This is a minimal extraction for benchmarking purposes.

#pragma once

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <random>
#include <vector>

namespace rocksdb {

// Minimal Allocator interface matching RocksDB
class Allocator {
 public:
  virtual ~Allocator() = default;
  virtual char* Allocate(size_t bytes) = 0;
  virtual char* AllocateAligned(size_t bytes, size_t alignment = 8) = 0;
  virtual size_t BlockSize() const = 0;
};

// Simple thread-safe arena allocator for the benchmark
class SimpleArena : public Allocator {
 public:
  SimpleArena() : alloc_bytes_(0) {}
  ~SimpleArena() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (char* block : blocks_) {
      delete[] block;
    }
  }

  char* Allocate(size_t bytes) override {
    char* result = new char[bytes];
    {
      std::lock_guard<std::mutex> lock(mutex_);
      blocks_.push_back(result);
      alloc_bytes_ += bytes;
    }
    return result;
  }

  char* AllocateAligned(size_t bytes, size_t alignment = 8) override {
    size_t alloc_size = bytes + alignment - 1;
    char* result = new char[alloc_size];
    {
      std::lock_guard<std::mutex> lock(mutex_);
      blocks_.push_back(result);
      alloc_bytes_ += alloc_size;
    }
    // Align the pointer
    uintptr_t addr = reinterpret_cast<uintptr_t>(result);
    uintptr_t aligned = (addr + alignment - 1) & ~(alignment - 1);
    return reinterpret_cast<char*>(aligned);
  }

  size_t BlockSize() const override { return 128 * 1024; }
  size_t MemoryUsage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return alloc_bytes_;
  }

 private:
  mutable std::mutex mutex_;
  std::vector<char*> blocks_;
  size_t alloc_bytes_;
};

template <class Comparator>
class InlineSkipList {
 private:
  struct Node;

 public:
  static const uint16_t kMaxPossibleHeight = 32;

  explicit InlineSkipList(Comparator cmp, Allocator* allocator,
                          int32_t max_height = 12,
                          int32_t branching_factor = 4)
      : kMaxHeight_(static_cast<uint16_t>(max_height)),
        kBranching_(static_cast<uint16_t>(branching_factor)),
        kScaledInverseBranching_((1u << 30) / branching_factor),
        allocator_(allocator),
        compare_(cmp),
        head_(AllocateNode(0, max_height)),
        max_height_(1),
        rnd_(0xdeadbeef) {
    for (int i = 0; i < max_height; ++i) {
      head_->SetNext(i, nullptr);
    }
  }

  InlineSkipList(const InlineSkipList&) = delete;
  InlineSkipList& operator=(const InlineSkipList&) = delete;

  // Allocate key storage
  char* AllocateKey(size_t key_size) {
    int height = RandomHeight();
    size_t prefix = sizeof(std::atomic<Node*>) * (height - 1);
    char* raw = allocator_->AllocateAligned(prefix + sizeof(Node) + key_size);
    Node* node = reinterpret_cast<Node*>(raw + prefix);
    node->StashHeight(height);
    return const_cast<char*>(node->Key());
  }

  // Insert (not thread-safe)
  bool Insert(const char* key) {
    Node* prev[kMaxPossibleHeight];
    Node* x = FindGreaterOrEqual(key, prev);

    int height = GetNodeHeight(key);
    int max_height = max_height_.load(std::memory_order_relaxed);
    if (height > max_height) {
      for (int i = max_height; i < height; ++i) {
        prev[i] = head_;
      }
      max_height_.store(height, std::memory_order_relaxed);
    }

    x = GetNodeFromKey(key);
    for (int i = 0; i < height; ++i) {
      x->NoBarrier_SetNext(i, prev[i]->NoBarrier_Next(i));
      prev[i]->SetNext(i, x);
    }
    return true;
  }

  // Thread-safe concurrent insert
  bool InsertConcurrently(const char* key) {
    Node* prev[kMaxPossibleHeight];
    Node* next[kMaxPossibleHeight];

    int height = GetNodeHeight(key);
    int max_height = max_height_.load(std::memory_order_relaxed);

    while (height > max_height) {
      if (max_height_.compare_exchange_weak(max_height, height,
                                            std::memory_order_relaxed)) {
        max_height = height;
        break;
      }
    }

    // Find insertion point
    Node* x = head_;
    int level = GetMaxHeight() - 1;
    while (true) {
      Node* next_node = x->Next(level);
      if (next_node != nullptr && compare_(next_node->Key(), key) < 0) {
        x = next_node;
      } else {
        prev[level] = x;
        next[level] = next_node;
        if (level == 0) break;
        --level;
      }
    }

    // Fill in higher levels
    for (int i = 1; i < height; ++i) {
      while (true) {
        if (prev[i] == nullptr) {
          prev[i] = head_;
          next[i] = nullptr;
        }
        Node* next_node = prev[i]->Next(i);
        if (next_node != nullptr && compare_(next_node->Key(), key) < 0) {
          prev[i] = next_node;
          next[i] = next_node->Next(i);
        } else {
          next[i] = next_node;
          break;
        }
      }
    }

    Node* node = GetNodeFromKey(key);

    // Insert at each level using CAS
    for (int i = 0; i < height; ++i) {
      while (true) {
        node->NoBarrier_SetNext(i, next[i]);
        if (prev[i]->CASNext(i, next[i], node)) {
          break;
        }
        // CAS failed, find new insertion point at this level
        Node* p = prev[i];
        while (true) {
          Node* n = p->Next(i);
          if (n == nullptr || compare_(n->Key(), key) >= 0) {
            prev[i] = p;
            next[i] = n;
            break;
          }
          p = n;
        }
      }
    }
    return true;
  }

  bool Contains(const char* key) const {
    Node* x = head_;
    int level = GetMaxHeight() - 1;
    while (true) {
      Node* next = x->Next(level);
      if (next != nullptr) {
        int cmp = compare_(next->Key(), key);
        if (cmp < 0) {
          x = next;
          continue;
        } else if (cmp == 0) {
          return true;
        }
      }
      if (level == 0) {
        return false;
      }
      --level;
    }
  }

  class Iterator {
   public:
    explicit Iterator(const InlineSkipList* list) : list_(list), node_(nullptr) {}

    bool Valid() const { return node_ != nullptr; }
    const char* key() const { return node_->Key(); }

    void Next() {
      assert(Valid());
      node_ = node_->Next(0);
    }

    void Prev() {
      assert(Valid());
      node_ = list_->FindLessThan(node_->Key());
      if (node_ == list_->head_) {
        node_ = nullptr;
      }
    }

    void Seek(const char* target) {
      node_ = list_->head_;
      int level = list_->GetMaxHeight() - 1;
      while (true) {
        Node* next = node_->Next(level);
        if (next != nullptr && list_->compare_(next->Key(), target) < 0) {
          node_ = next;
        } else {
          if (level == 0) {
            node_ = next;
            break;
          }
          --level;
        }
      }
    }

    void SeekToFirst() {
      node_ = list_->head_->Next(0);
    }

    void SeekToLast() {
      node_ = list_->FindLast();
      if (node_ == list_->head_) {
        node_ = nullptr;
      }
    }

   private:
    const InlineSkipList* list_;
    Node* node_;
  };

 private:
  const uint16_t kMaxHeight_;
  const uint16_t kBranching_;
  const uint32_t kScaledInverseBranching_;

  Allocator* const allocator_;
  Comparator const compare_;
  Node* const head_;

  std::atomic<int> max_height_;
  std::mt19937 rnd_;
  std::mutex rnd_mutex_;

  int GetMaxHeight() const {
    return max_height_.load(std::memory_order_relaxed);
  }

  int RandomHeight() {
    std::lock_guard<std::mutex> lock(rnd_mutex_);
    int height = 1;
    while (height < kMaxHeight_ && (rnd_() % kBranching_) == 0) {
      height++;
    }
    return height;
  }

  Node* AllocateNode(size_t key_size, int height) {
    size_t prefix = sizeof(std::atomic<Node*>) * (height - 1);
    char* raw = allocator_->AllocateAligned(prefix + sizeof(Node) + key_size);
    return reinterpret_cast<Node*>(raw + prefix);
  }

  int GetNodeHeight(const char* key) const {
    return GetNodeFromKey(key)->UnstashHeight();
  }

  Node* GetNodeFromKey(const char* key) const {
    return reinterpret_cast<Node*>(const_cast<char*>(key) - sizeof(Node));
  }

  Node* FindGreaterOrEqual(const char* key, Node** prev) const {
    Node* x = head_;
    int level = GetMaxHeight() - 1;
    while (true) {
      Node* next = x->Next(level);
      if (next != nullptr && compare_(next->Key(), key) < 0) {
        x = next;
      } else {
        if (prev != nullptr) prev[level] = x;
        if (level == 0) {
          return next;
        }
        --level;
      }
    }
  }

  Node* FindLessThan(const char* key) const {
    Node* x = head_;
    int level = GetMaxHeight() - 1;
    while (true) {
      Node* next = x->Next(level);
      if (next != nullptr && compare_(next->Key(), key) < 0) {
        x = next;
      } else {
        if (level == 0) {
          return x;
        }
        --level;
      }
    }
  }

  Node* FindLast() const {
    Node* x = head_;
    int level = GetMaxHeight() - 1;
    while (true) {
      Node* next = x->Next(level);
      if (next != nullptr) {
        x = next;
      } else {
        if (level == 0) {
          return x;
        }
        --level;
      }
    }
  }
};

template <class Comparator>
struct InlineSkipList<Comparator>::Node {
  void StashHeight(int height) {
    memcpy(static_cast<void*>(&next_[0]), &height, sizeof(int));
  }

  int UnstashHeight() const {
    int rv;
    memcpy(&rv, &next_[0], sizeof(int));
    return rv;
  }

  const char* Key() const {
    return reinterpret_cast<const char*>(&next_[1]);
  }

  Node* Next(int n) {
    return (&next_[0] - n)->load(std::memory_order_acquire);
  }

  void SetNext(int n, Node* x) {
    (&next_[0] - n)->store(x, std::memory_order_release);
  }

  bool CASNext(int n, Node* expected, Node* x) {
    return (&next_[0] - n)->compare_exchange_strong(
        expected, x, std::memory_order_acq_rel, std::memory_order_acquire);
  }

  Node* NoBarrier_Next(int n) {
    return (&next_[0] - n)->load(std::memory_order_relaxed);
  }

  void NoBarrier_SetNext(int n, Node* x) {
    (&next_[0] - n)->store(x, std::memory_order_relaxed);
  }

 private:
  std::atomic<Node*> next_[1];
};

}  // namespace rocksdb
