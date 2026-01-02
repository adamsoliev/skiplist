#pragma once

#include "arena.hpp"
#include "key.hpp"
#include "slice.hpp"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <random>
#include <string>

namespace minilsm
{

class SkipList
{
      public:
        static constexpr int kMaxHeight = 12;
        static constexpr int kBranchingFactor = 4;

      private:

        struct Node
        {
                uint32_t key_size;
                uint32_t value_size;
                uint64_t sequence;
                KeyType type;
                int height;

                // Key and value data stored immediately after Node
                const char *key_data() const { return reinterpret_cast<const char *>(this + 1); }
                char *key_data() { return reinterpret_cast<char *>(this + 1); }
                const char *value_data() const { return key_data() + key_size; }
                char *value_data() { return key_data() + key_size; }

                Slice user_key() const { return Slice(key_data(), key_size); }
                Slice value() const { return Slice(value_data(), value_size); }

                InternalKey get_key() const { return InternalKey(user_key(), sequence, type); }

                // Compare this node's key with an InternalKey
                int compare_key(const InternalKey &other) const
                {
                        int r = user_key().compare(other.user_key);
                        if (r != 0)
                                return r;
                        // Descending by sequence: higher sequence = smaller (comes first)
                        if (sequence > other.sequence)
                                return -1;
                        if (sequence < other.sequence)
                                return 1;
                        return 0;
                }

                // Next pointers are stored BEFORE this struct in memory
                // Access via next(level) method
                std::atomic<Node *> *next(int level)
                {
                        assert(level >= 0 && level < height);
                        // Pointers stored at negative offsets
                        return reinterpret_cast<std::atomic<Node *> *>(this) - (level + 1);
                }

                Node *get_next(int level) { return next(level)->load(std::memory_order_acquire); }

                void set_next(int level, Node *n) { next(level)->store(n, std::memory_order_release); }

                bool cas_next(int level, Node *expected, Node *desired)
                {
                        return next(level)->compare_exchange_strong(
                            expected, desired, std::memory_order_release, std::memory_order_acquire);
                }
        };

      public:
        explicit SkipList(Arena *arena)
            : arena_(arena), head_(new_node(InternalKey(), Slice(), kMaxHeight)), max_height_(1)
        {
                for (int i = 0; i < kMaxHeight; i++)
                {
                        head_->set_next(i, nullptr);
                }
        }

        ~SkipList() = default;

        SkipList(const SkipList &) = delete;
        SkipList &operator=(const SkipList &) = delete;

        // Insert key-value (allows duplicate user keys with different sequences)
        // Lock-free implementation using CAS
        void insert(const InternalKey &key, const Slice &value)
        {
                int height = random_height();

                // Update max height using CAS
                int current_max = max_height_.load(std::memory_order_relaxed);
                while (height > current_max)
                {
                        if (max_height_.compare_exchange_weak(current_max, height, std::memory_order_relaxed))
                        {
                                break;
                        }
                        // current_max is updated by compare_exchange_weak on failure
                }

                // Single allocation: [next pointers][Node][key data][value data]
                size_t key_size = key.user_key.size();
                size_t val_size = value.size();
                size_t alloc_size = sizeof(std::atomic<Node *>) * height + sizeof(Node) + key_size + val_size;
                char *mem = arena_->allocate_aligned(alloc_size, alignof(std::atomic<Node *>));

                // Layout pointers
                Node *x = reinterpret_cast<Node *>(mem + sizeof(std::atomic<Node *>) * height);

                // Initialize node with inline data
                x->key_size = static_cast<uint32_t>(key_size);
                x->value_size = static_cast<uint32_t>(val_size);
                x->sequence = key.sequence;
                x->type = key.type;
                x->height = height;

                // Copy key and value data inline (after Node)
                if (key_size > 0)
                {
                        std::memcpy(x->key_data(), key.user_key.data(), key_size);
                }
                if (val_size > 0)
                {
                        std::memcpy(x->value_data(), value.data(), val_size);
                }

                InternalKey stored_key = x->get_key();

                // Single traversal to cache all predecessors
                Node *prev[kMaxHeight];
                find_greater_or_equal(stored_key, prev);

                // Link node at each level using CAS, bottom-up
                for (int level = 0; level < height; level++)
                {
                        while (true)
                        {
                                Node *succ = prev[level]->get_next(level);

                                // Walk forward if predecessor is stale (another insert happened)
                                while (succ != nullptr && succ->compare_key(stored_key) < 0)
                                {
                                        prev[level] = succ;
                                        succ = succ->get_next(level);
                                }

                                // Set our next pointer
                                x->set_next(level, succ);

                                // Try to link
                                if (prev[level]->cas_next(level, succ, x))
                                {
                                        break; // Success, move to next level
                                }
                                // CAS failed - walk forward from current position to find new predecessor
                                succ = prev[level]->get_next(level);
                                while (succ != nullptr && succ->compare_key(stored_key) < 0)
                                {
                                        prev[level] = succ;
                                        succ = succ->get_next(level);
                                }
                        }
                }
        }

        // Point lookup (returns newest version for user key)
        bool get(const Slice &user_key, std::string *value)
        {
                // Seek to first key >= (user_key, MAX_SEQUENCE)
                // This will find the newest version
                InternalKey lookup_key(user_key, kMaxSequenceNumber, KeyType::Put);
                Node *x = find_greater_or_equal(lookup_key, nullptr);

                if (x != nullptr && x->user_key() == user_key)
                {
                        if (x->type == KeyType::Delete)
                        {
                                return false; // tombstone
                        }
                        if (value != nullptr)
                        {
                                *value = x->value().to_string();
                        }
                        return true;
                }
                return false;
        }

        class Iterator
        {
              public:
                explicit Iterator(const SkipList *list) : list_(list), node_(nullptr) {}

                bool valid() const { return node_ != nullptr; }

                InternalKey key() const
                {
                        assert(valid());
                        return node_->get_key();
                }

                Slice value() const
                {
                        assert(valid());
                        return node_->value();
                }

                void next()
                {
                        assert(valid());
                        node_ = node_->get_next(0);
                }

                void prev()
                {
                        assert(valid());
                        node_ = list_->find_less_than(node_->get_key());
                }

                void seek(const Slice &target)
                {
                        InternalKey lookup_key(target, kMaxSequenceNumber, KeyType::Put);
                        node_ = list_->find_greater_or_equal(lookup_key, nullptr);
                }

                void seek_to_first() { node_ = list_->head_->get_next(0); }

                void seek_to_last() { node_ = list_->find_last(); }

              private:
                const SkipList *list_;
                Node *node_;
        };

      private:
        Node *new_node(const InternalKey &key, const Slice &value, int height)
        {
                // Memory layout: [next pointers][Node][key data][value data]
                size_t key_size = key.user_key.size();
                size_t val_size = value.size();
                size_t alloc_size = sizeof(std::atomic<Node *>) * height + sizeof(Node) + key_size + val_size;
                char *mem = arena_->allocate_aligned(alloc_size, alignof(std::atomic<Node *>));

                // Node pointer is at the end of next pointers
                Node *node = reinterpret_cast<Node *>(mem + sizeof(std::atomic<Node *>) * height);
                node->key_size = static_cast<uint32_t>(key_size);
                node->value_size = static_cast<uint32_t>(val_size);
                node->sequence = key.sequence;
                node->type = key.type;
                node->height = height;

                // Copy key and value data inline
                if (key_size > 0)
                {
                        std::memcpy(node->key_data(), key.user_key.data(), key_size);
                }
                if (val_size > 0)
                {
                        std::memcpy(node->value_data(), value.data(), val_size);
                }

                return node;
        }

        int random_height()
        {
                static thread_local std::mt19937 rng(std::random_device{}());
                int height = 1;
                while (height < kMaxHeight && (rng() % kBranchingFactor) == 0)
                {
                        height++;
                }
                return height;
        }

        // Find predecessor of key at a specific level (for lock-free insert)
        Node *find_predecessor_at_level(const InternalKey &key, int target_level) const
        {
                Node *x = head_;
                int level = max_height_.load(std::memory_order_relaxed) - 1;

                while (true)
                {
                        Node *next = x->get_next(level);
                        if (next != nullptr && next->compare_key(key) < 0)
                        {
                                x = next;
                        }
                        else
                        {
                                if (level == target_level)
                                {
                                        return x;
                                }
                                level--;
                        }
                }
        }

        // Find the first node >= key
        // If prev is non-null, fills in predecessor at each level
        Node *find_greater_or_equal(const InternalKey &key, Node *prev[]) const
        {
                Node *x = head_;
                int level = max_height_.load(std::memory_order_relaxed) - 1;

                while (true)
                {
                        Node *next = x->get_next(level);
                        if (next != nullptr && next->compare_key(key) < 0)
                        {
                                // Keep searching at this level
                                x = next;
                        }
                        else
                        {
                                // Record predecessor and descend
                                if (prev != nullptr)
                                {
                                        prev[level] = x;
                                }
                                if (level == 0)
                                {
                                        return next;
                                }
                                level--;
                        }
                }
        }

        // Find the last node < key, or nullptr if no such node
        Node *find_less_than(const InternalKey &key) const
        {
                Node *x = head_;
                int level = max_height_.load(std::memory_order_relaxed) - 1;

                while (true)
                {
                        Node *next = x->get_next(level);
                        if (next != nullptr && next->compare_key(key) < 0)
                        {
                                x = next;
                        }
                        else
                        {
                                if (level == 0)
                                {
                                        return (x == head_) ? nullptr : x;
                                }
                                level--;
                        }
                }
        }

        // Find the last node in the list
        Node *find_last() const
        {
                Node *x = head_;
                int level = max_height_.load(std::memory_order_relaxed) - 1;

                while (true)
                {
                        Node *next = x->get_next(level);
                        if (next != nullptr)
                        {
                                x = next;
                        }
                        else
                        {
                                if (level == 0)
                                {
                                        return (x == head_) ? nullptr : x;
                                }
                                level--;
                        }
                }
        }

        Arena *arena_;
        Node *head_;
        std::atomic<int> max_height_;
};

} // namespace minilsm
