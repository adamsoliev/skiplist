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
                InternalKey key;
                Slice value;
                int height;

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
                // Copy key and value data into arena
                Slice stored_key_data;
                if (key.user_key.size() > 0)
                {
                        char *key_data = arena_->allocate(key.user_key.size());
                        std::memcpy(key_data, key.user_key.data(), key.user_key.size());
                        stored_key_data = Slice(key_data, key.user_key.size());
                }
                InternalKey stored_key(stored_key_data, key.sequence, key.type);

                Slice stored_value;
                if (value.size() > 0)
                {
                        char *val_data = arena_->allocate(value.size());
                        std::memcpy(val_data, value.data(), value.size());
                        stored_value = Slice(val_data, value.size());
                }

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

                // Create node
                Node *x = new_node(stored_key, stored_value, height);

                // Link node at each level using CAS, bottom-up
                for (int level = 0; level < height; level++)
                {
                        while (true)
                        {
                                // Find predecessor at this level
                                Node *pred = find_predecessor_at_level(stored_key, level);
                                Node *succ = pred->get_next(level);

                                // Validate that succ is actually >= our key (or null)
                                // If succ < our key, another thread inserted and we need to re-search
                                if (succ != nullptr && succ->key.compare(stored_key) < 0)
                                {
                                        continue; // Re-search for correct predecessor
                                }

                                // Set our next pointer
                                x->set_next(level, succ);

                                // Try to link
                                if (pred->cas_next(level, succ, x))
                                {
                                        break; // Success, move to next level
                                }
                                // CAS failed, retry - another thread modified pred->next
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

                if (x != nullptr && x->key.user_key == user_key)
                {
                        if (x->key.type == KeyType::Delete)
                        {
                                return false; // tombstone
                        }
                        if (value != nullptr)
                        {
                                *value = x->value.to_string();
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

                const InternalKey &key() const
                {
                        assert(valid());
                        return node_->key;
                }

                Slice value() const
                {
                        assert(valid());
                        return node_->value;
                }

                void next()
                {
                        assert(valid());
                        node_ = node_->get_next(0);
                }

                void prev()
                {
                        assert(valid());
                        node_ = list_->find_less_than(node_->key);
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
                // Memory layout: [next[height-1]] ... [next[0]] [Node]
                size_t alloc_size = sizeof(std::atomic<Node *>) * height + sizeof(Node);
                char *mem = arena_->allocate_aligned(alloc_size, alignof(std::atomic<Node *>));

                // Node pointer is at the end
                Node *node = reinterpret_cast<Node *>(mem + sizeof(std::atomic<Node *>) * height);
                new (node) Node();
                node->key = key;
                node->value = value;
                node->height = height;

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
                        if (next != nullptr && next->key.compare(key) < 0)
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
                        if (next != nullptr && next->key.compare(key) < 0)
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
                        if (next != nullptr && next->key.compare(key) < 0)
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
