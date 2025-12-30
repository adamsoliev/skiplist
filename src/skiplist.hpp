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
        mutable std::atomic_flag insert_lock_ = ATOMIC_FLAG_INIT;

        void lock_insert()
        {
                while (insert_lock_.test_and_set(std::memory_order_acquire))
                        ;
        }

        void unlock_insert()
        {
                insert_lock_.clear(std::memory_order_release);
        }

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

                Node *get_next(int level)
                {
                        return next(level)->load(std::memory_order_acquire);
                }

                void set_next(int level, Node *n)
                {
                        next(level)->store(n, std::memory_order_release);
                }

                bool cas_next(int level, Node *expected, Node *desired)
                {
                        return next(level)->compare_exchange_strong(
                                expected, desired, std::memory_order_release, std::memory_order_acquire);
                }
        };

public:
        explicit SkipList(Arena *arena) : arena_(arena), head_(new_node(InternalKey(), Slice(), kMaxHeight)), max_height_(1)
        {
                for (int i = 0; i < kMaxHeight; i++) {
                        head_->set_next(i, nullptr);
                }
        }

        ~SkipList() = default;

        SkipList(const SkipList &) = delete;
        SkipList &operator=(const SkipList &) = delete;

        // Insert key-value (allows duplicate user keys with different sequences)
        // Uses spinlock for writes; reads remain lock-free
        void insert(const InternalKey &key, const Slice &value)
        {
                // Copy key and value data into arena (can be done outside lock)
                Slice stored_key_data;
                if (key.user_key.size() > 0) {
                        char *key_data = arena_->allocate(key.user_key.size());
                        std::memcpy(key_data, key.user_key.data(), key.user_key.size());
                        stored_key_data = Slice(key_data, key.user_key.size());
                }
                InternalKey stored_key(stored_key_data, key.sequence, key.type);

                Slice stored_value;
                if (value.size() > 0) {
                        char *val_data = arena_->allocate(value.size());
                        std::memcpy(val_data, value.data(), value.size());
                        stored_value = Slice(val_data, value.size());
                }

                int height = random_height();

                lock_insert();

                // Update max height if needed
                int current_max = max_height_.load(std::memory_order_relaxed);
                if (height > current_max) {
                        max_height_.store(height, std::memory_order_relaxed);
                }

                // Find insertion point
                Node *prev[kMaxHeight];
                find_greater_or_equal(stored_key, prev);

                // Fill in prev for new levels
                for (int i = current_max; i < height; i++) {
                        prev[i] = head_;
                }

                // Create and link node
                Node *x = new_node(stored_key, stored_value, height);
                for (int i = 0; i < height; i++) {
                        x->set_next(i, prev[i]->get_next(i));
                        prev[i]->set_next(i, x);
                }

                unlock_insert();
        }

        // Point lookup (returns newest version for user key)
        bool get(const Slice &user_key, std::string *value)
        {
                // Seek to first key >= (user_key, MAX_SEQUENCE)
                // This will find the newest version
                InternalKey lookup_key(user_key, kMaxSequenceNumber, KeyType::Put);
                Node *x = find_greater_or_equal(lookup_key, nullptr);

                if (x != nullptr && x->key.user_key == user_key) {
                        if (x->key.type == KeyType::Delete) {
                                return false; // tombstone
                        }
                        if (value != nullptr) {
                                *value = x->value.to_string();
                        }
                        return true;
                }
                return false;
        }

        class Iterator
        {
        public:
                explicit Iterator(const SkipList *list) : list_(list), node_(nullptr)
                {
                }

                bool valid() const
                {
                        return node_ != nullptr;
                }

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

                void seek_to_first()
                {
                        node_ = list_->head_->get_next(0);
                }

                void seek_to_last()
                {
                        node_ = list_->find_last();
                }

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
                while (height < kMaxHeight && (rng() % kBranchingFactor) == 0) {
                        height++;
                }
                return height;
        }

        // Find the first node >= key
        // If prev is non-null, fills in predecessor at each level
        Node *find_greater_or_equal(const InternalKey &key, Node *prev[]) const
        {
                Node *x = head_;
                int level = max_height_.load(std::memory_order_relaxed) - 1;

                while (true) {
                        Node *next = x->get_next(level);
                        if (next != nullptr && next->key.compare(key) < 0) {
                                // Keep searching at this level
                                x = next;
                        } else {
                                // Record predecessor and descend
                                if (prev != nullptr) {
                                        prev[level] = x;
                                }
                                if (level == 0) {
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

                while (true) {
                        Node *next = x->get_next(level);
                        if (next != nullptr && next->key.compare(key) < 0) {
                                x = next;
                        } else {
                                if (level == 0) {
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

                while (true) {
                        Node *next = x->get_next(level);
                        if (next != nullptr) {
                                x = next;
                        } else {
                                if (level == 0) {
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
