// Wrapper for Redis zskiplist to provide unified benchmark interface
#pragma once

extern "C"
{
#include "../../third_party/redis/zskiplist.h"
}

#include <cstdint>
#include <cstring>
#include <string>

namespace bench
{

class RedisWrapper
{
      public:
        static constexpr bool kThreadSafe = false; // Redis skiplist is NOT thread-safe
        static constexpr const char *kName = "redis";

        RedisWrapper() : zsl_(zslCreate()) {}

        ~RedisWrapper()
        {
                if (zsl_)
                {
                        zslFree(zsl_);
                }
        }

        // Non-copyable
        RedisWrapper(const RedisWrapper &) = delete;
        RedisWrapper &operator=(const RedisWrapper &) = delete;

        void insert(const char *key, size_t key_len, const char *value, size_t value_len)
        {
                // Redis zskiplist stores (score, element) pairs
                // We use key hash as score and store key+value concatenated as element
                // Format: [key][value]
                double score = hash_to_score(key, key_len);

                // For fair comparison with other skiplists that store both key and value,
                // we concatenate them. The element stores: [4-byte key_len][key][value]
                size_t total = 4 + key_len + value_len;
                char *buf = new char[total];
                uint32_t klen = static_cast<uint32_t>(key_len);
                memcpy(buf, &klen, 4);
                memcpy(buf + 4, key, key_len);
                if (value_len > 0)
                {
                        memcpy(buf + 4 + key_len, value, value_len);
                }

                zslInsert(zsl_, score, buf, total);
                delete[] buf;
        }

        bool get(const char *key, size_t key_len, std::string *value)
        {
                // Build lookup element
                size_t total = 4 + key_len;
                char buf[256];
                char *lookup = key_len < 252 ? buf : new char[total];

                uint32_t klen = static_cast<uint32_t>(key_len);
                memcpy(lookup, &klen, 4);
                memcpy(lookup + 4, key, key_len);

                double score = hash_to_score(key, key_len);

                // Find node - need to iterate since we can't do exact lookup easily
                zskiplistNode *node = zslFind(zsl_, score, lookup, total);

                if (lookup != buf)
                        delete[] lookup;

                if (node == nullptr)
                        return false;

                // Extract value from element
                if (value && node->ele)
                {
                        uint32_t stored_key_len;
                        memcpy(&stored_key_len, node->ele->data, 4);
                        size_t val_len = node->ele->len - 4 - stored_key_len;
                        if (val_len > 0)
                        {
                                value->assign(node->ele->data + 4 + stored_key_len, val_len);
                        }
                        else
                        {
                                value->clear();
                        }
                }
                return true;
        }

        void remove(const char *key, size_t key_len)
        {
                size_t total = 4 + key_len;
                char buf[256];
                char *lookup = key_len < 252 ? buf : new char[total];

                uint32_t klen = static_cast<uint32_t>(key_len);
                memcpy(lookup, &klen, 4);
                memcpy(lookup + 4, key, key_len);

                double score = hash_to_score(key, key_len);
                zslDelete(zsl_, score, lookup, total);

                if (lookup != buf)
                        delete[] lookup;
        }

        void update(const char *key, size_t key_len, const char *value, size_t value_len)
        {
                // Remove old and insert new
                remove(key, key_len);
                insert(key, key_len, value, value_len);
        }

        size_t memory_usage() const
        {
                // Approximate - Redis doesn't track this directly in our extraction
                return zsl_->length * 64; // Rough estimate
        }

        class Iterator
        {
              public:
                explicit Iterator(const RedisWrapper *wrapper) : zsl_(wrapper->zsl_), node_(nullptr) {}

                bool valid() const { return node_ != nullptr; }

                void next()
                {
                        if (node_)
                        {
                                node_ = node_->level[0].forward;
                        }
                }

                void seek_to_first() { node_ = zslFirstNode(zsl_); }

                const char *key_data() const
                {
                        if (!node_ || !node_->ele)
                                return nullptr;
                        return node_->ele->data + 4; // Skip key length prefix
                }

                size_t key_size() const
                {
                        if (!node_ || !node_->ele)
                                return 0;
                        uint32_t len;
                        memcpy(&len, node_->ele->data, sizeof(uint32_t));
                        return len;
                }

              private:
                zskiplist *zsl_;
                zskiplistNode *node_;
        };

        Iterator new_iterator() const { return Iterator(this); }

      private:
        // FNV-1a hash converted to double for score
        static double hash_to_score(const char *key, size_t len)
        {
                uint64_t h = 14695981039346656037ULL;
                for (size_t i = 0; i < len; i++)
                {
                        h ^= static_cast<uint8_t>(key[i]);
                        h *= 1099511628211ULL;
                }
                // Convert to double in a way that preserves ordering for same-hash keys
                return static_cast<double>(h);
        }

        zskiplist *zsl_;
};

} // namespace bench
