// Common utilities for skiplist benchmarks
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <random>
#include <string>
#include <vector>

namespace bench
{

// Key/value size configuration
struct DataProfile
{
        size_t min_key_size = 8;
        size_t max_key_size = 64;
        size_t min_value_size = 100;
        size_t max_value_size = 4096;
};

// Pre-generated test data for consistent benchmarks
class TestData
{
      public:
        TestData(size_t count, const DataProfile &profile, uint64_t seed = 42) : rng_(seed), count_(count)
        {
                keys_.reserve(count);
                values_.reserve(count);

                std::uniform_int_distribution<size_t> key_dist(profile.min_key_size, profile.max_key_size);
                std::uniform_int_distribution<size_t> val_dist(profile.min_value_size, profile.max_value_size);

                for (size_t i = 0; i < count; ++i)
                {
                        keys_.push_back(make_random_string(key_dist(rng_)));
                        values_.push_back(make_random_string(val_dist(rng_)));
                }
        }

        const std::string &key(size_t i) const { return keys_[i % count_]; }
        const std::string &value(size_t i) const { return values_[i % count_]; }
        size_t count() const { return count_; }

        // Get shuffled indices for random access patterns
        std::vector<size_t> shuffled_indices(uint64_t seed = 12345) const
        {
                std::vector<size_t> indices(count_);
                for (size_t i = 0; i < count_; ++i)
                {
                        indices[i] = i;
                }
                std::mt19937_64 rng(seed);
                for (size_t i = count_ - 1; i > 0; --i)
                {
                        std::uniform_int_distribution<size_t> dist(0, i);
                        std::swap(indices[i], indices[dist(rng)]);
                }
                return indices;
        }

      private:
        std::string make_random_string(size_t len)
        {
                static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
                std::string s(len, '\0');
                for (size_t i = 0; i < len; ++i)
                {
                        s[i] = charset[rng_() % (sizeof(charset) - 1)];
                }
                return s;
        }

        std::mt19937_64 rng_;
        size_t count_;
        std::vector<std::string> keys_;
        std::vector<std::string> values_;
};

// Thread synchronization barrier
class Barrier
{
      public:
        explicit Barrier(int count) : count_(count), waiting_(0), generation_(0) {}

        void wait()
        {
                std::unique_lock<std::mutex> lock(mutex_);
                int gen = generation_;
                if (++waiting_ == count_)
                {
                        generation_++;
                        waiting_ = 0;
                        cv_.notify_all();
                }
                else
                {
                        cv_.wait(lock, [this, gen] { return gen != generation_; });
                }
        }

      private:
        std::mutex mutex_;
        std::condition_variable cv_;
        int count_;
        int waiting_;
        int generation_;
};

// Simple throughput counter
class ThroughputCounter
{
      public:
        ThroughputCounter() : count_(0) {}

        void increment(size_t n = 1) { count_.fetch_add(n, std::memory_order_relaxed); }

        size_t get() const { return count_.load(std::memory_order_relaxed); }

        void reset() { count_.store(0, std::memory_order_relaxed); }

      private:
        std::atomic<size_t> count_;
};

} // namespace bench
