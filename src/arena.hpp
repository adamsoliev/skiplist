#pragma once

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <thread>
#include <vector>

#ifdef __linux__
#include <sched.h>
#endif

namespace minilsm
{

class Arena
{
      public:
        static constexpr size_t kChunkSize = 128 * 1024;      // 128KB chunks
        static constexpr size_t kLargeThreshold = 128 * 1024; // Bypass shards for large allocs
        static constexpr size_t kCacheLineSize = 64;          // Cache line padding
        static constexpr int kRepickThreshold = 64;           // Spin count before repick
        static constexpr int kCentralSpinLimit = 100;         // Spins before yield in central lock

        explicit Arena(size_t max_bytes = 0, size_t num_shards = 0) : max_bytes_(max_bytes), memory_usage_(0)
        {
                // Default shard count: hardware_concurrency() - 2, minimum 1
                if (num_shards == 0)
                {
                        unsigned hw = std::thread::hardware_concurrency();
                        num_shards_ = (hw > 2) ? (hw - 2) : 1;
                }
                else
                {
                        num_shards_ = num_shards;
                }

                // Allocate shards array (cache-line aligned)
                shards_ = static_cast<Shard *>(aligned_alloc(kCacheLineSize, num_shards_ * sizeof(Shard)));
                for (size_t i = 0; i < num_shards_; i++)
                {
                        new (&shards_[i]) Shard();
                }
        }

        ~Arena()
        {
                // Free all allocated blocks
                for (void *block : blocks_)
                {
                        free(block);
                }

                if (shards_)
                {
                        for (size_t i = 0; i < num_shards_; i++)
                        {
                                shards_[i].~Shard();
                        }
                        free(shards_);
                }
        }

        Arena(const Arena &) = delete;
        Arena &operator=(const Arena &) = delete;

        // Thread-safe allocation
        char *allocate(size_t bytes)
        {
                if (bytes == 0)
                {
                        return nullptr;
                }

                // Large allocations bypass shards
                if (bytes > kLargeThreshold)
                {
                        return central_allocate(bytes);
                }

                return shard_allocate(bytes);
        }

        // Thread-safe aligned allocation
        char *allocate_aligned(size_t bytes, size_t align)
        {
                assert((align & (align - 1)) == 0); // power of 2

                if (bytes == 0)
                {
                        return nullptr;
                }

                // Large allocations bypass shards (get fresh aligned memory)
                if (bytes > kLargeThreshold)
                {
                        return central_allocate_aligned(bytes, align);
                }

                return shard_allocate_aligned(bytes, align);
        }

        size_t memory_usage() const { return memory_usage_.load(std::memory_order_relaxed); }

      private:
        // Cache-line aligned shard structure
        struct alignas(64) Shard
        {
                std::atomic_flag lock = ATOMIC_FLAG_INIT;
                char *block_ptr = nullptr;
                size_t block_remaining = 0;
                // Padding to 64 bytes is implicit from alignas(64)
        };

        // Simple TAS spinlock for shards
        bool try_lock_shard(Shard &shard) { return !shard.lock.test_and_set(std::memory_order_acquire); }

        void unlock_shard(Shard &shard) { shard.lock.clear(std::memory_order_release); }

        // Yielding spinlock for central arena
        void lock_central()
        {
                int spin_count = 0;
                while (central_lock_.test_and_set(std::memory_order_acquire))
                {
                        spin_count++;
                        if (spin_count >= kCentralSpinLimit)
                        {
                                sched_yield();
                                spin_count = 0;
                        }
                }
        }

        void unlock_central() { central_lock_.clear(std::memory_order_release); }

        // Get current CPU core ID (cached per thread)
        size_t get_shard_index()
        {
                thread_local size_t cached_shard = compute_shard_index();
                return cached_shard;
        }

        size_t compute_shard_index()
        {
#ifdef __linux__
                int cpu = sched_getcpu();
                if (cpu >= 0)
                {
                        return static_cast<size_t>(cpu) % num_shards_;
                }
#endif
                // Fallback: hash thread ID
                return std::hash<std::thread::id>{}(std::this_thread::get_id()) % num_shards_;
        }

        // Repick shard (refresh core ID)
        size_t repick_shard()
        {
                size_t new_shard = compute_shard_index();
                return new_shard;
        }

        // Allocate from a shard
        char *shard_allocate(size_t bytes)
        {
                size_t shard_idx = get_shard_index();
                int spin_count = 0;

                while (true)
                {
                        Shard &shard = shards_[shard_idx];

                        if (try_lock_shard(shard))
                        {
                                char *result = shard_allocate_locked(shard, bytes);
                                unlock_shard(shard);
                                return result;
                        }

                        spin_count++;
                        if (spin_count >= kRepickThreshold)
                        {
                                shard_idx = repick_shard();
                                spin_count = 0;
                        }
                }
        }

        // Allocate aligned from a shard
        char *shard_allocate_aligned(size_t bytes, size_t align)
        {
                size_t shard_idx = get_shard_index();
                int spin_count = 0;

                while (true)
                {
                        Shard &shard = shards_[shard_idx];

                        if (try_lock_shard(shard))
                        {
                                char *result = shard_allocate_aligned_locked(shard, bytes, align);
                                unlock_shard(shard);
                                return result;
                        }

                        spin_count++;
                        if (spin_count >= kRepickThreshold)
                        {
                                shard_idx = repick_shard();
                                spin_count = 0;
                        }
                }
        }

        // Must be called with shard lock held
        char *shard_allocate_locked(Shard &shard, size_t bytes)
        {
                if (shard.block_remaining >= bytes)
                {
                        char *result = shard.block_ptr;
                        shard.block_ptr += bytes;
                        shard.block_remaining -= bytes;
                        return result;
                }

                // Need new chunk from central
                char *new_block = central_allocate_chunk();
                if (new_block == nullptr)
                {
                        return nullptr;
                }

                shard.block_ptr = new_block;
                shard.block_remaining = kChunkSize;

                // Now allocate from the fresh chunk
                char *result = shard.block_ptr;
                shard.block_ptr += bytes;
                shard.block_remaining -= bytes;
                return result;
        }

        // Must be called with shard lock held
        char *shard_allocate_aligned_locked(Shard &shard, size_t bytes, size_t align)
        {
                // Calculate alignment adjustment
                size_t current_mod = reinterpret_cast<uintptr_t>(shard.block_ptr) & (align - 1);
                size_t slop = (current_mod == 0) ? 0 : (align - current_mod);

                if (slop + bytes <= shard.block_remaining)
                {
                        shard.block_ptr += slop;
                        shard.block_remaining -= slop;

                        char *result = shard.block_ptr;
                        shard.block_ptr += bytes;
                        shard.block_remaining -= bytes;
                        return result;
                }

                // Need new chunk from central (fresh allocation is aligned)
                char *new_block = central_allocate_chunk();
                if (new_block == nullptr)
                {
                        return nullptr;
                }

                shard.block_ptr = new_block;
                shard.block_remaining = kChunkSize;

                // Fresh chunk from aligned_alloc should be aligned, but recalculate just in case
                current_mod = reinterpret_cast<uintptr_t>(shard.block_ptr) & (align - 1);
                slop = (current_mod == 0) ? 0 : (align - current_mod);

                shard.block_ptr += slop;
                shard.block_remaining -= slop;

                char *result = shard.block_ptr;
                shard.block_ptr += bytes;
                shard.block_remaining -= bytes;
                return result;
        }

        // Allocate a chunk for a shard (called with shard lock held, acquires central lock)
        char *central_allocate_chunk()
        {
                lock_central();

                // Check memory limit
                if (max_bytes_ > 0)
                {
                        size_t current = memory_usage_.load(std::memory_order_relaxed);
                        if (current + kChunkSize > max_bytes_)
                        {
                                unlock_central();
                                return nullptr;
                        }
                }

                // Allocate aligned chunk
                void *mem = aligned_alloc(kCacheLineSize, kChunkSize);
                if (mem == nullptr)
                {
                        unlock_central();
                        return nullptr;
                }

                blocks_.push_back(mem);
                memory_usage_.fetch_add(kChunkSize, std::memory_order_relaxed);

                unlock_central();
                return static_cast<char *>(mem);
        }

        // Direct allocation from central (for large allocations)
        char *central_allocate(size_t bytes)
        {
                lock_central();

                // Check memory limit
                if (max_bytes_ > 0)
                {
                        size_t current = memory_usage_.load(std::memory_order_relaxed);
                        if (current + bytes > max_bytes_)
                        {
                                unlock_central();
                                return nullptr;
                        }
                }

                // Allocate
                void *mem = malloc(bytes);
                if (mem == nullptr)
                {
                        unlock_central();
                        return nullptr;
                }

                blocks_.push_back(mem);
                memory_usage_.fetch_add(bytes, std::memory_order_relaxed);

                unlock_central();
                return static_cast<char *>(mem);
        }

        // Direct aligned allocation from central (for large allocations)
        char *central_allocate_aligned(size_t bytes, size_t align)
        {
                lock_central();

                // Check memory limit
                if (max_bytes_ > 0)
                {
                        size_t current = memory_usage_.load(std::memory_order_relaxed);
                        if (current + bytes > max_bytes_)
                        {
                                unlock_central();
                                return nullptr;
                        }
                }

                // Allocate aligned
                void *mem = aligned_alloc(align, bytes);
                if (mem == nullptr)
                {
                        unlock_central();
                        return nullptr;
                }

                blocks_.push_back(mem);
                memory_usage_.fetch_add(bytes, std::memory_order_relaxed);

                unlock_central();
                return static_cast<char *>(mem);
        }

        size_t max_bytes_;
        size_t num_shards_;
        Shard *shards_;
        std::atomic_flag central_lock_ = ATOMIC_FLAG_INIT;
        std::atomic<size_t> memory_usage_;
        std::vector<void *> blocks_; // Owned memory blocks (freed in destructor)
};

} // namespace minilsm
