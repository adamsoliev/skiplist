#pragma once

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace minilsm
{

class Arena
{
      public:
        static constexpr size_t kBlockSize = 4096;

        Arena() : alloc_ptr_(nullptr), alloc_bytes_remaining_(0), memory_usage_(0) {}

        ~Arena() = default;

        Arena(const Arena &) = delete;
        Arena &operator=(const Arena &) = delete;

        // Thread-safe allocation
        char *allocate(size_t bytes)
        {
                if (bytes == 0)
                {
                        return nullptr;
                }

                std::lock_guard<std::mutex> lock(mutex_);
                return allocate_internal(bytes);
        }

        // Thread-safe aligned allocation
        char *allocate_aligned(size_t bytes, size_t align)
        {
                assert((align & (align - 1)) == 0); // power of 2

                if (bytes == 0)
                {
                        return nullptr;
                }

                std::lock_guard<std::mutex> lock(mutex_);

                size_t current_mod = reinterpret_cast<uintptr_t>(alloc_ptr_) & (align - 1);
                size_t slop = (current_mod == 0) ? 0 : (align - current_mod);

                if (slop + bytes <= alloc_bytes_remaining_)
                {
                        alloc_ptr_ += slop;
                        alloc_bytes_remaining_ -= slop;
                        return allocate_internal(bytes);
                }

                // Need new block - allocate fresh (will be aligned)
                return allocate_new_block_internal(bytes);
        }

        size_t memory_usage() const { return memory_usage_.load(std::memory_order_relaxed); }

      private:
        // Must be called with mutex held
        char *allocate_internal(size_t bytes)
        {
                if (bytes <= alloc_bytes_remaining_)
                {
                        char *result = alloc_ptr_;
                        alloc_ptr_ += bytes;
                        alloc_bytes_remaining_ -= bytes;
                        return result;
                }
                return allocate_slow_internal(bytes);
        }

        // Must be called with mutex held
        char *allocate_slow_internal(size_t bytes)
        {
                // Large allocation: give it its own block
                if (bytes > kBlockSize / 4)
                {
                        return allocate_new_block_internal(bytes);
                }

                // Allocate a new standard block
                alloc_ptr_ = allocate_new_block_internal(kBlockSize);
                alloc_bytes_remaining_ = kBlockSize - bytes;
                char *result = alloc_ptr_;
                alloc_ptr_ += bytes;
                return result;
        }

        // Must be called with mutex held
        char *allocate_new_block_internal(size_t block_bytes)
        {
                auto block = std::make_unique<char[]>(block_bytes);
                char *result = block.get();
                blocks_.push_back(std::move(block));
                memory_usage_.fetch_add(block_bytes, std::memory_order_relaxed);
                return result;
        }

        std::mutex mutex_;
        char *alloc_ptr_;
        size_t alloc_bytes_remaining_;
        std::atomic<size_t> memory_usage_;
        std::vector<std::unique_ptr<char[]>> blocks_;
};

} // namespace minilsm
