// Concurrent Skiplist Fuzzer with ThreadSanitizer
//
// DESIGN NOTES:
// - Must be built with TSan, not ASan (incompatible)
// - Uses barrier to maximize concurrent access
// - Bounded thread count and operations for reproducibility
// - TSan will catch data races in lock-free code

#include "../src/skiplist.hpp"
#include "../src/arena.hpp"
#include <cstdint>
#include <cstddef>
#include <thread>
#include <vector>
#include <atomic>
#include <fuzzer/FuzzedDataProvider.h>

using namespace minilsm;

static constexpr size_t kMaxThreads = 8;
static constexpr size_t kMaxOpsPerThread = 50;
static constexpr size_t kMaxKeySize = 64;
static constexpr size_t kMaxValueSize = 128;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;

    FuzzedDataProvider provider(data, size);
    Arena arena;
    SkipList list(&arena);

    // Derive thread count from input (deterministic)
    size_t num_threads = provider.ConsumeIntegralInRange<size_t>(2, kMaxThreads);

    std::vector<std::thread> threads;
    std::atomic<bool> start{false};
    std::atomic<size_t> ready{0};

    for (size_t t = 0; t < num_threads; t++) {
        // Divide remaining input among threads
        size_t remaining = provider.remaining_bytes();
        size_t threads_left = num_threads - t;
        size_t chunk_size = remaining / threads_left;
        auto thread_data = provider.ConsumeBytes<uint8_t>(chunk_size);

        threads.emplace_back([&list, thread_data, &start, &ready]() {
            ready.fetch_add(1, std::memory_order_release);

            // Spin barrier: all threads start together for maximum contention
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            FuzzedDataProvider tp(thread_data.data(), thread_data.size());
            size_t ops = 0;

            while (tp.remaining_bytes() > 0 && ops++ < kMaxOpsPerThread) {
                uint8_t op = tp.ConsumeIntegral<uint8_t>() % 3;

                switch (op) {
                    case 0: { // Insert
                        auto key_data = tp.ConsumeRandomLengthString(kMaxKeySize);
                        auto value_data = tp.ConsumeRandomLengthString(kMaxValueSize);
                        uint64_t seq = tp.ConsumeIntegral<uint64_t>();

                        InternalKey key(Slice(key_data.data(), key_data.size()),
                                       seq, KeyType::Put);
                        list.insert(key, Slice(value_data.data(), value_data.size()));
                        break;
                    }
                    case 1: { // Get
                        auto key_data = tp.ConsumeRandomLengthString(kMaxKeySize);
                        std::string result;
                        list.get(Slice(key_data.data(), key_data.size()), &result);
                        break;
                    }
                    case 2: { // Iterate
                        SkipList::Iterator it(&list);
                        it.seek_to_first();
                        for (int i = 0; i < 10 && it.valid(); i++) {
                            (void)it.key();
                            (void)it.value();
                            it.next();
                        }
                        break;
                    }
                }
            }
        });
    }

    // Wait for all threads to be ready
    while (ready.load(std::memory_order_acquire) < num_threads) {
        std::this_thread::yield();
    }

    // Release all threads simultaneously
    start.store(true, std::memory_order_release);

    for (auto& t : threads) {
        t.join();
    }

    return 0;
}
