#include "skiplist.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

int main()
{
        constexpr size_t NUM_KEYS = 100'000'000;  // 100 million keys
        constexpr size_t NUM_THREADS = 12;
        constexpr size_t KEY_SIZE = 16;
        constexpr size_t VALUE_SIZE = 100;

        std::cout << "SkipList Multi-threaded Stress Test\n";
        std::cout << "====================================\n";
        std::cout << "Keys to insert: " << NUM_KEYS << "\n";
        std::cout << "Threads: " << NUM_THREADS << "\n";
        std::cout << "Key size: " << KEY_SIZE << " bytes\n";
        std::cout << "Value size: " << VALUE_SIZE << " bytes\n\n";

        minilsm::Arena arena;
        minilsm::SkipList skiplist(&arena);

        std::atomic<size_t> total_inserted{0};
        std::atomic<bool> done{false};

        // Progress reporter thread
        std::thread reporter([&]() {
                size_t last_count = 0;
                auto last_time = std::chrono::high_resolution_clock::now();
                while (!done.load())
                {
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        auto now = std::chrono::high_resolution_clock::now();
                        size_t current = total_inserted.load();
                        double elapsed = std::chrono::duration<double>(now - last_time).count();
                        double rate = (current - last_count) / elapsed;
                        std::cout << "  " << current / 1'000'000.0 << "M keys, "
                                  << std::fixed << std::setprecision(0) << rate / 1000.0 << "K ops/sec, "
                                  << "memory: " << arena.memory_usage() / (1024.0 * 1024.0) << " MB\n";
                        last_count = current;
                        last_time = now;
                }
        });

        std::cout << "Inserting keys...\n";
        auto start = std::chrono::high_resolution_clock::now();

        // Worker threads
        std::vector<std::thread> workers;
        size_t keys_per_thread = NUM_KEYS / NUM_THREADS;

        for (size_t t = 0; t < NUM_THREADS; ++t)
        {
                workers.emplace_back([&, t]() {
                        std::string value_str(VALUE_SIZE, 'v');
                        char key_buf[KEY_SIZE + 1];

                        size_t start_key = t * keys_per_thread;
                        size_t end_key = (t == NUM_THREADS - 1) ? NUM_KEYS : start_key + keys_per_thread;

                        for (size_t i = start_key; i < end_key; ++i)
                        {
                                std::snprintf(key_buf, sizeof(key_buf), "%016zu", i);
                                skiplist.insert(minilsm::InternalKey(key_buf, i + 1, minilsm::KeyType::Put), value_str);
                                total_inserted.fetch_add(1, std::memory_order_relaxed);
                        }
                });
        }

        // Wait for all workers
        for (auto &w : workers)
        {
                w.join();
        }

        auto end = std::chrono::high_resolution_clock::now();
        done.store(true);
        reporter.join();

        auto elapsed = std::chrono::duration<double>(end - start).count();

        std::cout << "\n=== Results ===\n";
        std::cout << "Total keys inserted: " << NUM_KEYS << "\n";
        std::cout << "Threads: " << NUM_THREADS << "\n";
        std::cout << "Total time: " << std::fixed << std::setprecision(2) << elapsed << " seconds\n";
        std::cout << "Throughput: " << std::setprecision(0) << NUM_KEYS / elapsed << " inserts/sec\n";
        std::cout << "Throughput: " << std::setprecision(2) << (NUM_KEYS / elapsed) / 1'000'000.0 << " M inserts/sec\n";
        std::cout << "Arena memory: " << arena.memory_usage() / (1024.0 * 1024.0) << " MB\n";
        std::cout << "Bytes per entry: " << static_cast<double>(arena.memory_usage()) / NUM_KEYS << "\n";

        // Verify a few random lookups
        std::cout << "\n=== Verification ===\n";
        char key_buf[KEY_SIZE + 1];
        std::string result;
        std::snprintf(key_buf, sizeof(key_buf), "%016zu", size_t(0));
        if (skiplist.get(key_buf, &result))
        {
                std::cout << "Key 0: found (value size=" << result.size() << ")\n";
        }
        std::snprintf(key_buf, sizeof(key_buf), "%016zu", NUM_KEYS / 2);
        if (skiplist.get(key_buf, &result))
        {
                std::cout << "Key " << NUM_KEYS / 2 << ": found (value size=" << result.size() << ")\n";
        }
        std::snprintf(key_buf, sizeof(key_buf), "%016zu", NUM_KEYS - 1);
        if (skiplist.get(key_buf, &result))
        {
                std::cout << "Key " << NUM_KEYS - 1 << ": found (value size=" << result.size() << ")\n";
        }

        return 0;
}
