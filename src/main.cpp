#include "logger.hpp"
#include "skiplist.hpp"
#include <chrono>
#include <cstdio>
#include <string>

int main()
{
        minilsm::Logger log("skiplist");

        constexpr size_t NUM_KEYS = 100'000'000; // 100 million keys
        constexpr size_t KEY_SIZE = 16;
        constexpr size_t VALUE_SIZE = 100;

        log("SkipList Stress Test");
        log("====================");
        log("Keys to insert: ", NUM_KEYS);
        log("Key size: ", KEY_SIZE, " bytes");
        log("Value size: ", VALUE_SIZE, " bytes");
        log("");

        minilsm::Arena arena;
        minilsm::SkipList skiplist(&arena);

        // Pre-generate a fixed value string
        std::string value_str(VALUE_SIZE, 'v');

        // Format key as zero-padded number for good distribution
        char key_buf[KEY_SIZE + 1];

        log("Inserting keys...");
        auto start = std::chrono::high_resolution_clock::now();

        size_t report_interval = 1'000'000;
        for (size_t i = 0; i < NUM_KEYS; ++i)
        {
                std::snprintf(key_buf, sizeof(key_buf), "%016zu", i);
                skiplist.insert(minilsm::InternalKey(key_buf, i + 1, minilsm::KeyType::Put), value_str);

                if ((i + 1) % report_interval == 0)
                {
                        auto now = std::chrono::high_resolution_clock::now();
                        auto elapsed = std::chrono::duration<double>(now - start).count();
                        size_t rate = static_cast<size_t>((i + 1) / elapsed);

                        log("  ", (i + 1) / 1'000'000, "M keys, ",
                            rate / 1000, "K ops/sec, memory: ", arena.memory_usage() / (1024 * 1024), " MB");
                }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration<double>(end - start).count();

        log("");
        log("=== Results ===");
        log("Total keys inserted: ", NUM_KEYS);
        log("Total time: ", static_cast<int>(elapsed), " seconds");
        log("Throughput: ", static_cast<size_t>(NUM_KEYS / elapsed), " inserts/sec");
        log("Arena memory: ", arena.memory_usage() / (1024 * 1024), " MB");
        log("Bytes per entry: ", arena.memory_usage() / NUM_KEYS);

        // Verify a few random lookups
        log("");
        log("=== Verification ===");
        std::string result;
        std::snprintf(key_buf, sizeof(key_buf), "%016zu", size_t(0));
        if (skiplist.get(key_buf, &result))
        {
                log("Key 0: found (value size=", result.size(), ")");
        }
        std::snprintf(key_buf, sizeof(key_buf), "%016zu", NUM_KEYS / 2);
        if (skiplist.get(key_buf, &result))
        {
                log("Key ", NUM_KEYS / 2, ": found (value size=", result.size(), ")");
        }
        std::snprintf(key_buf, sizeof(key_buf), "%016zu", NUM_KEYS - 1);
        if (skiplist.get(key_buf, &result))
        {
                log("Key ", NUM_KEYS - 1, ": found (value size=", result.size(), ")");
        }

        return 0;
}
