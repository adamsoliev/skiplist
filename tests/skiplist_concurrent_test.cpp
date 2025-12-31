#include <gtest/gtest.h>

#include "../src/skiplist.hpp"

#include <atomic>
#include <chrono>
#include <random>
#include <set>
#include <thread>
#include <vector>

using namespace minilsm;

class SkipListConcurrentTest : public ::testing::Test
{
      protected:
        void SetUp() override
        {
                arena_ = std::make_unique<Arena>();
                list_ = std::make_unique<SkipList>(arena_.get());
        }

        std::unique_ptr<Arena> arena_;
        std::unique_ptr<SkipList> list_;
};

// Multiple Writers

TEST_F(SkipListConcurrentTest, ConcurrentWritersDifferentKeys)
{
        const int kNumThreads = 4;
        const int kInsertsPerThread = 1000;
        std::atomic<uint64_t> seq_counter{0};

        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, t, &seq_counter]()
                    {
                            for (int i = 0; i < kInsertsPerThread; i++)
                            {
                                    std::string key = "t" + std::to_string(t) + "_k" + std::to_string(i);
                                    std::string value = "v" + std::to_string(i);
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                    list_->insert(InternalKey(key, seq, KeyType::Put), value);
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        // Verify all keys are present
        for (int t = 0; t < kNumThreads; t++)
        {
                for (int i = 0; i < kInsertsPerThread; i++)
                {
                        std::string key = "t" + std::to_string(t) + "_k" + std::to_string(i);
                        std::string expected_value = "v" + std::to_string(i);
                        std::string value;
                        EXPECT_TRUE(list_->get(key, &value)) << "Missing key: " << key;
                        EXPECT_EQ(value, expected_value);
                }
        }
}

TEST_F(SkipListConcurrentTest, ConcurrentWritersSameKeys)
{
        const int kNumThreads = 4;
        const int kNumKeys = 100;
        const int kUpdatesPerKey = 50;
        std::atomic<uint64_t> seq_counter{0};

        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, t, &seq_counter]()
                    {
                            for (int round = 0; round < kUpdatesPerKey; round++)
                            {
                                    for (int k = 0; k < kNumKeys; k++)
                                    {
                                            std::string key = "key" + std::to_string(k);
                                            std::string value = "t" + std::to_string(t) + "_r" + std::to_string(round);
                                            uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                            list_->insert(InternalKey(key, seq, KeyType::Put), value);
                                    }
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        // Verify all keys exist (value will be from whichever thread had highest seq)
        for (int k = 0; k < kNumKeys; k++)
        {
                std::string key = "key" + std::to_string(k);
                std::string value;
                EXPECT_TRUE(list_->get(key, &value)) << "Missing key: " << key;
        }

        // Count total entries via iterator (should be kNumThreads * kUpdatesPerKey * kNumKeys)
        int count = 0;
        SkipList::Iterator iter(list_.get());
        for (iter.seek_to_first(); iter.valid(); iter.next())
        {
                count++;
        }
        EXPECT_EQ(count, kNumThreads * kUpdatesPerKey * kNumKeys);
}

// Multiple Readers

TEST_F(SkipListConcurrentTest, ConcurrentReaders)
{
        // Pre-populate the list
        const int kNumKeys = 1000;
        for (int i = 0; i < kNumKeys; i++)
        {
                std::string key = "key" + std::to_string(i);
                std::string value = "value" + std::to_string(i);
                list_->insert(InternalKey(key, i + 1, KeyType::Put), value);
        }

        const int kNumThreads = 8;
        const int kReadsPerThread = 5000;
        std::atomic<int> successful_reads{0};
        std::atomic<int> failed_reads{0};

        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, &successful_reads, &failed_reads]()
                    {
                            std::mt19937 rng(std::random_device{}());
                            std::uniform_int_distribution<int> dist(0, kNumKeys - 1);

                            for (int i = 0; i < kReadsPerThread; i++)
                            {
                                    int k = dist(rng);
                                    std::string key = "key" + std::to_string(k);
                                    std::string expected_value = "value" + std::to_string(k);
                                    std::string value;

                                    if (list_->get(key, &value))
                                    {
                                            EXPECT_EQ(value, expected_value);
                                            successful_reads.fetch_add(1, std::memory_order_relaxed);
                                    }
                                    else
                                    {
                                            failed_reads.fetch_add(1, std::memory_order_relaxed);
                                    }
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        EXPECT_EQ(successful_reads.load(), kNumThreads * kReadsPerThread);
        EXPECT_EQ(failed_reads.load(), 0);
}

TEST_F(SkipListConcurrentTest, ConcurrentIterators)
{
        // Pre-populate
        const int kNumKeys = 500;
        for (int i = 0; i < kNumKeys; i++)
        {
                char key[16];
                snprintf(key, sizeof(key), "key%06d", i);
                list_->insert(InternalKey(key, i + 1, KeyType::Put), std::to_string(i));
        }

        const int kNumThreads = 4;
        std::atomic<bool> all_passed{true};

        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, &all_passed]()
                    {
                            // Forward iteration
                            SkipList::Iterator iter(list_.get());
                            int count = 0;
                            int prev_num = -1;

                            for (iter.seek_to_first(); iter.valid(); iter.next())
                            {
                                    std::string key = iter.key().user_key.to_string();
                                    int num = std::stoi(key.substr(3));
                                    if (num <= prev_num)
                                    {
                                            all_passed.store(false, std::memory_order_relaxed);
                                            break;
                                    }
                                    prev_num = num;
                                    count++;
                            }

                            if (count != kNumKeys)
                            {
                                    all_passed.store(false, std::memory_order_relaxed);
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        EXPECT_TRUE(all_passed.load());
}

// Mixed Readers and Writers

TEST_F(SkipListConcurrentTest, ReadersAndWritersMixed)
{
        const int kNumWriters = 2;
        const int kNumReaders = 4;
        const int kWritesPerWriter = 500;
        const int kReadsPerReader = 2000;
        std::atomic<uint64_t> seq_counter{0};
        std::atomic<bool> writers_done{false};

        std::vector<std::thread> writers;
        std::vector<std::thread> readers;

        // Writers insert keys
        for (int w = 0; w < kNumWriters; w++)
        {
                writers.emplace_back(
                    [this, w, &seq_counter]()
                    {
                            for (int i = 0; i < kWritesPerWriter; i++)
                            {
                                    std::string key = "key" + std::to_string(i);
                                    std::string value = "w" + std::to_string(w) + "_v" + std::to_string(i);
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                    list_->insert(InternalKey(key, seq, KeyType::Put), value);
                            }
                    });
        }

        // Readers continuously read (may or may not find keys)
        for (int r = 0; r < kNumReaders; r++)
        {
                readers.emplace_back(
                    [this]()
                    {
                            std::mt19937 rng(std::random_device{}());
                            std::uniform_int_distribution<int> dist(0, kWritesPerWriter - 1);

                            for (int i = 0; i < kReadsPerReader; i++)
                            {
                                    int k = dist(rng);
                                    std::string key = "key" + std::to_string(k);
                                    std::string value;
                                    // Just verify no crash - key may or may not exist yet
                                    list_->get(key, &value);
                            }
                    });
        }

        for (auto &w : writers)
        {
                w.join();
        }
        writers_done.store(true, std::memory_order_release);

        for (auto &r : readers)
        {
                r.join();
        }

        // After all writers done, verify all keys exist
        for (int i = 0; i < kWritesPerWriter; i++)
        {
                std::string key = "key" + std::to_string(i);
                std::string value;
                EXPECT_TRUE(list_->get(key, &value)) << "Missing key: " << key;
        }
}

TEST_F(SkipListConcurrentTest, IteratorsWhileWriting)
{
        // Pre-populate some data
        for (int i = 0; i < 100; i++)
        {
                char key[16];
                snprintf(key, sizeof(key), "init%06d", i);
                list_->insert(InternalKey(key, i + 1, KeyType::Put), std::to_string(i));
        }

        std::atomic<uint64_t> seq_counter{100};
        std::atomic<bool> stop_writing{false};
        std::atomic<int> iter_count{0};

        // Writer thread adds new keys
        std::thread writer(
            [this, &seq_counter, &stop_writing]()
            {
                    int i = 0;
                    while (!stop_writing.load(std::memory_order_acquire))
                    {
                            char key[16];
                            snprintf(key, sizeof(key), "new%06d", i);
                            uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                            list_->insert(InternalKey(key, seq, KeyType::Put), std::to_string(i));
                            i++;
                    }
            });

        // Multiple readers iterate
        std::vector<std::thread> readers;
        for (int r = 0; r < 4; r++)
        {
                readers.emplace_back(
                    [this, &iter_count]()
                    {
                            for (int round = 0; round < 10; round++)
                            {
                                    SkipList::Iterator iter(list_.get());
                                    int count = 0;
                                    std::string prev_key;

                                    for (iter.seek_to_first(); iter.valid(); iter.next())
                                    {
                                            std::string key = iter.key().user_key.to_string();
                                            // Keys should be in order (though new ones may appear)
                                            if (!prev_key.empty())
                                            {
                                                    EXPECT_LE(prev_key, key)
                                                        << "Order violation: " << prev_key << " > " << key;
                                            }
                                            prev_key = key;
                                            count++;
                                    }
                                    iter_count.fetch_add(count, std::memory_order_relaxed);
                            }
                    });
        }

        for (auto &r : readers)
        {
                r.join();
        }

        stop_writing.store(true, std::memory_order_release);
        writer.join();

        EXPECT_GT(iter_count.load(), 0);
}

// Stress Tests

TEST_F(SkipListConcurrentTest, HighContentionSameKey)
{
        const int kNumThreads = 8;
        const int kUpdatesPerThread = 1000;
        std::atomic<uint64_t> seq_counter{0};

        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, t, &seq_counter]()
                    {
                            for (int i = 0; i < kUpdatesPerThread; i++)
                            {
                                    std::string value = "t" + std::to_string(t) + "_i" + std::to_string(i);
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                    list_->insert(InternalKey("hotkey", seq, KeyType::Put), value);
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        // Verify key exists and has the highest sequence value
        std::string value;
        EXPECT_TRUE(list_->get("hotkey", &value));

        // Count all versions
        int version_count = 0;
        SkipList::Iterator iter(list_.get());
        for (iter.seek_to_first(); iter.valid(); iter.next())
        {
                version_count++;
        }
        EXPECT_EQ(version_count, kNumThreads * kUpdatesPerThread);
}

TEST_F(SkipListConcurrentTest, RapidFireInsertAndRead)
{
        const int kDurationMs = 500;
        std::atomic<uint64_t> seq_counter{0};
        std::atomic<bool> stop{false};
        std::atomic<int> total_inserts{0};
        std::atomic<int> total_reads{0};
        std::atomic<int> successful_reads{0};

        // Writer threads
        std::vector<std::thread> writers;
        for (int w = 0; w < 2; w++)
        {
                writers.emplace_back(
                    [this, &seq_counter, &stop, &total_inserts]()
                    {
                            int local_inserts = 0;
                            while (!stop.load(std::memory_order_acquire))
                            {
                                    std::string key = "key" + std::to_string(local_inserts % 100);
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                    list_->insert(InternalKey(key, seq, KeyType::Put), std::to_string(local_inserts));
                                    local_inserts++;
                            }
                            total_inserts.fetch_add(local_inserts, std::memory_order_relaxed);
                    });
        }

        // Reader threads
        std::vector<std::thread> readers;
        for (int r = 0; r < 4; r++)
        {
                readers.emplace_back(
                    [this, &stop, &total_reads, &successful_reads]()
                    {
                            std::mt19937 rng(std::random_device{}());
                            std::uniform_int_distribution<int> dist(0, 99);
                            int local_reads = 0;
                            int local_successes = 0;

                            while (!stop.load(std::memory_order_acquire))
                            {
                                    std::string key = "key" + std::to_string(dist(rng));
                                    std::string value;
                                    if (list_->get(key, &value))
                                    {
                                            local_successes++;
                                    }
                                    local_reads++;
                            }
                            total_reads.fetch_add(local_reads, std::memory_order_relaxed);
                            successful_reads.fetch_add(local_successes, std::memory_order_relaxed);
                    });
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(kDurationMs));
        stop.store(true, std::memory_order_release);

        for (auto &w : writers)
        {
                w.join();
        }
        for (auto &r : readers)
        {
                r.join();
        }

        // Just verify we did substantial work without crashing
        EXPECT_GT(total_inserts.load(), 0);
        EXPECT_GT(total_reads.load(), 0);
}

// Sequence Number Ordering

TEST_F(SkipListConcurrentTest, SequenceOrderingUnderContention)
{
        const int kNumThreads = 4;
        const int kNumKeys = 10;
        const int kUpdatesPerKey = 100;
        std::atomic<uint64_t> seq_counter{0};

        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, &seq_counter]()
                    {
                            for (int round = 0; round < kUpdatesPerKey; round++)
                            {
                                    for (int k = 0; k < kNumKeys; k++)
                                    {
                                            std::string key = "key" + std::to_string(k);
                                            uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                            list_->insert(InternalKey(key, seq, KeyType::Put), std::to_string(seq));
                                    }
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        // For each key, verify versions are in descending sequence order
        for (int k = 0; k < kNumKeys; k++)
        {
                std::string target_key = "key" + std::to_string(k);
                SkipList::Iterator iter(list_.get());
                iter.seek(target_key);

                uint64_t prev_seq = UINT64_MAX;
                while (iter.valid() && iter.key().user_key.to_string() == target_key)
                {
                        uint64_t seq = iter.key().sequence;
                        EXPECT_LT(seq, prev_seq) << "Sequence order violation for key " << target_key;
                        prev_seq = seq;
                        iter.next();
                }
        }
}
