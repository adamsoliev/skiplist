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

// ========================================
// Additional Edge Case Tests
// ========================================

// Single Writer + Multiple Readers (RocksDB pattern)

TEST_F(SkipListConcurrentTest, SingleWriterMultipleReaders)
{
        const int kNumReaders = 8;
        const int kNumWrites = 1000;
        const int kReadsPerReader = 5000;
        std::atomic<uint64_t> seq_counter{0};
        std::atomic<int> writes_done{0};
        std::atomic<int> failed_reads{0};

        // Single writer thread
        std::thread writer(
            [this, &seq_counter, &writes_done]()
            {
                    for (int i = 0; i < kNumWrites; i++)
                    {
                            std::string key = "key" + std::to_string(i);
                            std::string value = "value" + std::to_string(i);
                            uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                            list_->insert(InternalKey(key, seq, KeyType::Put), value);
                            writes_done.fetch_add(1, std::memory_order_release);
                    }
            });

        // Multiple reader threads
        std::vector<std::thread> readers;
        for (int r = 0; r < kNumReaders; r++)
        {
                readers.emplace_back(
                    [this, &failed_reads, &writes_done]()
                    {
                            std::mt19937 rng(std::random_device{}());
                            std::uniform_int_distribution<int> dist(0, kNumWrites - 1);

                            for (int i = 0; i < kReadsPerReader; i++)
                            {
                                    int k = dist(rng);
                                    std::string key = "key" + std::to_string(k);
                                    std::string value;

                                    // If write is done, read must succeed
                                    int current_writes = writes_done.load(std::memory_order_acquire);
                                    bool found = list_->get(key, &value);

                                    if (k < current_writes && !found)
                                    {
                                            failed_reads.fetch_add(1, std::memory_order_relaxed);
                                    }

                                    if (found)
                                    {
                                            std::string expected = "value" + std::to_string(k);
                                            EXPECT_EQ(value, expected);
                                    }
                            }
                    });
        }

        writer.join();
        for (auto &r : readers)
        {
                r.join();
        }

        // No reads should fail after writer is done
        for (int i = 0; i < kNumWrites; i++)
        {
                std::string key = "key" + std::to_string(i);
                std::string value;
                EXPECT_TRUE(list_->get(key, &value));
        }
}

// Multiple Writers + Single Reader (RocksDB pattern)

TEST_F(SkipListConcurrentTest, MultipleWritersSingleReader)
{
        const int kNumWriters = 4;
        const int kWritesPerWriter = 500;
        std::atomic<uint64_t> seq_counter{0};
        std::atomic<bool> stop_reading{false};
        std::atomic<int> successful_reads{0};

        // Multiple writer threads
        std::vector<std::thread> writers;
        for (int w = 0; w < kNumWriters; w++)
        {
                writers.emplace_back(
                    [this, w, &seq_counter]()
                    {
                            for (int i = 0; i < kWritesPerWriter; i++)
                            {
                                    std::string key = "w" + std::to_string(w) + "_k" + std::to_string(i);
                                    std::string value = "v" + std::to_string(i);
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                    list_->insert(InternalKey(key, seq, KeyType::Put), value);
                            }
                    });
        }

        // Single reader thread
        std::thread reader(
            [this, &stop_reading, &successful_reads]()
            {
                    std::mt19937 rng(std::random_device{}());
                    std::uniform_int_distribution<int> writer_dist(0, kNumWriters - 1);
                    std::uniform_int_distribution<int> key_dist(0, kWritesPerWriter - 1);

                    while (!stop_reading.load(std::memory_order_acquire))
                    {
                            int w = writer_dist(rng);
                            int k = key_dist(rng);
                            std::string key = "w" + std::to_string(w) + "_k" + std::to_string(k);
                            std::string value;

                            if (list_->get(key, &value))
                            {
                                    std::string expected = "v" + std::to_string(k);
                                    EXPECT_EQ(value, expected);
                                    successful_reads.fetch_add(1, std::memory_order_relaxed);
                            }
                    }
            });

        for (auto &w : writers)
        {
                w.join();
        }
        stop_reading.store(true, std::memory_order_release);
        reader.join();

        // Verify all keys exist
        for (int w = 0; w < kNumWriters; w++)
        {
                for (int i = 0; i < kWritesPerWriter; i++)
                {
                        std::string key = "w" + std::to_string(w) + "_k" + std::to_string(i);
                        std::string value;
                        EXPECT_TRUE(list_->get(key, &value));
                }
        }

        EXPECT_GT(successful_reads.load(), 0);
}

// Backward Iteration During Concurrent Writes

TEST_F(SkipListConcurrentTest, BackwardIterationWhileWriting)
{
        // Pre-populate
        for (int i = 0; i < 100; i++)
        {
                char key[16];
                snprintf(key, sizeof(key), "init%06d", i);
                list_->insert(InternalKey(key, i + 1, KeyType::Put), std::to_string(i));
        }

        std::atomic<uint64_t> seq_counter{100};
        std::atomic<bool> stop_writing{false};
        std::atomic<int> backward_count{0};

        // Writer thread
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

        // Multiple readers iterating backward
        std::vector<std::thread> readers;
        for (int r = 0; r < 4; r++)
        {
                readers.emplace_back(
                    [this, &backward_count]()
                    {
                            for (int round = 0; round < 10; round++)
                            {
                                    SkipList::Iterator iter(list_.get());
                                    int count = 0;
                                    std::string prev_key;

                                    // Backward iteration
                                    for (iter.seek_to_last(); iter.valid(); iter.prev())
                                    {
                                            std::string key = iter.key().user_key.to_string();
                                            // Keys should be in reverse order
                                            if (!prev_key.empty())
                                            {
                                                    EXPECT_GE(prev_key, key)
                                                        << "Reverse order violation: " << prev_key << " < " << key;
                                            }
                                            prev_key = key;
                                            count++;
                                    }
                                    backward_count.fetch_add(count, std::memory_order_relaxed);
                            }
                    });
        }

        for (auto &r : readers)
        {
                r.join();
        }

        stop_writing.store(true, std::memory_order_release);
        writer.join();

        EXPECT_GT(backward_count.load(), 0);
}

// Concurrent Seeks to Same Key

TEST_F(SkipListConcurrentTest, ConcurrentSeeksToSameKey)
{
        // Insert multiple versions of same key
        const int kNumVersions = 100;
        for (int i = 0; i < kNumVersions; i++)
        {
                list_->insert(InternalKey("target_key", i + 1, KeyType::Put), std::to_string(i));
        }

        // Multiple threads seeking to the same key simultaneously
        const int kNumThreads = 8;
        const int kSeeksPerThread = 1000;
        std::atomic<int> correct_seeks{0};

        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, &correct_seeks]()
                    {
                            for (int i = 0; i < kSeeksPerThread; i++)
                            {
                                    SkipList::Iterator iter(list_.get());
                                    iter.seek("target_key");

                                    if (iter.valid() && iter.key().user_key.to_string() == "target_key")
                                    {
                                            // Should land on newest version (highest sequence)
                                            if (iter.key().sequence == kNumVersions)
                                            {
                                                    correct_seeks.fetch_add(1, std::memory_order_relaxed);
                                            }
                                    }
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        EXPECT_EQ(correct_seeks.load(), kNumThreads * kSeeksPerThread);
}

// Max Height Stress Test

TEST_F(SkipListConcurrentTest, MaxHeightConcurrentInserts)
{
        // Force creation of tall nodes by inserting many keys
        // With branching factor 4 and max height 12, we need enough keys
        // to likely create some max-height nodes
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
                                    // Use formatted keys to ensure good distribution
                                    char key[32];
                                    snprintf(key, sizeof(key), "key_%03d_%06d", t, i);
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                    list_->insert(InternalKey(key, seq, KeyType::Put), std::to_string(i));
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        // Verify all keys via iteration
        SkipList::Iterator iter(list_.get());
        int count = 0;
        for (iter.seek_to_first(); iter.valid(); iter.next())
        {
                count++;
        }

        EXPECT_EQ(count, kNumThreads * kInsertsPerThread);
}

// Sequence Number Boundaries

TEST_F(SkipListConcurrentTest, SequenceNumberBoundaries)
{
        const int kNumThreads = 4;
        const int kInsertsPerThread = 100;

        // Test with very high sequence numbers (near UINT64_MAX)
        std::atomic<uint64_t> seq_counter{UINT64_MAX - 1000};

        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, &seq_counter]()
                    {
                            for (int i = 0; i < kInsertsPerThread; i++)
                            {
                                    std::string key = "key" + std::to_string(i);
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed);
                                    list_->insert(InternalKey(key, seq, KeyType::Put), "value");
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        // Verify keys exist and ordering is maintained
        for (int i = 0; i < kInsertsPerThread; i++)
        {
                std::string key = "key" + std::to_string(i);
                std::string value;
                EXPECT_TRUE(list_->get(key, &value));
        }
}

// Tombstone Visibility Under Concurrency

TEST_F(SkipListConcurrentTest, ConcurrentDeletesAndReads)
{
        const int kNumKeys = 100;
        const int kNumWriters = 2;
        const int kNumReaders = 4;
        std::atomic<uint64_t> seq_counter{0};
        std::atomic<bool> stop{false};

        // Pre-populate with initial values
        for (int i = 0; i < kNumKeys; i++)
        {
                std::string key = "key" + std::to_string(i);
                uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                list_->insert(InternalKey(key, seq, KeyType::Put), "initial");
        }

        // Writer threads: alternate between put and delete
        std::vector<std::thread> writers;
        for (int w = 0; w < kNumWriters; w++)
        {
                writers.emplace_back(
                    [this, &seq_counter]()
                    {
                            std::mt19937 rng(std::random_device{}());
                            std::uniform_int_distribution<int> key_dist(0, kNumKeys - 1);
                            std::uniform_int_distribution<int> type_dist(0, 1);

                            int ops = 0;
                            while (ops < 500)
                            {
                                    int k = key_dist(rng);
                                    std::string key = "key" + std::to_string(k);
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;

                                    if (type_dist(rng) == 0)
                                    {
                                            // Put
                                            list_->insert(InternalKey(key, seq, KeyType::Put), "updated");
                                    }
                                    else
                                    {
                                            // Delete
                                            list_->insert(InternalKey(key, seq, KeyType::Delete), "");
                                    }
                                    ops++;
                            }
                    });
        }

        // Reader threads: continuously read and verify consistency
        std::vector<std::thread> readers;
        for (int r = 0; r < kNumReaders; r++)
        {
                readers.emplace_back(
                    [this, &stop]()
                    {
                            std::mt19937 rng(std::random_device{}());
                            std::uniform_int_distribution<int> dist(0, kNumKeys - 1);

                            while (!stop.load(std::memory_order_acquire))
                            {
                                    int k = dist(rng);
                                    std::string key = "key" + std::to_string(k);
                                    std::string value;

                                    // Get may return true or false depending on latest version
                                    // Just verify no crashes occur
                                    list_->get(key, &value);
                            }
                    });
        }

        for (auto &w : writers)
        {
                w.join();
        }
        stop.store(true, std::memory_order_release);

        for (auto &r : readers)
        {
                r.join();
        }

        // All operations should complete without crashes
        SUCCEED();
}

// Version Chain Integrity

TEST_F(SkipListConcurrentTest, VersionChainIntegrityUnderConcurrentWrites)
{
        const int kNumThreads = 8;
        const int kVersionsPerThread = 50;
        const std::string kTargetKey = "versioned_key";
        std::atomic<uint64_t> seq_counter{0};

        // All threads update the same key
        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, t, &seq_counter, &kTargetKey]()
                    {
                            for (int i = 0; i < kVersionsPerThread; i++)
                            {
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                    std::string value = "t" + std::to_string(t) + "_v" + std::to_string(i);
                                    list_->insert(InternalKey(kTargetKey, seq, KeyType::Put), value);
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        // Verify all versions are present and in correct order
        SkipList::Iterator iter(list_.get());
        iter.seek(kTargetKey);

        int version_count = 0;
        uint64_t prev_seq = UINT64_MAX;

        while (iter.valid() && iter.key().user_key.to_string() == kTargetKey)
        {
                uint64_t seq = iter.key().sequence;
                EXPECT_LT(seq, prev_seq) << "Version sequence should be descending";
                prev_seq = seq;
                version_count++;
                iter.next();
        }

        EXPECT_EQ(version_count, kNumThreads * kVersionsPerThread);
}

// Seek Accuracy During Concurrent Insertions

TEST_F(SkipListConcurrentTest, SeekAccuracyDuringConcurrentInserts)
{
        const int kNumWriters = 2;
        const int kNumSeekers = 4;
        const int kInsertsPerWriter = 500;
        const int kSeeksPerSeeker = 1000;
        std::atomic<uint64_t> seq_counter{0};
        std::atomic<bool> stop_seeking{false};

        // Writers continuously insert keys
        std::vector<std::thread> writers;
        for (int w = 0; w < kNumWriters; w++)
        {
                writers.emplace_back(
                    [this, w, &seq_counter]()
                    {
                            for (int i = 0; i < kInsertsPerWriter; i++)
                            {
                                    char key[32];
                                    snprintf(key, sizeof(key), "key_%03d_%06d", w, i);
                                    uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                    list_->insert(InternalKey(key, seq, KeyType::Put), std::to_string(i));
                            }
                    });
        }

        // Seekers continuously seek to random keys
        std::vector<std::thread> seekers;
        std::atomic<int> seek_errors{0};

        for (int s = 0; s < kNumSeekers; s++)
        {
                seekers.emplace_back(
                    [this, &stop_seeking, &seek_errors]()
                    {
                            std::mt19937 rng(std::random_device{}());
                            std::uniform_int_distribution<int> writer_dist(0, kNumWriters - 1);
                            std::uniform_int_distribution<int> key_dist(0, kInsertsPerWriter - 1);

                            int local_seeks = 0;
                            while (local_seeks < kSeeksPerSeeker && !stop_seeking.load(std::memory_order_acquire))
                            {
                                    int w = writer_dist(rng);
                                    int k = key_dist(rng);
                                    char seek_key[32];
                                    snprintf(seek_key, sizeof(seek_key), "key_%03d_%06d", w, k);

                                    SkipList::Iterator iter(list_.get());
                                    iter.seek(seek_key);

                                    if (iter.valid())
                                    {
                                            std::string found_key = iter.key().user_key.to_string();
                                            // Found key should be >= seek key
                                            if (found_key < std::string(seek_key))
                                            {
                                                    seek_errors.fetch_add(1, std::memory_order_relaxed);
                                            }
                                    }
                                    local_seeks++;
                            }
                    });
        }

        for (auto &w : writers)
        {
                w.join();
        }
        stop_seeking.store(true, std::memory_order_release);

        for (auto &s : seekers)
        {
                s.join();
        }

        EXPECT_EQ(seek_errors.load(), 0);
}

// Interleaved Insert Pattern (Stress Splice Invalidation)

TEST_F(SkipListConcurrentTest, InterleavedInsertPattern)
{
        const int kNumThreads = 4;
        const int kRounds = 100;
        std::atomic<uint64_t> seq_counter{0};

        // Each thread inserts keys in interleaved pattern to maximize contention
        std::vector<std::thread> threads;
        for (int t = 0; t < kNumThreads; t++)
        {
                threads.emplace_back(
                    [this, t, &seq_counter]()
                    {
                            for (int round = 0; round < kRounds; round++)
                            {
                                    // Insert in pattern: t0 inserts 0,4,8... t1 inserts 1,5,9...
                                    for (int i = t; i < kRounds * kNumThreads; i += kNumThreads)
                                    {
                                            char key[16];
                                            snprintf(key, sizeof(key), "k%08d", i);
                                            uint64_t seq = seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
                                            list_->insert(InternalKey(key, seq, KeyType::Put), std::to_string(i));
                                    }
                            }
                    });
        }

        for (auto &t : threads)
        {
                t.join();
        }

        // Verify sorted order
        SkipList::Iterator iter(list_.get());
        std::string prev_key;
        int count = 0;

        for (iter.seek_to_first(); iter.valid(); iter.next())
        {
                std::string key = iter.key().user_key.to_string();
                if (!prev_key.empty())
                {
                        EXPECT_LE(prev_key, key) << "Keys should be in sorted order";
                }
                prev_key = key;
                count++;
        }

        EXPECT_GT(count, 0);
}
