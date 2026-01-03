// Comparative benchmark: minilsm vs RocksDB InlineSkipList vs Redis zskiplist
#include <benchmark/benchmark.h>

#include "bench_common.hpp"
#include "wrappers/minilsm_wrapper.hpp"
#include "wrappers/redis_wrapper.hpp"
#include "wrappers/rocksdb_wrapper.hpp"

#include <memory>
#include <thread>
#include <vector>

using namespace bench;

// Default data profile: 8-64B keys, 100B-4KB values
static const DataProfile kDefaultProfile{8, 64, 100, 4096};

// ============================================================================
// Sequential Insert Benchmark
// ============================================================================

template <typename SkipListType> static void BM_Insert(benchmark::State &state)
{
        const size_t num_items = static_cast<size_t>(state.range(0));
        TestData data(num_items, kDefaultProfile);

        for (auto _ : state)
        {
                state.PauseTiming();
                SkipListType list;
                state.ResumeTiming();

                for (size_t i = 0; i < num_items; ++i)
                {
                        list.insert(data.key(i).data(), data.key(i).size(), data.value(i).data(), data.value(i).size());
                }

                benchmark::DoNotOptimize(list.memory_usage());
        }

        state.SetItemsProcessed(static_cast<int64_t>(state.iterations() * num_items));
        state.SetLabel(SkipListType::kName);
}

// ============================================================================
// Random Insert Benchmark (shuffled keys)
// ============================================================================

template <typename SkipListType> static void BM_InsertRandom(benchmark::State &state)
{
        const size_t num_items = static_cast<size_t>(state.range(0));
        TestData data(num_items, kDefaultProfile);
        auto indices = data.shuffled_indices();

        for (auto _ : state)
        {
                state.PauseTiming();
                SkipListType list;
                state.ResumeTiming();

                for (size_t i = 0; i < num_items; ++i)
                {
                        size_t idx = indices[i];
                        list.insert(
                            data.key(idx).data(), data.key(idx).size(), data.value(idx).data(), data.value(idx).size());
                }

                benchmark::DoNotOptimize(list.memory_usage());
        }

        state.SetItemsProcessed(static_cast<int64_t>(state.iterations() * num_items));
        state.SetLabel(SkipListType::kName);
}

// ============================================================================
// Point Lookup Benchmark
// ============================================================================

template <typename SkipListType> static void BM_Lookup(benchmark::State &state)
{
        const size_t num_items = static_cast<size_t>(state.range(0));
        TestData data(num_items, kDefaultProfile);

        // Pre-populate
        SkipListType list;
        for (size_t i = 0; i < num_items; ++i)
        {
                list.insert(data.key(i).data(), data.key(i).size(), data.value(i).data(), data.value(i).size());
        }

        std::mt19937_64 rng(12345);
        std::uniform_int_distribution<size_t> dist(0, num_items - 1);

        for (auto _ : state)
        {
                size_t idx = dist(rng);
                std::string value;
                benchmark::DoNotOptimize(list.get(data.key(idx).data(), data.key(idx).size(), &value));
                benchmark::DoNotOptimize(value.data());
        }

        state.SetItemsProcessed(state.iterations());
        state.SetLabel(SkipListType::kName);
}

// ============================================================================
// Iterator Scan Benchmark
// ============================================================================

template <typename SkipListType> static void BM_Iterate(benchmark::State &state)
{
        const size_t num_items = static_cast<size_t>(state.range(0));
        TestData data(num_items, kDefaultProfile);

        // Pre-populate
        SkipListType list;
        for (size_t i = 0; i < num_items; ++i)
        {
                list.insert(data.key(i).data(), data.key(i).size(), data.value(i).data(), data.value(i).size());
        }

        for (auto _ : state)
        {
                auto iter = list.new_iterator();
                iter.seek_to_first();
                size_t count = 0;
                while (iter.valid())
                {
                        benchmark::DoNotOptimize(iter.key_data());
                        iter.next();
                        ++count;
                }
                benchmark::DoNotOptimize(count);
        }

        state.SetItemsProcessed(static_cast<int64_t>(state.iterations() * num_items));
        state.SetLabel(SkipListType::kName);
}

// ============================================================================
// Delete Benchmark
// ============================================================================

template <typename SkipListType> static void BM_Delete(benchmark::State &state)
{
        const size_t num_items = static_cast<size_t>(state.range(0));
        TestData data(num_items, kDefaultProfile);

        for (auto _ : state)
        {
                state.PauseTiming();
                SkipListType list;
                // Insert all items first
                for (size_t i = 0; i < num_items; ++i)
                {
                        list.insert(data.key(i).data(), data.key(i).size(), data.value(i).data(), data.value(i).size());
                }
                state.ResumeTiming();

                // Delete all items
                for (size_t i = 0; i < num_items; ++i)
                {
                        list.remove(data.key(i).data(), data.key(i).size());
                }
        }

        state.SetItemsProcessed(static_cast<int64_t>(state.iterations() * num_items));
        state.SetLabel(SkipListType::kName);
}

// ============================================================================
// Concurrent Insert Benchmark (thread-safe implementations only)
// ============================================================================

template <typename SkipListType> static void BM_ConcurrentInsert(benchmark::State &state)
{
        if constexpr (!SkipListType::kThreadSafe)
        {
                state.SkipWithError("Not thread-safe");
                return;
        }

        const int num_threads = static_cast<int>(state.range(0));
        const size_t ops_per_thread = 10000;
        const size_t total_ops = num_threads * ops_per_thread;
        TestData data(total_ops, kDefaultProfile);

        for (auto _ : state)
        {
                state.PauseTiming();
                SkipListType list;
                std::vector<std::thread> threads;
                Barrier barrier(num_threads);
                state.ResumeTiming();

                for (int t = 0; t < num_threads; ++t)
                {
                        threads.emplace_back(
                            [&, t]()
                            {
                                    barrier.wait(); // Synchronized start
                                    for (size_t i = 0; i < ops_per_thread; ++i)
                                    {
                                            size_t idx = t * ops_per_thread + i;
                                            list.insert(
                                                data.key(idx).data(),
                                                data.key(idx).size(),
                                                data.value(idx).data(),
                                                data.value(idx).size());
                                    }
                            });
                }

                for (auto &thread : threads)
                {
                        thread.join();
                }
        }

        state.SetItemsProcessed(static_cast<int64_t>(state.iterations() * total_ops));
        state.SetLabel(SkipListType::kName);
}

// ============================================================================
// Mixed Read/Write Benchmark (80% read, 20% write)
// ============================================================================

template <typename SkipListType> static void BM_MixedReadWrite(benchmark::State &state)
{
        if constexpr (!SkipListType::kThreadSafe)
        {
                state.SkipWithError("Not thread-safe");
                return;
        }

        const int num_threads = static_cast<int>(state.range(0));
        const size_t ops_per_thread = 5000;
        const size_t preload = 10000;
        TestData data(preload + num_threads * ops_per_thread, kDefaultProfile);

        for (auto _ : state)
        {
                state.PauseTiming();
                SkipListType list;

                // Pre-populate
                for (size_t i = 0; i < preload; ++i)
                {
                        list.insert(data.key(i).data(), data.key(i).size(), data.value(i).data(), data.value(i).size());
                }

                std::vector<std::thread> threads;
                Barrier barrier(num_threads);
                std::atomic<size_t> total_reads(0);
                std::atomic<size_t> total_writes(0);
                state.ResumeTiming();

                for (int t = 0; t < num_threads; ++t)
                {
                        threads.emplace_back(
                            [&, t]()
                            {
                                    barrier.wait();
                                    std::mt19937_64 rng(t * 12345);
                                    std::uniform_int_distribution<size_t> read_dist(0, preload - 1);
                                    std::uniform_int_distribution<int> op_dist(0, 99);

                                    size_t reads = 0, writes = 0;
                                    for (size_t i = 0; i < ops_per_thread; ++i)
                                    {
                                            if (op_dist(rng) < 80)
                                            {
                                                    // 80% read
                                                    size_t idx = read_dist(rng);
                                                    std::string value;
                                                    benchmark::DoNotOptimize(
                                                        list.get(data.key(idx).data(), data.key(idx).size(), &value));
                                                    ++reads;
                                            }
                                            else
                                            {
                                                    // 20% write
                                                    size_t idx = preload + t * ops_per_thread + i;
                                                    list.insert(
                                                        data.key(idx).data(),
                                                        data.key(idx).size(),
                                                        data.value(idx).data(),
                                                        data.value(idx).size());
                                                    ++writes;
                                            }
                                    }
                                    total_reads.fetch_add(reads, std::memory_order_relaxed);
                                    total_writes.fetch_add(writes, std::memory_order_relaxed);
                            });
                }

                for (auto &thread : threads)
                {
                        thread.join();
                }
        }

        state.SetItemsProcessed(static_cast<int64_t>(state.iterations() * num_threads * ops_per_thread));
        state.SetLabel(SkipListType::kName);
}

// ============================================================================
// Register Benchmarks
// ============================================================================

// Sequential Insert
BENCHMARK(BM_Insert<MinilsmWrapper>)->Name("Minilsm/Insert")->Range(1000, 100000)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Insert<RocksDBWrapper>)->Name("RocksDB/Insert")->Range(1000, 100000)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Insert<RedisWrapper>)->Name("Redis/Insert")->Range(1000, 100000)->Unit(benchmark::kMillisecond);

// Random Insert
BENCHMARK(BM_InsertRandom<MinilsmWrapper>)
    ->Name("Minilsm/InsertRandom")
    ->Range(1000, 100000)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_InsertRandom<RocksDBWrapper>)
    ->Name("RocksDB/InsertRandom")
    ->Range(1000, 100000)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_InsertRandom<RedisWrapper>)
    ->Name("Redis/InsertRandom")
    ->Range(1000, 100000)
    ->Unit(benchmark::kMillisecond);

// Point Lookup
BENCHMARK(BM_Lookup<MinilsmWrapper>)->Name("Minilsm/Lookup")->Range(1000, 100000)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Lookup<RocksDBWrapper>)->Name("RocksDB/Lookup")->Range(1000, 100000)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Lookup<RedisWrapper>)->Name("Redis/Lookup")->Range(1000, 100000)->Unit(benchmark::kNanosecond);

// Iterator Scan
BENCHMARK(BM_Iterate<MinilsmWrapper>)->Name("Minilsm/Iterate")->Range(1000, 100000)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Iterate<RocksDBWrapper>)->Name("RocksDB/Iterate")->Range(1000, 100000)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Iterate<RedisWrapper>)->Name("Redis/Iterate")->Range(1000, 100000)->Unit(benchmark::kMillisecond);

// Delete
BENCHMARK(BM_Delete<MinilsmWrapper>)->Name("Minilsm/Delete")->Range(1000, 100000)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Delete<RocksDBWrapper>)->Name("RocksDB/Delete")->Range(1000, 100000)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Delete<RedisWrapper>)->Name("Redis/Delete")->Range(1000, 100000)->Unit(benchmark::kMillisecond);

// Concurrent Insert (only for thread-safe implementations)
BENCHMARK(BM_ConcurrentInsert<MinilsmWrapper>)
    ->Name("Minilsm/ConcurrentInsert")
    ->Arg(1)
    ->Arg(2)
    ->Arg(4)
    ->Arg(8)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_ConcurrentInsert<RocksDBWrapper>)
    ->Name("RocksDB/ConcurrentInsert")
    ->Arg(1)
    ->Arg(2)
    ->Arg(4)
    ->Arg(8)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_ConcurrentInsert<RedisWrapper>)
    ->Name("Redis/ConcurrentInsert")
    ->Arg(1)
    ->Arg(2)
    ->Arg(4)
    ->Arg(8)
    ->Unit(benchmark::kMillisecond);

// Mixed Read/Write (only for thread-safe implementations)
BENCHMARK(BM_MixedReadWrite<MinilsmWrapper>)
    ->Name("Minilsm/MixedReadWrite")
    ->Arg(1)
    ->Arg(2)
    ->Arg(4)
    ->Arg(8)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_MixedReadWrite<RocksDBWrapper>)
    ->Name("RocksDB/MixedReadWrite")
    ->Arg(1)
    ->Arg(2)
    ->Arg(4)
    ->Arg(8)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_MixedReadWrite<RedisWrapper>)
    ->Name("Redis/MixedReadWrite")
    ->Arg(1)
    ->Arg(2)
    ->Arg(4)
    ->Arg(8)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
