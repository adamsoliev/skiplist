#include "../src/arena.hpp"
#include "../src/skiplist.hpp"

#include <benchmark/benchmark.h>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace minilsm;

// Helper to generate random keys
static std::string make_key(int i)
{
        char buf[32];
        snprintf(buf, sizeof(buf), "key%010d", i);
        return std::string(buf);
}

// Sequential insert benchmark
static void BM_SkipListInsert(benchmark::State &state)
{
        for (auto _ : state)
        {
                state.PauseTiming();
                Arena arena;
                SkipList list(&arena);
                state.ResumeTiming();

                for (int i = 0; i < state.range(0); i++)
                {
                        std::string key = make_key(i);
                        InternalKey ikey(Slice(key), i, KeyType::Put);
                        list.insert(ikey, Slice("value"));
                }
        }
        state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_SkipListInsert)->Range(1000, 100000)->Unit(benchmark::kMillisecond);

// Random insert benchmark
static void BM_SkipListInsertRandom(benchmark::State &state)
{
        std::mt19937 rng(42);
        std::vector<int> indices(state.range(0));
        for (int i = 0; i < state.range(0); i++)
        {
                indices[i] = i;
        }
        std::shuffle(indices.begin(), indices.end(), rng);

        for (auto _ : state)
        {
                state.PauseTiming();
                Arena arena;
                SkipList list(&arena);
                state.ResumeTiming();

                for (int i = 0; i < state.range(0); i++)
                {
                        std::string key = make_key(indices[i]);
                        InternalKey ikey(Slice(key), i, KeyType::Put);
                        list.insert(ikey, Slice("value"));
                }
        }
        state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_SkipListInsertRandom)->Range(1000, 100000)->Unit(benchmark::kMillisecond);

// Point lookup benchmark
static void BM_SkipListGet(benchmark::State &state)
{
        Arena arena;
        SkipList list(&arena);

        // Pre-populate
        for (int i = 0; i < state.range(0); i++)
        {
                std::string key = make_key(i);
                InternalKey ikey(Slice(key), i, KeyType::Put);
                list.insert(ikey, Slice("value"));
        }

        std::mt19937 rng(42);
        std::uniform_int_distribution<int> dist(0, state.range(0) - 1);

        for (auto _ : state)
        {
                std::string key = make_key(dist(rng));
                std::string value;
                benchmark::DoNotOptimize(list.get(Slice(key), &value));
        }
        state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_SkipListGet)->Range(1000, 100000)->Unit(benchmark::kMicrosecond);

// Iterator scan benchmark
static void BM_SkipListIterator(benchmark::State &state)
{
        Arena arena;
        SkipList list(&arena);

        // Pre-populate
        for (int i = 0; i < state.range(0); i++)
        {
                std::string key = make_key(i);
                InternalKey ikey(Slice(key), i, KeyType::Put);
                list.insert(ikey, Slice("value"));
        }

        for (auto _ : state)
        {
                SkipList::Iterator iter(&list);
                iter.seek_to_first();
                int count = 0;
                while (iter.valid())
                {
                        auto key = iter.key();
                        auto val = iter.value();
                        benchmark::DoNotOptimize(key);
                        benchmark::DoNotOptimize(val);
                        iter.next();
                        count++;
                }
                benchmark::DoNotOptimize(count);
        }
        state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_SkipListIterator)->Range(1000, 100000)->Unit(benchmark::kMillisecond);

// Concurrent write benchmark
static void BM_SkipListConcurrentInsert(benchmark::State &state)
{
        constexpr int kOpsPerThread = 10000;
        const int num_threads = state.range(0);

        for (auto _ : state)
        {
                state.PauseTiming();
                Arena arena;
                SkipList list(&arena);
                std::vector<std::thread> threads;
                state.ResumeTiming();

                for (int t = 0; t < num_threads; t++)
                {
                        threads.emplace_back(
                            [&list, t]()
                            {
                                    for (int i = 0; i < kOpsPerThread; i++)
                                    {
                                            std::string key = make_key(t * kOpsPerThread + i);
                                            InternalKey ikey(Slice(key), t * kOpsPerThread + i, KeyType::Put);
                                            list.insert(ikey, Slice("value"));
                                    }
                            });
                }
                for (auto &t : threads)
                {
                        t.join();
                }
        }
        state.SetItemsProcessed(state.iterations() * num_threads * kOpsPerThread);
}
BENCHMARK(BM_SkipListConcurrentInsert)->Arg(1)->Arg(2)->Arg(4)->Arg(8)->Unit(benchmark::kMillisecond);

// Mixed read/write benchmark
static void BM_SkipListMixedReadWrite(benchmark::State &state)
{
        constexpr int kOpsPerThread = 5000;
        constexpr int kReadRatio = 80; // 80% reads, 20% writes
        const int num_threads = state.range(0);

        for (auto _ : state)
        {
                state.PauseTiming();
                Arena arena;
                SkipList list(&arena);

                // Pre-populate with some data
                for (int i = 0; i < 10000; i++)
                {
                        std::string key = make_key(i);
                        InternalKey ikey(Slice(key), i, KeyType::Put);
                        list.insert(ikey, Slice("value"));
                }

                std::vector<std::thread> threads;
                std::atomic<int> write_counter{10000};
                state.ResumeTiming();

                for (int t = 0; t < num_threads; t++)
                {
                        threads.emplace_back(
                            [&list, &write_counter, t]()
                            {
                                    std::mt19937 rng(t);
                                    std::uniform_int_distribution<int> op_dist(0, 99);
                                    std::uniform_int_distribution<int> key_dist(0, 9999);

                                    for (int i = 0; i < kOpsPerThread; i++)
                                    {
                                            if (op_dist(rng) < kReadRatio)
                                            {
                                                    std::string key = make_key(key_dist(rng));
                                                    std::string value;
                                                    benchmark::DoNotOptimize(list.get(Slice(key), &value));
                                            }
                                            else
                                            {
                                                    int idx = write_counter.fetch_add(1);
                                                    std::string key = make_key(idx);
                                                    InternalKey ikey(Slice(key), idx, KeyType::Put);
                                                    list.insert(ikey, Slice("value"));
                                            }
                                    }
                            });
                }
                for (auto &t : threads)
                {
                        t.join();
                }
        }
        state.SetItemsProcessed(state.iterations() * num_threads * kOpsPerThread);
}
BENCHMARK(BM_SkipListMixedReadWrite)->Arg(1)->Arg(2)->Arg(4)->Arg(8)->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
