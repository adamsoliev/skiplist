# Fuzzing Testing Infrastructure Spec

## Overview

This specification outlines the adoption of RocksDB-style fuzzing testing infrastructure for the minilsm skiplist implementation. Fuzzing will complement existing unit tests (61 tests), concurrent stress tests, and sanitizer runs to discover edge cases and potential bugs in the lock-free concurrent skiplist implementation.

## Motivation

1. **Lock-free code is notoriously hard to test** - The skiplist uses CAS-based concurrent insertions with acquire/release memory semantics. Traditional unit tests may miss subtle race conditions.

2. **Complex memory layout** - Nodes use inline storage with negative-offset next pointers. Memory corruption bugs are easy to introduce and hard to detect.

3. **RocksDB's success** - RocksDB uses continuous fuzzing via OSS-Fuzz and has caught numerous bugs. Since minilsm is modeled after RocksDB internals, adopting their testing strategy is natural.

4. **Coverage gaps** - Current tests use predetermined inputs. Fuzzing generates unexpected inputs that may trigger undiscovered edge cases.

---

## Lessons Learned from Industry Experience

Based on research into RocksDB's testing evolution, Google's OSS-Fuzz program (13,000+ vulnerabilities found across 1,000+ projects), and Ada Logics' experience integrating 100+ projects:

### What Works

| Practice | Evidence |
|----------|----------|
| **Narrow, focused fuzz targets** | Broad targets overwhelm fuzzers; narrow targets achieve thorough coverage quickly |
| **Structure-aware fuzzing** | libprotobuf-mutator finds bugs faster for complex inputs than raw byte fuzzing |
| **Continuous fuzzing** | Bugs are found incrementally; one-off runs miss regressions |
| **Complementary testing layers** | RocksDB uses unit tests + stress tests (db_stress) + fuzz tests as distinct layers |
| **Developer ownership** | 46% of OSS-Fuzz bugs are fixed by the same developer who introduced them |

### What to Avoid

| Anti-Pattern | Problem |
|--------------|---------|
| **"Checkbox security" mindset** | OSS-Fuzz integration is not a guarantee; most projects plateau at ~30% coverage |
| **Monolithic fuzz targets** | APIs with >20-30k reachable control flow edges should be split |
| **Reusing input data** | FuzzedDataProvider prevents accidental data reuse; raw byte slicing does not |
| **Non-determinism** | Random decisions not derived from input bytes make fuzzing inefficient |
| **Debug output** | Writing to stderr/stdout dramatically slows execution |
| **Ignoring harness maintenance** | Fuzz harnesses degrade as APIs evolve; they need updates |

### Performance Baselines

| Metric | Target | Red Flag |
|--------|--------|----------|
| Execution speed | 1,000+ exec/s | <10 exec/s indicates fundamental problems |
| Memory per core | <1.5 GB | OOM bugs slow fuzzing dramatically |
| Lightweight targets | 10,000+ exec/s | Simple parsers should be fast |

---

## Critical: Arena Allocator Considerations

**The arena allocator can hide bugs from AddressSanitizer.**

Arena-type custom memory allocators (CMAs) internally allocate a large chunk and sub-allocate from it. ASan only places redzones around the base chunk, not individual allocations. This means:

- Buffer overflows between arena objects go undetected
- Use-after-free within the arena is invisible
- Double-free within the arena is invisible

### Mitigations

1. **Dedicated arena fuzzer with bypass mode**:
```cpp
// In arena.hpp, add a fuzzing mode
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Bypass arena, use direct malloc for each allocation
    // This lets ASan see every allocation boundary
    char* allocate(size_t size) {
        return static_cast<char*>(malloc(size));
    }
#endif
```

2. **Memory poisoning pattern** (0xDEADBEEF on free):
```cpp
void Arena::debug_poison_chunk(char* ptr, size_t size) {
    memset(ptr, 0xDE, size);  // Detectable pattern on use-after-free
}
```

3. **Bounds checking with UBSan** - Even without ASan detecting overflows, UBSan can catch undefined behavior from corrupted data.

---

## Complementary Testing Strategy

Following RocksDB's multi-layer approach:

```
┌─────────────────────────────────────────────────────────────┐
│                    Testing Pyramid                           │
├─────────────────────────────────────────────────────────────┤
│  Unit Tests (61 tests)                                       │
│  - Deterministic                                             │
│  - Single functionality                                      │
│  - Fast feedback                                             │
├─────────────────────────────────────────────────────────────┤
│  Stress Tests (like RocksDB's db_stress)                     │
│  - Randomized operations                                     │
│  - Feature combinations                                      │
│  - Crash injection (kill -9, white-box crash points)         │
│  - Data validation against external oracle                   │
├─────────────────────────────────────────────────────────────┤
│  Fuzz Tests                                                  │
│  - Coverage-guided input generation                          │
│  - Edge case discovery                                       │
│  - Sanitizer integration (ASan, UBSan, TSan, MSan)           │
│  - Continuous execution                                      │
└─────────────────────────────────────────────────────────────┘
```

### When Each Layer Shines

| Layer | Best For |
|-------|----------|
| Unit tests | Known invariants, API contracts, regression tests |
| Stress tests | Correctness at scale, crash recovery, feature interactions |
| Fuzz tests | Unknown edge cases, malformed inputs, memory safety |

---

## Background: RocksDB's Fuzzing Infrastructure

RocksDB's fuzzing infrastructure consists of:

### Directory Structure
```
rocksdb/
├── fuzz/
│   ├── Makefile
│   ├── README.md
│   ├── proto/                    # Protobuf definitions for structured fuzzing
│   │   └── db_operation.proto
│   ├── db_fuzzer.cc              # Database operations fuzzer
│   ├── db_map_fuzzer.cc          # Database mapping fuzzer
│   ├── sst_file_writer_fuzzer.cc # SST file writer fuzzer
│   └── util.h                    # Shared utilities
```

### Key Components

1. **LLVM libFuzzer** - Coverage-guided fuzzing engine
2. **libprotobuf-mutator** - Structure-aware mutations using Protocol Buffers
3. **OSS-Fuzz Integration** - Continuous fuzzing on Google's infrastructure
4. **Sanitizer Integration** - ASan, UBSan, TSan for bug detection

---

## Proposed Implementation

### Phase 1: Basic libFuzzer Integration

#### Directory Structure
```
skiplist/
├── fuzz/
│   ├── Makefile
│   ├── README.md
│   ├── skiplist_fuzzer.cc        # Basic skiplist operations fuzzer
│   ├── arena_fuzzer.cc           # Arena allocator fuzzer (with bypass mode)
│   ├── iterator_fuzzer.cc        # Iterator operations fuzzer
│   ├── dictionaries/             # Token dictionaries for efficiency
│   │   └── skiplist.dict
│   └── corpus/                   # Seed corpus directory
│       ├── skiplist/
│       ├── arena/
│       └── iterator/
```

#### Fuzz Target: skiplist_fuzzer.cc

```cpp
// DESIGN NOTES:
// - Narrow focus: only skiplist insert/get/iterate
// - Uses FuzzedDataProvider to prevent input reuse
// - Limits iteration to prevent timeouts
// - No debug output
// - Deterministic (no random not from input)

#include "../src/skiplist.hpp"
#include "../src/arena.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

using namespace minilsm;

// Limit operations to maintain >1000 exec/s
static constexpr size_t kMaxOps = 100;
static constexpr size_t kMaxKeySize = 256;
static constexpr size_t kMaxValueSize = 1024;
static constexpr size_t kMaxIterSteps = 50;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    FuzzedDataProvider provider(data, size);

    // Fresh arena per run - no state leakage
    Arena arena;
    SkipList list(&arena);

    size_t ops = 0;
    while (provider.remaining_bytes() > 0 && ops++ < kMaxOps) {
        uint8_t op = provider.ConsumeIntegral<uint8_t>() % 4;

        switch (op) {
            case 0: { // Insert
                auto key_data = provider.ConsumeRandomLengthString(kMaxKeySize);
                auto value_data = provider.ConsumeRandomLengthString(kMaxValueSize);
                uint64_t seq = provider.ConsumeIntegral<uint64_t>();
                KeyType type = static_cast<KeyType>(
                    provider.ConsumeIntegral<uint8_t>() % 6);

                InternalKey key(Slice(key_data.data(), key_data.size()), seq, type);
                list.insert(key, Slice(value_data.data(), value_data.size()));
                break;
            }
            case 1: { // Get
                auto key_data = provider.ConsumeRandomLengthString(kMaxKeySize);
                std::string result;
                list.get(Slice(key_data.data(), key_data.size()), &result);
                break;
            }
            case 2: { // Iterator forward (bounded)
                auto key_data = provider.ConsumeRandomLengthString(kMaxKeySize);
                auto it = list.new_iterator();
                it.seek(Slice(key_data.data(), key_data.size()));
                for (size_t i = 0; i < kMaxIterSteps && it.valid(); i++) {
                    (void)it.key();
                    (void)it.value();
                    it.next();
                }
                break;
            }
            case 3: { // Iterator reverse (bounded)
                auto it = list.new_iterator();
                it.seek_to_last();
                for (size_t i = 0; i < kMaxIterSteps && it.valid(); i++) {
                    (void)it.key();
                    (void)it.value();
                    it.prev();
                }
                break;
            }
        }
    }

    return 0;  // Always return 0; non-zero reserved for future use
}
```

#### Fuzz Target: arena_fuzzer.cc (with ASan bypass)

```cpp
// DESIGN NOTES:
// - Tests arena allocator edge cases
// - Uses FUZZING_BUILD_MODE to bypass arena for ASan visibility
// - Tests alignment, large allocations, concurrent access patterns

#include "../src/arena.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

using namespace minilsm;

static constexpr size_t kMaxAllocSize = 128 * 1024;  // 128KB max
static constexpr size_t kMaxAllocs = 200;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    FuzzedDataProvider provider(data, size);
    Arena arena;

    size_t allocs = 0;
    while (provider.remaining_bytes() > 0 && allocs++ < kMaxAllocs) {
        size_t alloc_size = provider.ConsumeIntegralInRange<size_t>(1, kMaxAllocSize);
        char* ptr = arena.allocate(alloc_size);

        if (ptr) {
            // Write pattern to detect buffer overflows
            memset(ptr, static_cast<char>(alloc_size & 0xFF), alloc_size);

            // Verify we can read back
            volatile char check = ptr[0];
            (void)check;

            if (alloc_size > 1) {
                volatile char check_end = ptr[alloc_size - 1];
                (void)check_end;
            }
        }
    }

    // Arena destructor frees everything - no cleanup needed
    return 0;
}
```

#### Dictionary: dictionaries/skiplist.dict

```
# Key types
"Put"
"Delete"
"RangePut"
"RangeDelete"
"Update"
"RangeUpdate"

# Common key patterns
"key"
"user"
"test"
"\x00"
"\xFF"
"\x00\x00\x00\x00"
"\xFF\xFF\xFF\xFF"

# Sequence number boundaries
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"

# Size boundaries
"\x00"
"\x01"
```

#### Makefile (improved)

```makefile
CXX := clang++
CXXFLAGS := -std=c++17 -g -O2 -fno-omit-frame-pointer
FUZZ_FLAGS := -fsanitize=fuzzer,address,undefined
TSAN_FLAGS := -fsanitize=fuzzer,thread
INCLUDES := -I../src

# Performance: aim for >1000 exec/s
FUZZ_OPTS := -max_len=4096 -timeout=30 -rss_limit_mb=2048

FUZZERS := skiplist_fuzzer arena_fuzzer iterator_fuzzer
TSAN_FUZZERS := concurrent_fuzzer

.PHONY: all clean tsan coverage

all: $(FUZZERS)

tsan: $(TSAN_FUZZERS)

%_fuzzer: %_fuzzer.cc
	$(CXX) $(CXXFLAGS) $(FUZZ_FLAGS) $(INCLUDES) $< -o $@

concurrent_fuzzer: concurrent_fuzzer.cc
	$(CXX) $(CXXFLAGS) $(TSAN_FLAGS) $(INCLUDES) $< -o $@

clean:
	rm -f $(FUZZERS) $(TSAN_FUZZERS) crash-* oom-* timeout-* slow-unit-*

# Run with corpus and dictionary
run_%: %
	mkdir -p corpus/$*
	./$* $(FUZZ_OPTS) -dict=dictionaries/skiplist.dict corpus/$*/

# Quick smoke test (60 seconds each)
quick: $(FUZZERS)
	@for f in $(FUZZERS); do \
		echo "=== Running $$f for 60s ==="; \
		mkdir -p corpus/$$f; \
		./$$f -max_total_time=60 $(FUZZ_OPTS) corpus/$$f/ 2>&1 | tail -10; \
	done

# Minimize corpus (run periodically)
minimize_%: %
	mkdir -p corpus/$*_min
	./$* -merge=1 corpus/$*_min/ corpus/$*/
	rm -rf corpus/$*
	mv corpus/$*_min corpus/$*

# Coverage report
coverage:
	@echo "Build with coverage and run fuzzers to generate coverage data"
	@echo "Then use llvm-cov to generate reports"
```

### Phase 2: Structure-Aware Fuzzing with Protobuf

Use libprotobuf-mutator for more intelligent mutations. This is particularly valuable when:
- Inputs have complex structure (operation sequences)
- Certain operation orderings are more interesting
- We want to test specific invariants

#### Proto Definition: fuzz/proto/skiplist_ops.proto

```protobuf
syntax = "proto3";
package skiplist_fuzz;

enum KeyType {
    PUT = 0;
    DELETE = 1;
    RANGE_PUT = 2;
    RANGE_DELETE = 3;
    UPDATE = 4;
    RANGE_UPDATE = 5;
}

message Key {
    bytes user_key = 1;
    uint64 sequence = 2;
    KeyType type = 3;
}

message InsertOp {
    Key key = 1;
    bytes value = 2;
}

message GetOp {
    bytes user_key = 1;
}

message SeekOp {
    bytes target = 1;
    bool reverse = 2;
    uint32 steps = 3;  // Bounded by post-processor
}

message Operation {
    oneof op {
        InsertOp insert = 1;
        GetOp get = 2;
        SeekOp seek = 3;
    }
}

message SkipListOperations {
    repeated Operation operations = 1;
}
```

#### Structure-Aware Fuzzer: fuzz/skiplist_proto_fuzzer.cc

```cpp
#include "../src/skiplist.hpp"
#include "../src/arena.hpp"
#include "proto/skiplist_ops.pb.h"
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

using namespace minilsm;

// Enforce constraints to maintain performance
static constexpr size_t kMaxOps = 100;
static constexpr size_t kMaxKeySize = 256;
static constexpr size_t kMaxValueSize = 4096;
static constexpr size_t kMaxIterSteps = 50;

// Post-processor: normalize inputs to valid ranges
static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    skiplist_fuzz::SkipListOperations> reg = {
    [](skiplist_fuzz::SkipListOperations* ops, unsigned int seed) {
        // Ensure at least one operation for meaningful test
        if (ops->operations_size() == 0) {
            ops->add_operations()->mutable_insert();
        }

        // Limit operation count for performance
        while (static_cast<size_t>(ops->operations_size()) > kMaxOps) {
            ops->mutable_operations()->RemoveLast();
        }

        // Normalize each operation
        for (auto& op : *ops->mutable_operations()) {
            if (op.has_insert()) {
                auto* insert = op.mutable_insert();
                if (insert->key().user_key().size() > kMaxKeySize) {
                    insert->mutable_key()->set_user_key(
                        insert->key().user_key().substr(0, kMaxKeySize));
                }
                if (insert->value().size() > kMaxValueSize) {
                    insert->set_value(insert->value().substr(0, kMaxValueSize));
                }
            } else if (op.has_seek()) {
                auto* seek = op.mutable_seek();
                if (seek->steps() > kMaxIterSteps) {
                    seek->set_steps(kMaxIterSteps);
                }
                if (seek->target().size() > kMaxKeySize) {
                    seek->set_target(seek->target().substr(0, kMaxKeySize));
                }
            } else if (op.has_get()) {
                auto* get = op.mutable_get();
                if (get->user_key().size() > kMaxKeySize) {
                    get->set_user_key(get->user_key().substr(0, kMaxKeySize));
                }
            }
        }
    }
};

DEFINE_PROTO_FUZZER(const skiplist_fuzz::SkipListOperations& input) {
    Arena arena;
    SkipList list(&arena);

    for (const auto& op : input.operations()) {
        if (op.has_insert()) {
            const auto& ins = op.insert();
            InternalKey key(
                Slice(ins.key().user_key().data(), ins.key().user_key().size()),
                ins.key().sequence(),
                static_cast<KeyType>(ins.key().type() % 6));
            list.insert(key, Slice(ins.value().data(), ins.value().size()));
        } else if (op.has_get()) {
            std::string result;
            list.get(Slice(op.get().user_key().data(),
                          op.get().user_key().size()), &result);
        } else if (op.has_seek()) {
            auto it = list.new_iterator();
            it.seek(Slice(op.seek().target().data(), op.seek().target().size()));

            for (uint32_t i = 0; i < op.seek().steps() && it.valid(); i++) {
                (void)it.key();
                (void)it.value();
                if (op.seek().reverse()) {
                    it.prev();
                } else {
                    it.next();
                }
            }
        }
    }
}
```

### Phase 3: Concurrent Fuzzing with ThreadSanitizer

ThreadSanitizer in happens-before mode has **no false positives** for correctly synchronized code. This is critical for validating lock-free implementations.

#### Concurrent Fuzzer: fuzz/concurrent_fuzzer.cc

```cpp
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
        size_t chunk_size = provider.remaining_bytes() / (num_threads - t);
        auto thread_data = provider.ConsumeBytes<uint8_t>(chunk_size);

        threads.emplace_back([&list, thread_data, &start, &ready, num_threads]() {
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
                        auto key_data = tp.ConsumeRandomLengthString(64);
                        auto value_data = tp.ConsumeRandomLengthString(128);
                        uint64_t seq = tp.ConsumeIntegral<uint64_t>();

                        InternalKey key(Slice(key_data.data(), key_data.size()),
                                       seq, KeyType::Put);
                        list.insert(key, Slice(value_data.data(), value_data.size()));
                        break;
                    }
                    case 1: { // Get
                        auto key_data = tp.ConsumeRandomLengthString(64);
                        std::string result;
                        list.get(Slice(key_data.data(), key_data.size()), &result);
                        break;
                    }
                    case 2: { // Iterate
                        auto it = list.new_iterator();
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
```

### Phase 4: CI/CD Integration with Coverage Monitoring

#### GitHub Actions: .github/workflows/fuzz.yml

```yaml
name: Fuzz Testing

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours for continuous fuzzing

jobs:
  fuzz-asan:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        fuzzer: [skiplist_fuzzer, arena_fuzzer, iterator_fuzzer]

    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm

      - name: Restore corpus
        uses: actions/cache@v4
        with:
          path: fuzz/corpus/${{ matrix.fuzzer }}
          key: fuzz-corpus-${{ matrix.fuzzer }}-${{ github.sha }}
          restore-keys: |
            fuzz-corpus-${{ matrix.fuzzer }}-

      - name: Build fuzzer
        run: |
          cd fuzz
          make ${{ matrix.fuzzer }}

      - name: Run fuzzer (5 minutes)
        run: |
          mkdir -p fuzz/corpus/${{ matrix.fuzzer }}
          cd fuzz
          ./${{ matrix.fuzzer }} \
            -max_total_time=300 \
            -max_len=4096 \
            -timeout=30 \
            -rss_limit_mb=2048 \
            -print_final_stats=1 \
            -dict=dictionaries/skiplist.dict \
            corpus/${{ matrix.fuzzer }}/

      - name: Save corpus
        uses: actions/cache/save@v4
        if: always()
        with:
          path: fuzz/corpus/${{ matrix.fuzzer }}
          key: fuzz-corpus-${{ matrix.fuzzer }}-${{ github.sha }}

      - name: Upload crashes
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: crashes-${{ matrix.fuzzer }}
          path: |
            fuzz/crash-*
            fuzz/oom-*
            fuzz/timeout-*
            fuzz/slow-unit-*

  fuzz-tsan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm

      - name: Build concurrent fuzzer with TSan
        run: |
          cd fuzz
          make tsan

      - name: Run concurrent fuzzer (5 minutes)
        run: |
          mkdir -p fuzz/corpus/concurrent
          cd fuzz
          ./concurrent_fuzzer \
            -max_total_time=300 \
            -max_len=4096 \
            -timeout=60 \
            -print_final_stats=1 \
            corpus/concurrent/

      - name: Upload TSan reports
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: tsan-reports
          path: fuzz/crash-*

  coverage-report:
    runs-on: ubuntu-latest
    needs: [fuzz-asan]
    if: github.event_name == 'schedule'  # Only on scheduled runs
    steps:
      - uses: actions/checkout@v4

      - name: Build with coverage
        run: |
          cd fuzz
          CXX=clang++ CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping" make all

      - name: Run fuzzers for coverage
        run: |
          cd fuzz
          for f in skiplist_fuzzer arena_fuzzer iterator_fuzzer; do
            LLVM_PROFILE_FILE="$f.profraw" ./$f -runs=10000 corpus/$f/
          done

      - name: Generate coverage report
        run: |
          cd fuzz
          llvm-profdata merge -sparse *.profraw -o coverage.profdata
          llvm-cov report ./skiplist_fuzzer -instr-profile=coverage.profdata
```

### Phase 5: OSS-Fuzz Integration (Future)

For continuous fuzzing on Google's infrastructure at scale.

#### oss-fuzz/projects/minilsm/Dockerfile

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    make \
    pkg-config

RUN git clone --depth 1 https://github.com/adamsoliev/skiplist.git minilsm

WORKDIR minilsm
COPY build.sh $SRC/
```

#### oss-fuzz/projects/minilsm/build.sh

```bash
#!/bin/bash -eu

# Use OSS-Fuzz provided compiler and flags
# This builds with multiple sanitizers and fuzzing engines

cd $SRC/minilsm

# Build fuzzers using OSS-Fuzz environment variables
cd fuzz
for fuzzer in skiplist_fuzzer arena_fuzzer iterator_fuzzer; do
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        -std=c++17 \
        -I../src \
        ${fuzzer}.cc \
        -o $OUT/${fuzzer}

    # Copy seed corpus if exists
    if [ -d "corpus/${fuzzer}" ]; then
        zip -j $OUT/${fuzzer}_seed_corpus.zip corpus/${fuzzer}/*
    fi

    # Copy dictionary if exists
    if [ -f "dictionaries/skiplist.dict" ]; then
        cp dictionaries/skiplist.dict $OUT/${fuzzer}.dict
    fi
done
```

#### oss-fuzz/projects/minilsm/project.yaml

```yaml
homepage: "https://github.com/adamsoliev/skiplist"
language: c++
primary_contact: "maintainer@example.com"
sanitizers:
  - address
  - undefined
  - memory
architectures:
  - x86_64
fuzzing_engines:
  - libfuzzer
  - afl
  - honggfuzz
main_repo: "https://github.com/adamsoliev/skiplist"
vendor_ccs:
  - "security-team@example.com"
```

---

## Coverage Optimization

### Diagnosing Coverage Plateaus

If corpus stops growing, use these techniques:

1. **Check execution speed**: `./fuzzer -runs=100000 corpus/` should show >1000 exec/s
2. **Analyze coverage**: Build with `-fprofile-instr-generate -fcoverage-mapping`
3. **Use Fuzz Introspector**: Identifies blocker functions and unreached code

### Corpus Management

```bash
# Minimize corpus (removes redundant inputs)
./skiplist_fuzzer -merge=1 corpus_min/ corpus/

# Progressive size fuzzing (start small)
for size in 64 256 1024 4096; do
    ./skiplist_fuzzer -max_len=$size -max_total_time=300 corpus/
done
./skiplist_fuzzer -merge=1 corpus/ corpus/  # Combine
```

### When to Split Targets

If a fuzz target has >20,000-30,000 reachable control flow edges, split it:

- `skiplist_insert_fuzzer` - Insert-only operations
- `skiplist_iterator_fuzzer` - Iterator-only operations
- `skiplist_mixed_fuzzer` - Mixed operations (current)

---

## Build & Run Instructions

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm pkg-config

# For structure-aware fuzzing (Phase 2)
sudo apt-get install protobuf-compiler libprotobuf-dev

# Install libprotobuf-mutator
git clone https://github.com/google/libprotobuf-mutator.git
cd libprotobuf-mutator
mkdir build && cd build
cmake .. -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
ninja
sudo ninja install
```

### Building Fuzzers

```bash
cd fuzz
make all        # ASan/UBSan fuzzers
make tsan       # TSan concurrent fuzzer
```

### Running Fuzzers

```bash
# Basic run with dictionary
./skiplist_fuzzer -dict=dictionaries/skiplist.dict corpus/skiplist/

# Time-limited run
./skiplist_fuzzer -max_total_time=3600 corpus/skiplist/

# Parallel fuzzing (N workers)
./skiplist_fuzzer -jobs=4 -workers=4 corpus/skiplist/

# Minimize corpus
./skiplist_fuzzer -merge=1 corpus_min/ corpus/skiplist/
```

### Reproducing Crashes

```bash
# Reproduce a specific crash
./skiplist_fuzzer crash-<hash>

# Get detailed backtrace
ASAN_OPTIONS=symbolize=1 ./skiplist_fuzzer crash-<hash>

# Minimize crash input
./skiplist_fuzzer -minimize_crash=1 -max_total_time=60 crash-<hash>
```

---

## Makefile Integration

Add to existing Makefile:

```makefile
# Fuzzing targets
.PHONY: fuzz fuzz-quick fuzz-tsan fuzz-clean fuzz-coverage

fuzz:
	$(MAKE) -C fuzz all

fuzz-quick:
	$(MAKE) -C fuzz quick

fuzz-tsan:
	$(MAKE) -C fuzz tsan
	cd fuzz && ./concurrent_fuzzer -max_total_time=300 corpus/concurrent/

fuzz-clean:
	$(MAKE) -C fuzz clean

fuzz-coverage:
	$(MAKE) -C fuzz coverage
```

---

## Expected Impact

| Benefit | Description |
|---------|-------------|
| Bug Discovery | Catch memory corruption, use-after-free, buffer overflows |
| Race Conditions | TSan-based concurrent fuzzer finds data races |
| Edge Cases | Coverage-guided exploration finds unexpected inputs |
| Regression Prevention | Corpus grows over time, ensuring old bugs don't return |
| Security | Proactive vulnerability discovery before production |

---

## Implementation Order

| Phase | Focus | Effort | Impact |
|-------|-------|--------|--------|
| **Phase 1** | Basic libFuzzer + dictionaries | 1-2 days | High |
| **Phase 2** | Structure-aware (protobuf) | 2-3 days | Medium |
| **Phase 3** | Concurrent fuzzer (TSan) | 1 day | High for lock-free code |
| **Phase 4** | CI/CD + coverage monitoring | 1 day | Continuous value |
| **Phase 5** | OSS-Fuzz submission | 1 day | Long-term continuous |

---

## References

### Primary Sources
- [RocksDB Fuzz Test Wiki](https://github.com/facebook/rocksdb/wiki/Fuzz-Test)
- [RocksDB Stress Test Wiki](https://github.com/facebook/rocksdb/wiki/Stress-test)
- [RocksDB fuzz directory](https://github.com/facebook/rocksdb/tree/main/fuzz)
- [Google: Good Fuzz Target](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)

### Fuzzing Infrastructure
- [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator)
- [OSS-Fuzz New Project Guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)
- [Fuzz Introspector](https://github.com/ossf/fuzz-introspector)

### Lessons Learned
- [Fuzzing 100+ Projects with OSS-Fuzz](https://adalogics.com/blog/fuzzing-100-open-source-projects-with-oss-fuzz)
- [Empirical Study of OSS-Fuzz Bugs](https://arxiv.org/abs/2103.11518)
- [Custom Memory Allocators Hide Bugs](https://blog.fuzzing-project.org/65-When-your-Memory-Allocator-hides-Security-Bugs.html)

### Concurrency
- [ThreadSanitizer in Practice](https://www.researchgate.net/publication/234779363_ThreadSanitizer_-_Data_race_detection_in_practice)
- [Comparison: TSan vs Thread Fuzzing](https://undo.io/resources/threadsanitizer-or-thread-fuzzing/)
