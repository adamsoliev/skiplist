# Fuzzing Testing Infrastructure Spec

## Overview

This specification outlines the adoption of RocksDB-style fuzzing testing infrastructure for the minilsm skiplist implementation. Fuzzing will complement existing unit tests (61 tests), concurrent stress tests, and sanitizer runs to discover edge cases and potential bugs in the lock-free concurrent skiplist implementation.

## Motivation

1. **Lock-free code is notoriously hard to test** - The skiplist uses CAS-based concurrent insertions with acquire/release memory semantics. Traditional unit tests may miss subtle race conditions.

2. **Complex memory layout** - Nodes use inline storage with negative-offset next pointers. Memory corruption bugs are easy to introduce and hard to detect.

3. **RocksDB's success** - RocksDB uses continuous fuzzing via OSS-Fuzz and has caught numerous bugs. Since minilsm is modeled after RocksDB internals, adopting their testing strategy is natural.

4. **Coverage gaps** - Current tests use predetermined inputs. Fuzzing generates unexpected inputs that may trigger undiscovered edge cases.

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

### Fuzz Target Structure

```cpp
// Basic libFuzzer target
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    DoSomethingWithAPI(data, size);
    return 0;
}

// Structure-aware target with protobuf
DEFINE_PROTO_FUZZER(const DbOperations& input) {
    for (const auto& op : input.operations()) {
        ExecuteOperation(op);
    }
}
```

## Proposed Implementation

### Phase 1: Basic libFuzzer Integration

#### Directory Structure
```
skiplist/
├── fuzz/
│   ├── Makefile
│   ├── README.md
│   ├── skiplist_fuzzer.cc        # Basic skiplist operations fuzzer
│   ├── arena_fuzzer.cc           # Arena allocator fuzzer
│   ├── iterator_fuzzer.cc        # Iterator operations fuzzer
│   └── corpus/                   # Seed corpus directory
│       └── minimal_seeds/
```

#### Fuzz Target: skiplist_fuzzer.cc

```cpp
#include "../src/skiplist.hpp"
#include "../src/arena.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

using namespace minilsm;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    FuzzedDataProvider provider(data, size);
    Arena arena;
    SkipList list(&arena);

    while (provider.remaining_bytes() > 0) {
        uint8_t op = provider.ConsumeIntegral<uint8_t>() % 4;

        switch (op) {
            case 0: { // Insert
                auto key_data = provider.ConsumeRandomLengthString(256);
                auto value_data = provider.ConsumeRandomLengthString(1024);
                uint64_t seq = provider.ConsumeIntegral<uint64_t>();
                KeyType type = static_cast<KeyType>(
                    provider.ConsumeIntegral<uint8_t>() % 6);

                InternalKey key(Slice(key_data.data(), key_data.size()), seq, type);
                list.insert(key, Slice(value_data.data(), value_data.size()));
                break;
            }
            case 1: { // Get
                auto key_data = provider.ConsumeRandomLengthString(256);
                std::string result;
                list.get(Slice(key_data.data(), key_data.size()), &result);
                break;
            }
            case 2: { // Iterator seek
                auto key_data = provider.ConsumeRandomLengthString(256);
                auto it = list.new_iterator();
                it.seek(Slice(key_data.data(), key_data.size()));
                while (it.valid()) {
                    it.key();
                    it.value();
                    it.next();
                }
                break;
            }
            case 3: { // Iterator reverse
                auto it = list.new_iterator();
                it.seek_to_last();
                while (it.valid()) {
                    it.key();
                    it.value();
                    it.prev();
                }
                break;
            }
        }
    }

    return 0;
}
```

#### Fuzz Target: arena_fuzzer.cc

```cpp
#include "../src/arena.hpp"
#include <cstdint>
#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>

using namespace minilsm;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    FuzzedDataProvider provider(data, size);
    Arena arena;

    while (provider.remaining_bytes() > 0) {
        // Allocate random sizes up to 16KB
        size_t alloc_size = provider.ConsumeIntegralInRange<size_t>(1, 16384);
        char* ptr = arena.allocate(alloc_size);

        if (ptr) {
            // Write to allocated memory to catch buffer overflows
            memset(ptr, 0xAB, alloc_size);
        }
    }

    return 0;
}
```

#### Makefile

```makefile
CXX := clang++
CXXFLAGS := -std=c++17 -g -O2 -fno-omit-frame-pointer
FUZZ_FLAGS := -fsanitize=fuzzer,address,undefined
INCLUDES := -I../src

FUZZERS := skiplist_fuzzer arena_fuzzer iterator_fuzzer

.PHONY: all clean

all: $(FUZZERS)

%_fuzzer: %_fuzzer.cc
	$(CXX) $(CXXFLAGS) $(FUZZ_FLAGS) $(INCLUDES) $< -o $@

clean:
	rm -f $(FUZZERS) crash-* oom-* timeout-*

# Run fuzzers
run_%: %
	./$< -max_len=4096 -timeout=10 corpus/$*/

# Run all fuzzers briefly
quick_fuzz: $(FUZZERS)
	@for f in $(FUZZERS); do \
		echo "Running $$f for 60 seconds..."; \
		./$$f -max_total_time=60 -max_len=4096 corpus/$$f/ 2>&1 | tail -5; \
	done
```

### Phase 2: Structure-Aware Fuzzing with Protobuf

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
    uint32 steps = 3;
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

// Post-processor to ensure valid key sequences
static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    skiplist_fuzz::SkipListOperations> reg = {
    [](skiplist_fuzz::SkipListOperations* ops, unsigned int seed) {
        // Ensure at least one operation
        if (ops->operations_size() == 0) {
            ops->add_operations();
        }

        // Limit operations to prevent timeout
        while (ops->operations_size() > 1000) {
            ops->mutable_operations()->RemoveLast();
        }

        // Ensure keys are not too large
        for (auto& op : *ops->mutable_operations()) {
            if (op.has_insert()) {
                auto* insert = op.mutable_insert();
                if (insert->key().user_key().size() > 256) {
                    insert->mutable_key()->set_user_key(
                        insert->key().user_key().substr(0, 256));
                }
                if (insert->value().size() > 4096) {
                    insert->set_value(insert->value().substr(0, 4096));
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
                static_cast<KeyType>(ins.key().type()));
            list.insert(key, Slice(ins.value().data(), ins.value().size()));
        } else if (op.has_get()) {
            std::string result;
            list.get(Slice(op.get().user_key().data(),
                          op.get().user_key().size()), &result);
        } else if (op.has_seek()) {
            auto it = list.new_iterator();
            it.seek(Slice(op.seek().target().data(), op.seek().target().size()));

            uint32_t steps = op.seek().steps() % 100;
            for (uint32_t i = 0; i < steps && it.valid(); i++) {
                it.key();
                it.value();
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

### Phase 3: Concurrent Fuzzing

#### Concurrent Fuzzer: fuzz/concurrent_fuzzer.cc

```cpp
#include "../src/skiplist.hpp"
#include "../src/arena.hpp"
#include <cstdint>
#include <cstddef>
#include <thread>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

using namespace minilsm;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;

    FuzzedDataProvider provider(data, size);
    Arena arena;
    SkipList list(&arena);

    uint8_t num_threads = provider.ConsumeIntegralInRange<uint8_t>(2, 8);

    std::vector<std::thread> threads;
    std::atomic<bool> start{false};

    for (int t = 0; t < num_threads; t++) {
        auto thread_data = provider.ConsumeBytes<uint8_t>(
            provider.remaining_bytes() / (num_threads - t));

        threads.emplace_back([&list, thread_data, &start, t]() {
            while (!start.load()) {} // Spin until all threads ready

            FuzzedDataProvider tp(thread_data.data(), thread_data.size());

            while (tp.remaining_bytes() > 0) {
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
                        int count = 0;
                        while (it.valid() && count++ < 10) {
                            it.key();
                            it.value();
                            it.next();
                        }
                        break;
                    }
                }
            }
        });
    }

    start.store(true);

    for (auto& t : threads) {
        t.join();
    }

    return 0;
}
```

### Phase 4: CI/CD Integration

#### GitHub Actions: .github/workflows/fuzz.yml

```yaml
name: Fuzz Testing

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight

jobs:
  fuzz:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        fuzzer: [skiplist_fuzzer, arena_fuzzer, iterator_fuzzer]

    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm

      - name: Build fuzzers
        run: |
          cd fuzz
          make ${{ matrix.fuzzer }}

      - name: Download corpus
        uses: actions/cache@v4
        with:
          path: fuzz/corpus/${{ matrix.fuzzer }}
          key: fuzz-corpus-${{ matrix.fuzzer }}-${{ github.sha }}
          restore-keys: |
            fuzz-corpus-${{ matrix.fuzzer }}-

      - name: Run fuzzer
        run: |
          mkdir -p fuzz/corpus/${{ matrix.fuzzer }}
          cd fuzz
          ./${{ matrix.fuzzer }} \
            -max_total_time=300 \
            -max_len=4096 \
            -print_final_stats=1 \
            corpus/${{ matrix.fuzzer }}/

      - name: Upload crashes
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: crashes-${{ matrix.fuzzer }}
          path: |
            fuzz/crash-*
            fuzz/oom-*
            fuzz/timeout-*
```

### Phase 5: OSS-Fuzz Integration (Future)

For continuous fuzzing on Google's infrastructure:

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

# Build the static library
make clean
CXX=$CXX CXXFLAGS="$CXXFLAGS" make static_lib

# Build fuzzers
cd fuzz
for fuzzer in skiplist_fuzzer arena_fuzzer iterator_fuzzer; do
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        -I../src \
        ${fuzzer}.cc \
        -o $OUT/${fuzzer} \
        ../libminilsm.a
done

# Copy seed corpus
cp -r corpus/* $OUT/
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
```

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
make all
```

### Running Fuzzers

```bash
# Run skiplist fuzzer
./skiplist_fuzzer -max_len=4096 corpus/skiplist/

# Run with time limit
./skiplist_fuzzer -max_total_time=3600 corpus/skiplist/

# Run with sanitizers explicitly
./skiplist_fuzzer -detect_leaks=1 corpus/skiplist/

# Minimize corpus
./skiplist_fuzzer -merge=1 corpus/skiplist/ corpus_new/
```

### Reproducing Crashes

```bash
# Reproduce a specific crash
./skiplist_fuzzer crash-<hash>

# Get detailed backtrace
ASAN_OPTIONS=symbolize=1 ./skiplist_fuzzer crash-<hash>
```

## Makefile Integration

Add to existing Makefile:

```makefile
# Fuzzing targets
.PHONY: fuzz fuzz-quick fuzz-clean

fuzz:
	$(MAKE) -C fuzz all

fuzz-quick:
	$(MAKE) -C fuzz quick_fuzz

fuzz-clean:
	$(MAKE) -C fuzz clean
```

## Expected Impact

| Benefit | Description |
|---------|-------------|
| Bug Discovery | Catch memory corruption, use-after-free, buffer overflows |
| Race Conditions | Concurrent fuzzer may find subtle concurrency bugs |
| Edge Cases | Find unexpected inputs that break invariants |
| Regression Prevention | Corpus grows over time, ensuring old bugs don't return |
| Security | Proactively find potential security vulnerabilities |

## Implementation Order

1. **Phase 1** - Basic libFuzzer integration (skiplist_fuzzer, arena_fuzzer)
2. **Phase 2** - Structure-aware fuzzing with protobuf
3. **Phase 3** - Concurrent fuzzer for race condition detection
4. **Phase 4** - CI/CD integration with GitHub Actions
5. **Phase 5** - OSS-Fuzz submission for continuous fuzzing

## References

- [RocksDB Fuzz Test Wiki](https://github.com/facebook/rocksdb/wiki/Fuzz-Test)
- [RocksDB fuzz directory](https://github.com/facebook/rocksdb/tree/main/fuzz)
- [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator)
- [OSS-Fuzz New Project Guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)
- [Google Fuzzing Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
- [Structure-Aware Fuzzing](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md)
