# Fuzzing Infrastructure

This directory contains fuzzing harnesses for the minilsm skiplist implementation, based on RocksDB's fuzzing approach.

## Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm

# Verify installation
clang++ --version  # Should support libFuzzer
```

## Building Fuzzers

```bash
# Build all ASan/UBSan fuzzers
make all

# Build TSan concurrent fuzzer
make tsan
```

## Running Fuzzers

### Basic Usage

```bash
# Run skiplist fuzzer with dictionary
make run_skiplist

# Run arena fuzzer
make run_arena

# Run iterator fuzzer
make run_iterator

# Run concurrent fuzzer (ThreadSanitizer)
make run_concurrent
```

### Quick Smoke Test

```bash
# Run all fuzzers for 60 seconds each
make quick

# Run concurrent fuzzer for 60 seconds
make quick-tsan
```

### Manual Execution

```bash
# Time-limited run
./skiplist_fuzzer -max_total_time=3600 corpus/skiplist/

# Parallel fuzzing (N workers)
./skiplist_fuzzer -jobs=4 -workers=4 corpus/skiplist/

# With dictionary for better coverage
./skiplist_fuzzer -dict=dictionaries/skiplist.dict corpus/skiplist/
```

## Reproducing Crashes

```bash
# Reproduce a specific crash
./skiplist_fuzzer crash-<hash>

# Get detailed backtrace
ASAN_OPTIONS=symbolize=1 ./skiplist_fuzzer crash-<hash>

# Minimize crash input
./skiplist_fuzzer -minimize_crash=1 -max_total_time=60 crash-<hash>
```

## Corpus Management

```bash
# Minimize corpus (removes redundant inputs)
make minimize_skiplist
make minimize_arena
make minimize_iterator
make minimize_concurrent
```

## Fuzzer Descriptions

| Fuzzer | Focus | Sanitizers |
|--------|-------|------------|
| `skiplist_fuzzer` | Insert, get, iteration operations | ASan, UBSan |
| `arena_fuzzer` | Memory allocation patterns | ASan, UBSan |
| `iterator_fuzzer` | Iterator navigation edge cases | ASan, UBSan |
| `concurrent_fuzzer` | Multi-threaded race conditions | TSan |

## Performance Targets

| Metric | Target |
|--------|--------|
| Execution speed | >1000 exec/s |
| Memory per core | <1.5 GB |

If execution speed drops below 10 exec/s, there may be a fundamental issue with the harness.

## Coverage Analysis

```bash
# Build with coverage and generate report
make coverage
```

## Directory Structure

```
fuzz/
├── Makefile
├── README.md
├── skiplist_fuzzer.cc      # Main skiplist operations
├── arena_fuzzer.cc         # Arena allocator
├── iterator_fuzzer.cc      # Iterator operations
├── concurrent_fuzzer.cc    # Thread safety (TSan)
├── dictionaries/
│   └── skiplist.dict       # Token dictionary
└── corpus/                 # Seed corpus (grows over time)
    ├── skiplist/
    ├── arena/
    ├── iterator/
    └── concurrent/
```

## References

- [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [Google Fuzzing Guide](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)
- [RocksDB Fuzz Tests](https://github.com/facebook/rocksdb/tree/main/fuzz)
