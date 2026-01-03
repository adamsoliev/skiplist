CXX = clang++

# Detect CPU architecture and set appropriate flags
ARCH := $(shell uname -m)
CPU_FLAGS :=

ifeq ($(ARCH),aarch64)
    # Check if running on ARM64/AArch64
    CPU_MODEL := $(shell lscpu | grep -i "model name" | head -1)
    ifneq ($(findstring Neoverse,$(CPU_MODEL)),)
        # Neoverse-specific optimizations
        CPU_FLAGS += -mcpu=neoverse-512tvb -moutline-atomics
    else
        # Generic ARM64 optimizations
        CPU_FLAGS += -march=armv8-a
    endif
else ifeq ($(ARCH),x86_64)
    # x86_64 optimizations - use native for local builds
    CPU_FLAGS += -march=native
endif

CXXFLAGS = -std=c++17 -Wall -Wextra -O3 -g -fno-omit-frame-pointer -pthread $(CPU_FLAGS)
CXXFLAGS_BENCH = -std=c++17 -Wall -Wextra -O3 -DNDEBUG -pthread
LDFLAGS = -pthread

SRC = src/main.cpp
TARGET = skiplist

# Google Test configuration
GTEST_DIR = third_party/googletest
GTEST_BUILD_DIR = $(GTEST_DIR)/build
GTEST_INCLUDE = $(GTEST_DIR)/googletest/include
GTEST_LIB = $(GTEST_BUILD_DIR)/lib

# Google Benchmark configuration
GBENCH_DIR = third_party/benchmark
GBENCH_BUILD_DIR = $(GBENCH_DIR)/build
GBENCH_INCLUDE = $(GBENCH_DIR)/include
GBENCH_LIB = $(GBENCH_BUILD_DIR)/src

# Test configuration
TEST_DIR = tests
TEST_SOURCES = $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJECTS = $(TEST_SOURCES:.cpp=.o)
TEST_TARGET = run_tests

# Benchmark configuration
BENCH_DIR = bench
BENCH_SOURCES = $(BENCH_DIR)/skiplist_bench.cpp
BENCH_OBJECTS = $(BENCH_SOURCES:.cpp=.o)
BENCH_TARGET = run_bench

# Comparative benchmark configuration
COMP_BENCH_SOURCES = $(BENCH_DIR)/comparative_bench.cpp
COMP_BENCH_OBJECTS = $(COMP_BENCH_SOURCES:.cpp=.o)
COMP_BENCH_TARGET = run_comp_bench
REDIS_SKIPLIST_OBJ = third_party/redis/zskiplist.o

# Profiling configuration
PERF = /usr/lib/linux-tools-6.8.0-31/perf
PERF_FREQ = 99
FLAMEGRAPH_DIR = /home/ubuntu/development/FlameGraph
APERF_DIR = /tmp/aperf-v0.1.10-alpha-aarch64
PROFILE_NAME ?= skiplist_profile
REPORT_NAME ?= skiplist_report

# Number of parallel jobs
NPROCS := $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Sanitizer flags
ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer
TSAN_FLAGS = -fsanitize=thread -fno-omit-frame-pointer
UBSAN_FLAGS = -fsanitize=undefined -fno-omit-frame-pointer

.PHONY: all clean test bench comp-bench sanitizers valgrind
.PHONY: format format-check lint compile_commands
.PHONY: perf-record perf-report perf-stat perf-annotate flamegraph aperf-record aperf-report
.PHONY: fuzz fuzz-quick fuzz-tsan fuzz-clean
.PHONY: help

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

# === Dependencies (auto-downloaded) ===

$(GTEST_DIR):
	@echo "Downloading Google Test..."
	@mkdir -p third_party
	@cd third_party && \
		curl -sL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz | tar xz && \
		mv googletest-1.14.0 googletest

$(GTEST_BUILD_DIR)/lib/libgtest.a: $(GTEST_DIR)
	@echo "Building Google Test..."
	@mkdir -p $(GTEST_BUILD_DIR)
	@cd $(GTEST_BUILD_DIR) && \
		cmake .. -DCMAKE_CXX_STANDARD=17 -DBUILD_GMOCK=OFF > /dev/null && \
		make -j$(NPROCS) > /dev/null

$(GBENCH_DIR):
	@echo "Downloading Google Benchmark..."
	@mkdir -p third_party
	@cd third_party && \
		curl -sL https://github.com/google/benchmark/archive/refs/tags/v1.8.3.tar.gz | tar xz && \
		mv benchmark-1.8.3 benchmark

$(GBENCH_BUILD_DIR)/src/libbenchmark.a: $(GBENCH_DIR)
	@echo "Building Google Benchmark..."
	@mkdir -p $(GBENCH_BUILD_DIR)
	@cd $(GBENCH_BUILD_DIR) && \
		cmake .. -DCMAKE_CXX_STANDARD=17 -DCMAKE_BUILD_TYPE=Release \
			-DBENCHMARK_ENABLE_TESTING=OFF -DBENCHMARK_ENABLE_GTEST_TESTS=OFF > /dev/null && \
		make -j$(NPROCS) > /dev/null

# === Testing ===

$(TEST_DIR)/%.o: $(TEST_DIR)/%.cpp $(GTEST_BUILD_DIR)/lib/libgtest.a
	$(CXX) $(CXXFLAGS) -I$(GTEST_INCLUDE) -c $< -o $@

$(TEST_TARGET): $(TEST_OBJECTS) $(GTEST_BUILD_DIR)/lib/libgtest.a
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(TEST_OBJECTS) \
		-L$(GTEST_LIB) -lgtest -lgtest_main

test: $(TEST_TARGET)
	@./$(TEST_TARGET) --gtest_color=yes

# === Sanitizers (ASan + TSan + UBSan) ===

sanitizers: $(GTEST_BUILD_DIR)/lib/libgtest.a
	@echo "=== AddressSanitizer ==="
	@rm -f $(TEST_OBJECTS) $(TEST_TARGET)
	@$(MAKE) --no-print-directory CXXFLAGS="$(CXXFLAGS) $(ASAN_FLAGS)" LDFLAGS="$(LDFLAGS) $(ASAN_FLAGS)" $(TEST_TARGET)
	@ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ./$(TEST_TARGET) --gtest_color=yes
	@rm -f $(TEST_OBJECTS) $(TEST_TARGET)
	@echo ""
	@echo "=== ThreadSanitizer ==="
	@rm -f $(TEST_OBJECTS) $(TEST_TARGET)
	@$(MAKE) --no-print-directory CXXFLAGS="$(CXXFLAGS) $(TSAN_FLAGS)" LDFLAGS="$(LDFLAGS) $(TSAN_FLAGS)" $(TEST_TARGET)
	@TSAN_OPTIONS=second_deadlock_stack=1:abort_on_error=1 ./$(TEST_TARGET) --gtest_color=yes
	@rm -f $(TEST_OBJECTS) $(TEST_TARGET)
	@echo ""
	@echo "=== UndefinedBehaviorSanitizer ==="
	@rm -f $(TEST_OBJECTS) $(TEST_TARGET)
	@$(MAKE) --no-print-directory CXXFLAGS="$(CXXFLAGS) $(UBSAN_FLAGS)" LDFLAGS="$(LDFLAGS) $(UBSAN_FLAGS)" $(TEST_TARGET)
	@UBSAN_OPTIONS=print_stacktrace=1:abort_on_error=1 ./$(TEST_TARGET) --gtest_color=yes
	@rm -f $(TEST_OBJECTS) $(TEST_TARGET)
	@echo ""
	@echo "All sanitizer tests passed!"

valgrind: $(TEST_TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
		--error-exitcode=1 ./$(TEST_TARGET) --gtest_color=no

# === Benchmarks ===

$(BENCH_DIR)/%.o: $(BENCH_DIR)/%.cpp $(GBENCH_BUILD_DIR)/src/libbenchmark.a
	$(CXX) $(CXXFLAGS_BENCH) -I$(GBENCH_INCLUDE) -c $< -o $@

$(BENCH_TARGET): $(BENCH_OBJECTS) $(GBENCH_BUILD_DIR)/src/libbenchmark.a
	$(CXX) $(CXXFLAGS_BENCH) $(LDFLAGS) -o $@ $(BENCH_OBJECTS) \
		-L$(GBENCH_LIB) -lbenchmark -lbenchmark_main

bench: $(BENCH_TARGET)
	@./$(BENCH_TARGET) --benchmark_color=true --benchmark_format=json --benchmark_out=benchmark_results.json

# === Comparative Benchmark ===

# Compile Redis zskiplist C code
$(REDIS_SKIPLIST_OBJ): third_party/redis/zskiplist.c third_party/redis/zskiplist.h
	$(CC) -c -O3 -std=c11 -I third_party/redis -o $@ $<

# Compile comparative benchmark
$(BENCH_DIR)/comparative_bench.o: $(BENCH_DIR)/comparative_bench.cpp $(GBENCH_BUILD_DIR)/src/libbenchmark.a
	$(CXX) $(CXXFLAGS_BENCH) -I$(GBENCH_INCLUDE) -c $< -o $@

# Link comparative benchmark
$(COMP_BENCH_TARGET): $(COMP_BENCH_OBJECTS) $(REDIS_SKIPLIST_OBJ) $(GBENCH_BUILD_DIR)/src/libbenchmark.a
	$(CXX) $(CXXFLAGS_BENCH) $(LDFLAGS) -o $@ $(COMP_BENCH_OBJECTS) $(REDIS_SKIPLIST_OBJ) \
		-L$(GBENCH_LIB) -lbenchmark -lbenchmark_main

comp-bench: $(COMP_BENCH_TARGET)
	@./$(COMP_BENCH_TARGET) --benchmark_color=true --benchmark_format=json --benchmark_out=comp_benchmark_results.json

# === Profiling ===

perf-record: $(TARGET)
	@echo "Recording perf profile at $(PERF_FREQ) Hz..."
	sudo $(PERF) record -g -F $(PERF_FREQ) ./$(TARGET)

perf-report:
	sudo $(PERF) report -g 'graph,0.5,caller'

perf-stat: $(TARGET)
	sudo $(PERF) stat -e cycles,instructions,stalled-cycles-frontend,stalled-cycles-backend,cache-misses,branch-misses ./$(TARGET)

perf-annotate:
	sudo $(PERF) annotate --stdio

flamegraph:
	@test -d $(FLAMEGRAPH_DIR) || (echo "Error: FlameGraph not found at $(FLAMEGRAPH_DIR)" && exit 1)
	sudo $(PERF) script | $(FLAMEGRAPH_DIR)/stackcollapse-perf.pl | $(FLAMEGRAPH_DIR)/flamegraph.pl > flamegraph.svg
	@echo "Generated flamegraph.svg"

aperf-record: $(TARGET)
	@test -x $(APERF_DIR)/aperf || (echo "Error: aperf not found at $(APERF_DIR)" && exit 1)
	sudo $(APERF_DIR)/aperf record -r $(PROFILE_NAME) -i 1 -p 180 --profile

aperf-report:
	sudo $(APERF_DIR)/aperf report -r $(PROFILE_NAME) -n $(REPORT_NAME)
	@echo "Report generated in $(REPORT_NAME)/"

# === Code Quality ===

format:
	@find src tests bench \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) | xargs clang-format -i

format-check:
	@find src tests bench \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) | xargs clang-format --dry-run --Werror

lint:
	@find src \( -name '*.cpp' -o -name '*.hpp' \) | xargs -I {} clang-tidy {} -- -std=c++17

compile_commands: clean
	bear -- $(MAKE) all $(TEST_TARGET)

# === Fuzzing ===

fuzz:
	$(MAKE) -C fuzz all

fuzz-quick:
	$(MAKE) -C fuzz quick

fuzz-tsan:
	$(MAKE) -C fuzz tsan
	cd fuzz && ./concurrent_fuzzer -max_total_time=300 corpus/concurrent/

fuzz-clean:
	$(MAKE) -C fuzz clean

# === Cleanup ===

clean:
	rm -f $(TARGET) $(TEST_TARGET) $(TEST_OBJECTS) $(BENCH_TARGET) $(BENCH_OBJECTS) benchmark_results.json
	rm -f $(COMP_BENCH_TARGET) $(COMP_BENCH_OBJECTS) $(REDIS_SKIPLIST_OBJ) comp_benchmark_results.json
	$(MAKE) -C fuzz clean

distclean: clean
	rm -rf third_party

# === Help ===

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build:"
	@echo "  all          Build main executable (default)"
	@echo "  clean        Remove build artifacts"
	@echo "  distclean    Remove everything including dependencies"
	@echo ""
	@echo "Test:"
	@echo "  test         Run all tests"
	@echo "  sanitizers   Run tests with ASan, TSan, UBSan"
	@echo "  valgrind     Run tests with Valgrind"
	@echo "  bench        Run benchmarks (outputs JSON)"
	@echo "  comp-bench   Run comparative benchmark (minilsm vs RocksDB vs Redis)"
	@echo ""
	@echo "Fuzzing:"
	@echo "  fuzz         Build all fuzzer targets"
	@echo "  fuzz-quick   Run fuzzers for 60s each (smoke test)"
	@echo "  fuzz-tsan    Build and run ThreadSanitizer fuzzer"
	@echo "  fuzz-clean   Remove fuzzer binaries and crash files"
	@echo ""
	@echo "Profile (requires sudo):"
	@echo "  perf-stat    Show CPU counters (cycles, stalls, cache/branch misses)"
	@echo "  perf-record  Record perf profile"
	@echo "  perf-report  Show interactive perf report"
	@echo "  perf-annotate Show annotated assembly from perf.data"
	@echo "  flamegraph   Generate flamegraph.svg"
	@echo "  aperf-record Record aperf profile (PROFILE_NAME=name)"
	@echo "  aperf-report Generate aperf report (REPORT_NAME=name)"
	@echo ""
	@echo "Code quality:"
	@echo "  format       Format source files"
	@echo "  format-check Check formatting"
	@echo "  lint         Run clang-tidy"
