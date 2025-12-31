CXX = clang++
CXXFLAGS = -std=c++17 -Wall -Wextra -g -pthread
CXXFLAGS_BENCH = -std=c++17 -Wall -Wextra -O3 -DNDEBUG -pthread
LDFLAGS = -pthread

SRC = src/main.cpp
TARGET = mini-lsm

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
BENCH_SOURCES = $(wildcard $(BENCH_DIR)/*.cpp)
BENCH_OBJECTS = $(BENCH_SOURCES:.cpp=.o)
BENCH_TARGET = run_bench

# Number of parallel test jobs (default to number of CPU cores)
NPROCS := $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

.PHONY: all clean check test gtest gbench bench format format-check lint compile_commands

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Download and build Google Test
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

gtest: $(GTEST_BUILD_DIR)/lib/libgtest.a

# Download and build Google Benchmark
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

gbench: $(GBENCH_BUILD_DIR)/src/libbenchmark.a

# Compile test object files
$(TEST_DIR)/%.o: $(TEST_DIR)/%.cpp $(GTEST_BUILD_DIR)/lib/libgtest.a
	$(CXX) $(CXXFLAGS) -I$(GTEST_INCLUDE) -c $< -o $@

# Link test executable
$(TEST_TARGET): $(TEST_OBJECTS) $(GTEST_BUILD_DIR)/lib/libgtest.a
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(TEST_OBJECTS) \
		-L$(GTEST_LIB) -lgtest -lgtest_main

# Run tests with parallel execution
check: $(TEST_TARGET)
	@echo "Running tests with $(NPROCS) parallel jobs..."
	@./$(TEST_TARGET) --gtest_color=yes

# Alias for check
test: check

# Compile benchmark object files
$(BENCH_DIR)/%.o: $(BENCH_DIR)/%.cpp $(GBENCH_BUILD_DIR)/src/libbenchmark.a
	$(CXX) $(CXXFLAGS_BENCH) -I$(GBENCH_INCLUDE) -c $< -o $@

# Link benchmark executable
$(BENCH_TARGET): $(BENCH_OBJECTS) $(GBENCH_BUILD_DIR)/src/libbenchmark.a
	$(CXX) $(CXXFLAGS_BENCH) $(LDFLAGS) -o $@ $(BENCH_OBJECTS) \
		-L$(GBENCH_LIB) -lbenchmark -lbenchmark_main

# Run benchmarks
bench: $(BENCH_TARGET)
	@echo "Running benchmarks..."
	@./$(BENCH_TARGET) --benchmark_color=true

# Run benchmarks with JSON output for CI
bench-ci: $(BENCH_TARGET)
	@./$(BENCH_TARGET) --benchmark_format=json --benchmark_out=benchmark_results.json

clean:
	rm -f $(TARGET) $(TEST_TARGET) $(TEST_OBJECTS) $(BENCH_TARGET) $(BENCH_OBJECTS) benchmark_results.json

# Deep clean including Google Test and Benchmark
distclean: clean
	rm -rf $(GTEST_DIR) $(GTEST_BUILD_DIR) $(GBENCH_DIR) $(GBENCH_BUILD_DIR)

# Format source files
format:
	@find src tests \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) | xargs clang-format -i

# Check formatting without modifying files
format-check:
	@find src tests \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) | xargs clang-format --dry-run --Werror

# Run clang-tidy linter
lint:
	@find src \( -name '*.cpp' -o -name '*.hpp' \) | xargs -I {} clang-tidy {} -- -std=c++17

# Generate compile_commands.json for clangd (requires bear)
compile_commands: clean
	bear -- $(MAKE) all $(TEST_TARGET)

# Show help
help:
	@echo "Available targets:"
	@echo "  all              - Build main executable (default)"
	@echo "  check            - Build and run all tests"
	@echo "  test             - Alias for check"
	@echo "  gtest            - Download and build Google Test only"
	@echo "  gbench           - Download and build Google Benchmark only"
	@echo "  bench            - Build and run benchmarks"
	@echo "  bench-ci         - Run benchmarks with JSON output"
	@echo "  format           - Format source files with clang-format"
	@echo "  format-check     - Check formatting without modifying files"
	@echo "  lint             - Run clang-tidy linter"
	@echo "  compile_commands - Generate compile_commands.json for clangd"
	@echo "  clean            - Remove build artifacts"
	@echo "  distclean        - Remove build artifacts, Google Test and Benchmark"
