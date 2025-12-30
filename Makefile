CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g -pthread
LDFLAGS = -pthread

SRC = src/main.cpp
TARGET = mini-lsm

# Google Test configuration
GTEST_DIR = third_party/googletest
GTEST_BUILD_DIR = $(GTEST_DIR)/build
GTEST_INCLUDE = $(GTEST_DIR)/googletest/include
GTEST_LIB = $(GTEST_BUILD_DIR)/lib

# Test configuration
TEST_DIR = tests
TEST_SOURCES = $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJECTS = $(TEST_SOURCES:.cpp=.o)
TEST_TARGET = run_tests

# Number of parallel test jobs (default to number of CPU cores)
NPROCS := $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

.PHONY: all clean check test gtest format format-check lint

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

clean:
	rm -f $(TARGET) $(TEST_TARGET) $(TEST_OBJECTS)

# Deep clean including Google Test
distclean: clean
	rm -rf $(GTEST_DIR) $(GTEST_BUILD_DIR)

# Format source files
format:
	@find src tests \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) | xargs clang-format -i

# Check formatting without modifying files
format-check:
	@find src tests \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) | xargs clang-format --dry-run --Werror

# Run clang-tidy linter
lint:
	@find src \( -name '*.cpp' -o -name '*.hpp' \) | xargs clang-tidy -- -std=c++17

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build main executable (default)"
	@echo "  check        - Build and run all tests"
	@echo "  test         - Alias for check"
	@echo "  gtest        - Download and build Google Test only"
	@echo "  format       - Format source files with clang-format"
	@echo "  format-check - Check formatting without modifying files"
	@echo "  lint         - Run clang-tidy linter"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Remove build artifacts and Google Test"
