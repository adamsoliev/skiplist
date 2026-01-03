CXX := clang++
CXXFLAGS := -std=c++17 -g -O2 -fno-omit-frame-pointer
FUZZ_FLAGS := -fsanitize=fuzzer,address,undefined
TSAN_FLAGS := -fsanitize=fuzzer,thread
INCLUDES := -I../src

# Performance: aim for >1000 exec/s
FUZZ_OPTS := -max_len=4096 -timeout=30 -rss_limit_mb=2048

FUZZERS := skiplist_fuzzer arena_fuzzer iterator_fuzzer
TSAN_FUZZERS := concurrent_fuzzer

.PHONY: all clean tsan coverage help

all: $(FUZZERS)

tsan: $(TSAN_FUZZERS)

skiplist_fuzzer: skiplist_fuzzer.cc
	$(CXX) $(CXXFLAGS) $(FUZZ_FLAGS) $(INCLUDES) $< -o $@

arena_fuzzer: arena_fuzzer.cc
	$(CXX) $(CXXFLAGS) $(FUZZ_FLAGS) $(INCLUDES) $< -o $@

iterator_fuzzer: iterator_fuzzer.cc
	$(CXX) $(CXXFLAGS) $(FUZZ_FLAGS) $(INCLUDES) $< -o $@

concurrent_fuzzer: concurrent_fuzzer.cc
	$(CXX) $(CXXFLAGS) $(TSAN_FLAGS) $(INCLUDES) $< -o $@ -pthread

clean:
	rm -f $(FUZZERS) $(TSAN_FUZZERS) crash-* oom-* timeout-* slow-unit-*

# Run with corpus and dictionary
run_skiplist: skiplist_fuzzer
	mkdir -p corpus/skiplist
	./skiplist_fuzzer $(FUZZ_OPTS) -dict=dictionaries/skiplist.dict corpus/skiplist/

run_arena: arena_fuzzer
	mkdir -p corpus/arena
	./arena_fuzzer $(FUZZ_OPTS) corpus/arena/

run_iterator: iterator_fuzzer
	mkdir -p corpus/iterator
	./iterator_fuzzer $(FUZZ_OPTS) -dict=dictionaries/skiplist.dict corpus/iterator/

run_concurrent: concurrent_fuzzer
	mkdir -p corpus/concurrent
	./concurrent_fuzzer $(FUZZ_OPTS) -timeout=60 corpus/concurrent/

# Quick smoke test (60 seconds each)
quick: $(FUZZERS)
	@for f in $(FUZZERS); do \
		echo "=== Running $$f for 60s ==="; \
		mkdir -p corpus/$$f; \
		./$$f -max_total_time=60 $(FUZZ_OPTS) corpus/$$f/ 2>&1 | tail -10; \
	done

quick-tsan: $(TSAN_FUZZERS)
	@for f in $(TSAN_FUZZERS); do \
		echo "=== Running $$f for 60s ==="; \
		mkdir -p corpus/$$f; \
		./$$f -max_total_time=60 $(FUZZ_OPTS) -timeout=60 corpus/$$f/ 2>&1 | tail -10; \
	done

# Minimize corpus (run periodically)
minimize_skiplist: skiplist_fuzzer
	mkdir -p corpus/skiplist_min
	./skiplist_fuzzer -merge=1 corpus/skiplist_min/ corpus/skiplist/
	rm -rf corpus/skiplist
	mv corpus/skiplist_min corpus/skiplist

minimize_arena: arena_fuzzer
	mkdir -p corpus/arena_min
	./arena_fuzzer -merge=1 corpus/arena_min/ corpus/arena/
	rm -rf corpus/arena
	mv corpus/arena_min corpus/arena

minimize_iterator: iterator_fuzzer
	mkdir -p corpus/iterator_min
	./iterator_fuzzer -merge=1 corpus/iterator_min/ corpus/iterator/
	rm -rf corpus/iterator
	mv corpus/iterator_min corpus/iterator

minimize_concurrent: concurrent_fuzzer
	mkdir -p corpus/concurrent_min
	./concurrent_fuzzer -merge=1 corpus/concurrent_min/ corpus/concurrent/
	rm -rf corpus/concurrent
	mv corpus/concurrent_min corpus/concurrent

# Coverage report (requires separate coverage build)
coverage: CXXFLAGS += -fprofile-instr-generate -fcoverage-mapping
coverage: clean $(FUZZERS)
	@echo "Running fuzzers for coverage data..."
	@for f in $(FUZZERS); do \
		mkdir -p corpus/$$f; \
		LLVM_PROFILE_FILE="$$f.profraw" ./$$f -runs=10000 corpus/$$f/ 2>/dev/null || true; \
	done
	@echo "Generating coverage report..."
	llvm-profdata merge -sparse *.profraw -o coverage.profdata
	llvm-cov report ./skiplist_fuzzer -instr-profile=coverage.profdata ../src/*.hpp

# Help
help:
	@echo "Fuzz Testing Targets:"
	@echo ""
	@echo "Build:"
	@echo "  all              Build all ASan/UBSan fuzzers"
	@echo "  tsan             Build TSan concurrent fuzzer"
	@echo "  clean            Remove fuzzer binaries and crash files"
	@echo ""
	@echo "Run:"
	@echo "  run_skiplist     Run skiplist fuzzer with dictionary"
	@echo "  run_arena        Run arena fuzzer"
	@echo "  run_iterator     Run iterator fuzzer with dictionary"
	@echo "  run_concurrent   Run concurrent fuzzer (TSan)"
	@echo ""
	@echo "Quick Tests:"
	@echo "  quick            Run all ASan fuzzers for 60s each"
	@echo "  quick-tsan       Run TSan fuzzer for 60s"
	@echo ""
	@echo "Maintenance:"
	@echo "  minimize_*       Minimize corpus for specified fuzzer"
	@echo "  coverage         Build with coverage and generate report"
