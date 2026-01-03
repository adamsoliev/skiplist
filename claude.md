# Claude Code Notes

## Project Overview

**minilsm** - Thread-safe skiplist in C++17 with lock-free arena allocator.
**Structure:**
- `src/` - Core: skiplist.hpp, arena.hpp, key.hpp, slice.hpp
- `tests/` - Google Test (basic, concurrent, iterator)
- `bench/` - Google Benchmark (micro + comparative vs Redis/RocksDB)
- `fuzz/` - libfuzzer harnesses with sanitizers

## Development Workflow

```sh
# 1. Make changes

# 2. Run tests
make test                    # Unit tests
make sanitizers              # ASan + TSan + UBSan

# 3. Format/lint before committing
make format                  # Format all files
make format-check            # Check formatting (CI)
make lint                    # Run clang-tidy
```

## Git Commands

Always use `git [action] ...`, not `git -C path [action]`.

## CI Testing with Multipass

Always test CI changes locally in an Ubuntu VM using multipass before pushing:

```bash
# Create VM
multipass launch --name ci-test --memory 2G --disk 10G

# Mount project
multipass mount /Users/adamsoliev/Development/skiplist ci-test:/home/ubuntu/skiplist

# Run tests inside VM
multipass exec ci-test -- bash -c "cd /home/ubuntu/skiplist && <command>"
```
