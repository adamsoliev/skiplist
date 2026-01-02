# Concurrent Arena Allocator Specification

## Overview

A core-sharded arena allocator designed to eliminate mutex contention in multi-threaded workloads. Replaces the existing `Arena` class.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      ConcurrentArena                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐       ┌─────────┐     │
│  │ Shard 0 │ │ Shard 1 │ │ Shard 2 │  ...  │ Shard N │     │
│  │ [lock]  │ │ [lock]  │ │ [lock]  │       │ [lock]  │     │
│  │ [block] │ │ [block] │ │ [block] │       │ [block] │     │
│  └────┬────┘ └────┬────┘ └────┬────┘       └────┬────┘     │
│       │           │           │                 │          │
│       └───────────┴─────┬─────┴─────────────────┘          │
│                         ▼                                   │
│              ┌─────────────────────┐                       │
│              │    Central Arena    │                       │
│              │      [spinlock]     │                       │
│              │   [block storage]   │                       │
│              └─────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

## Design Decisions

### 1. Concurrency Model

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Shard count | `hardware_concurrency() - 2` (configurable) | Leave cores for OS/background tasks |
| Thread-to-shard mapping | Core ID via `sched_getcpu()` | Exploits OS soft affinity for cache locality |
| Core ID caching | Thread-local, refresh on contention | Balance freshness vs. syscall overhead |
| Oversubscription | Not supported | Thread count must be <= shard count |

### 2. Synchronization

| Component | Mechanism | Details |
|-----------|-----------|---------|
| Shard lock | Simple TAS spinlock | `while(flag.test_and_set(acquire))` |
| Central lock | Spinlock with yield | Spin ~100 iterations, then `sched_yield()` |
| Repick trigger | After 64 failed spins | Re-query core ID, try new shard |

### 3. Memory Management

| Parameter | Value | Notes |
|-----------|-------|-------|
| Chunk size | Fixed 128KB | Shards request fixed-size chunks from central |
| Large allocation threshold | >128KB | Bypass shards, allocate directly from central |
| Tail scavenging minimum | 1KB | Smaller fragments are wasted |
| Cache line padding | 64 bytes | Prevent false sharing between shards |
| Memory limit | Configurable | Constructor parameter, return nullptr on exceed |

### 4. Shard Exhaustion Behavior

When a shard's current block is exhausted:
1. Thread holds shard lock while requesting chunk from central
2. Other threads mapped to same shard **block and wait**
3. No work stealing or shard migration during refill
4. Rationale: Memory efficiency over latency; keeps allocations core-local

### 5. API Design

```cpp
class Arena {
public:
    // Constructor
    explicit Arena(size_t max_bytes = 0,          // 0 = unlimited
                   size_t num_shards = 0);        // 0 = auto (cores - 2)

    ~Arena();

    // Non-copyable, non-movable
    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;

    // Allocation (thread-safe)
    // Returns nullptr on failure (OOM or limit exceeded)
    char* allocate(size_t bytes);
    char* allocate_aligned(size_t bytes, size_t align);

    // Statistics
    size_t memory_usage() const;  // Total bytes allocated from system
};
```

### 6. Error Handling

| Condition | Behavior |
|-----------|----------|
| Allocation failure (OOM) | Return `nullptr` |
| Memory limit exceeded | Return `nullptr` |
| Reset/reclaim | Not supported; destroy and recreate arena |

## Internal Structures

### Shard

```cpp
struct alignas(64) Shard {
    std::atomic_flag lock = ATOMIC_FLAG_INIT;
    char* block_ptr = nullptr;      // Current position in block
    size_t block_remaining = 0;     // Bytes remaining in current block
    // Padding to 64 bytes for cache line isolation
};
```

### Central Arena

- Owns all allocated memory blocks (vector of unique_ptr)
- Protected by yielding spinlock
- Tracks total memory usage (atomic counter)
- Handles large allocations (>128KB) directly

## Allocation Flow

```
allocate(size):
    if size > 128KB:
        return central_allocate(size)  // Direct path

    shard_idx = get_cached_core_id()
    spin_count = 0

    while true:
        if try_lock(shards[shard_idx]):
            result = shard_allocate(shard_idx, size)
            unlock(shards[shard_idx])
            return result

        spin_count++
        if spin_count >= 64:
            shard_idx = repick()  // Re-query core ID
            spin_count = 0

shard_allocate(idx, size):
    if shards[idx].block_remaining >= size:
        ptr = shards[idx].block_ptr
        shards[idx].block_ptr += size
        shards[idx].block_remaining -= size
        return ptr

    // Need new chunk from central
    new_block = central_allocate_chunk(128KB)
    if new_block == nullptr:
        return nullptr

    shards[idx].block_ptr = new_block
    shards[idx].block_remaining = 128KB
    return shard_allocate(idx, size)  // Retry

repick():
    refresh thread-local core ID via sched_getcpu()
    return core_id % num_shards
```

## Memory Layout

```
Shard 0 (64 bytes, cache-line aligned):
┌────────────────┬────────────────┬────────────────┬──────────┐
│  atomic_flag   │   block_ptr    │ block_remaining│ padding  │
│   (1 byte)     │   (8 bytes)    │   (8 bytes)    │(47 bytes)│
└────────────────┴────────────────┴────────────────┴──────────┘

Shard 1 (64 bytes, cache-line aligned):
┌────────────────┬────────────────┬────────────────┬──────────┐
│  atomic_flag   │   block_ptr    │ block_remaining│ padding  │
└────────────────┴────────────────┴────────────────┴──────────┘
...
```

## Performance Expectations

| Scenario | Before (mutex) | After (sharded) |
|----------|----------------|-----------------|
| Single-threaded | ~same | ~same (slight overhead from shard lookup) |
| 12 threads, 12 cores | Heavy contention (~40% in mutex) | Near-linear scaling |
| Allocation latency | Variable (lock contention) | Consistent (core-local) |

## Constraints

1. Thread count must not exceed shard count
2. No memory reclamation without destroying arena
3. Large allocations (>128KB) bypass sharding benefits
4. Relies on OS soft affinity; explicit thread pinning not required
