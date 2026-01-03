# SkipList Performance Optimization Spec

## Problem Statement

Comparative benchmarking against RocksDB InlineSkipList reveals minilsm insert is ~35% slower:

| Operation (100K items) | minilsm | RocksDB | Gap |
|------------------------|---------|---------|-----|
| Insert | 615K ops/s | 940K ops/s | 1.53x slower |
| Insert Random | 677K ops/s | 796K ops/s | 1.18x slower |

## Root Causes

### 1. Redundant Search Traversals (Primary Bottleneck)

**Current behavior**: For each level in the insert, `find_predecessor_at_level()` starts from the top and traverses down:

```cpp
// skiplist.hpp:104-129
for (int level = 0; level < height; level++) {
    while (true) {
        Node *pred = find_predecessor_at_level(stored_key, level);  // O(log n) each time!
        ...
    }
}
```

`find_predecessor_at_level()` always starts from `head_` at `max_height - 1`:

```cpp
// skiplist.hpp:230-251
Node *find_predecessor_at_level(const InternalKey &key, int target_level) const {
    Node *x = head_;
    int level = max_height_.load(std::memory_order_relaxed) - 1;  // starts at top every time
    while (true) {
        Node *next = x->get_next(level);
        if (next != nullptr && next->key.compare(key) < 0) {
            x = next;
        } else {
            if (level == target_level) return x;
            level--;
        }
    }
}
```

**Complexity**: O(height × log n) per insert instead of O(log n).

With average height ~2.5 (branching factor 4), this is **2-3x more work** than necessary.

**RocksDB approach**: Single top-down traversal caches all predecessors:

```cpp
// One traversal fills prev[0..max_height-1]
Node* prev[kMaxPossibleHeight];
FindGreaterOrEqual(key, prev);

// Then link at each level using cached predecessors
for (int i = 0; i < height; ++i) {
    x->SetNext(i, prev[i]->Next(i));
    prev[i]->SetNext(i, x);
}
```

### 2. Multiple Memory Allocations

**Current behavior**: 3 separate allocations per insert:

```cpp
// skiplist.hpp:69-85
char *key_data = arena_->allocate(key.user_key.size());     // allocation 1
std::memcpy(key_data, key.user_key.data(), key.user_key.size());

char *val_data = arena_->allocate(value.size());            // allocation 2
std::memcpy(val_data, value.data(), value.size());

Node *x = new_node(stored_key, stored_value, height);       // allocation 3 (in new_node)
```

**RocksDB approach**: Single allocation for node + key:

```cpp
char* AllocateKey(size_t key_size) {
    int height = RandomHeight();
    size_t prefix = sizeof(std::atomic<Node*>) * (height - 1);
    char* raw = allocator_->AllocateAligned(prefix + sizeof(Node) + key_size);  // 1 allocation
    ...
}
```

### 3. Poor Cache Locality

**Current layout**: Node stores pointers to separately allocated key/value:

```cpp
struct Node {
    InternalKey key;   // Slice (8 bytes ptr + 8 bytes size) + 8 bytes seq + enum
    Slice value;       // 8 bytes ptr + 8 bytes size
    int height;        // 4 bytes
};
// Accessing key data requires following pointer → cache miss
```

**RocksDB layout**: Key data inline immediately after node:

```cpp
struct Node {
    std::atomic<Node*> next_[1];  // variable size array stored BEFORE node
    // Key data stored immediately after node in same allocation
};

const char* Key() const {
    return reinterpret_cast<const char*>(&next_[1]);  // no indirection
}
```

---

## Proposed Changes

### Change 1: Cache Predecessors During Insert

Replace per-level search with single traversal that caches predecessors.

**File**: `src/skiplist.hpp`

**Current**:
```cpp
void insert(const InternalKey &key, const Slice &value) {
    ...
    for (int level = 0; level < height; level++) {
        while (true) {
            Node *pred = find_predecessor_at_level(stored_key, level);
            Node *succ = pred->get_next(level);
            ...
        }
    }
}
```

**Proposed**:
```cpp
void insert(const InternalKey &key, const Slice &value) {
    ...
    // Single traversal to find all predecessors
    Node* prev[kMaxHeight];
    find_greater_or_equal(stored_key, prev);

    // Link at each level using cached predecessors
    for (int level = 0; level < height; level++) {
        while (true) {
            Node *succ = prev[level]->get_next(level);

            // Validate predecessor is still valid (for concurrent safety)
            if (succ != nullptr && succ->key.compare(stored_key) < 0) {
                // Another thread inserted, re-find predecessor at this level only
                prev[level] = find_predecessor_at_level(stored_key, level);
                continue;
            }

            x->set_next(level, succ);
            if (prev[level]->cas_next(level, succ, x)) {
                break;
            }
            // CAS failed, re-find predecessor at this level only
            prev[level] = find_predecessor_at_level(stored_key, level);
        }
    }
}
```

**Expected impact**: ~2x improvement in insert throughput.

### Change 2: Batch Memory Allocation

Allocate node + key + value in a single arena call.

**File**: `src/skiplist.hpp`

**Current**:
```cpp
void insert(const InternalKey &key, const Slice &value) {
    char *key_data = arena_->allocate(key.user_key.size());
    std::memcpy(key_data, ...);

    char *val_data = arena_->allocate(value.size());
    std::memcpy(val_data, ...);

    Node *x = new_node(stored_key, stored_value, height);
}
```

**Proposed**:
```cpp
void insert(const InternalKey &key, const Slice &value) {
    int height = random_height();

    // Single allocation: next pointers + Node + key + value
    size_t alloc_size = sizeof(std::atomic<Node*>) * height
                      + sizeof(Node)
                      + key.user_key.size()
                      + value.size();

    char* mem = arena_->allocate_aligned(alloc_size, alignof(std::atomic<Node*>));

    // Layout: [next[height-1]..next[0]][Node][key_data][value_data]
    Node* node = reinterpret_cast<Node*>(mem + sizeof(std::atomic<Node*>) * height);
    char* key_data = reinterpret_cast<char*>(node + 1);
    char* val_data = key_data + key.user_key.size();

    std::memcpy(key_data, key.user_key.data(), key.user_key.size());
    std::memcpy(val_data, value.data(), value.size());

    // Initialize node with pointers to inline data
    new (node) Node();
    node->key = InternalKey(Slice(key_data, key.user_key.size()), key.sequence, key.type);
    node->value = Slice(val_data, value.size());
    node->height = height;
    ...
}
```

**Expected impact**: ~10-20% improvement (reduces allocator contention and improves locality).

### Change 3: Inline Key Storage (Optional, Larger Change)

Store key data directly in the node structure like RocksDB.

**File**: `src/skiplist.hpp`

This requires restructuring Node to be variable-sized:

```cpp
struct Node {
    uint32_t key_size;
    uint32_t value_size;
    uint64_t sequence;
    KeyType type;
    int height;
    // Key and value data follow immediately after

    const char* key_data() const {
        return reinterpret_cast<const char*>(this + 1);
    }
    const char* value_data() const {
        return key_data() + key_size;
    }
    Slice user_key() const {
        return Slice(key_data(), key_size);
    }
    Slice value() const {
        return Slice(value_data(), value_size);
    }
};
```

**Expected impact**: ~5-10% improvement (eliminates pointer chasing in comparisons).

**Trade-off**: More complex code, breaks existing API slightly.

---

## Implementation Order

1. **Change 1** (Cache Predecessors) - Highest impact, moderate complexity
2. **Change 2** (Batch Allocation) - Medium impact, low complexity
3. **Change 3** (Inline Storage) - Lower impact, higher complexity (optional)

## Validation

Run comparative benchmark after each change:

```bash
make clean && make run_comp_bench
./run_comp_bench --benchmark_filter="Insert" --benchmark_color=true
```

Target: Match or exceed RocksDB insert performance (~900K+ ops/s at 100K items).

## References

- RocksDB InlineSkipList: `third_party/rocksdb/inlineskiplist.h`
- Current implementation: `src/skiplist.hpp`
- Benchmark: `bench/comparative_bench.cpp`
- Previous arena spec: `old/SPEC-arena.md`
