# Mini LSM Tree Specification

## SkipList

Lock-free concurrent ordered map for MemTable.

### Key Structure

```cpp
struct InternalKey {
    Slice user_key;      // raw bytes + length (non-owning view)
    uint64_t sequence;   // monotonic sequence number
    KeyType type;        // put, delete, range_put, range_delete, update, range_update
};
```

### Value Structure

```cpp
struct Slice {
    const char* data;
    size_t size;
};
// Non-owning view, data lives in arena
```

### Ordering

- Keys ordered: `user_key ASC, sequence DESC`
- Same user key → newest (highest sequence) comes first
- Readers pick first match (most recent version)

### Node Layout

```
Memory layout (negative offset addressing):

    [next[height-1]] ← highest level pointer
    [next[height-2]]
    ...
    [next[1]]
    [next[0]]        ← base level pointer
    [Node struct]    ← node pointer points here
        - key
        - value
        - height
```

Single allocation per node. Forward pointers stored before Node struct for cache locality.

### Concurrency Model

- **Reads**: Lock-free, acquire semantics on pointer loads
- **Writes**: Lock-free insertions, release semantics on pointer stores
- **Deletes**: None during operation (append-only with tombstones)
- **Reclamation**: Entire skiplist destroyed on memtable flush

### Height Selection

- Probabilistic with branching factor (default: 4, i.e., p=0.25)
- Each level has 1/branching_factor probability
- Max height configurable (default: 12)

### Memory Allocation

- Arena allocator (bump pointer from large blocks)
- All memory freed at once on flush
- No per-node deallocation

### Operations

```cpp
class SkipList {
public:
    // Insert key-value (allows duplicate user keys with different sequences)
    void insert(const InternalKey& key, const Slice& value);

    // Point lookup (returns newest version for user key)
    bool get(const Slice& user_key, std::string* value);

    // Iterator (live view, sees concurrent modifications)
    class Iterator {
        void seek(const Slice& target);
        void seek_to_first();
        void next();
        bool valid();
        Slice key();
        Slice value();
    };
};
```

### Conflict Resolution

Multiple inserts with same user key: both inserted with different sequences. Reader sees newest.

### Configuration

| Parameter        | Default | Description                    |
|------------------|---------|--------------------------------|
| memtable_size    | 64 MB   | Flush threshold                |
| branching_factor | 4       | Height probability (p=1/bf)    |
| max_height       | 12      | Maximum skiplist height        |

### KeyType Enum

```cpp
enum class KeyType : uint8_t {
    Put,
    Delete,
    RangePut,
    RangeDelete,
    Update,
    RangeUpdate
};
```
