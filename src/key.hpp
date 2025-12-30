#pragma once

#include "slice.hpp"
#include <cstdint>

namespace minilsm
{

enum class KeyType : uint8_t
{
        Put,
        Delete,
        RangePut,
        RangeDelete,
        Update,
        RangeUpdate
};

struct InternalKey
{
        Slice user_key;
        uint64_t sequence;
        KeyType type;

        InternalKey() : user_key(), sequence(0), type(KeyType::Put) {}

        InternalKey(Slice uk, uint64_t seq, KeyType t) : user_key(uk), sequence(seq), type(t) {}

        // Compare: user_key ASC, sequence DESC
        // Same user key -> newest (highest sequence) comes first
        int compare(const InternalKey &other) const
        {
                int r = user_key.compare(other.user_key);
                if (r != 0)
                        return r;
                // Descending by sequence: higher sequence = smaller (comes first)
                if (sequence > other.sequence)
                        return -1;
                if (sequence < other.sequence)
                        return 1;
                return 0;
        }

        bool operator<(const InternalKey &other) const { return compare(other) < 0; }

        bool operator==(const InternalKey &other) const { return compare(other) == 0; }

        bool operator!=(const InternalKey &other) const { return compare(other) != 0; }
};

constexpr uint64_t kMaxSequenceNumber = UINT64_MAX;

} // namespace minilsm
