// Iterator Operations Fuzzer
//
// DESIGN NOTES:
// - Focused on iterator edge cases and navigation patterns
// - Tests seek/next/prev combinations
// - Bounded iteration to maintain performance

#include "../src/skiplist.hpp"
#include "../src/arena.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

using namespace minilsm;

static constexpr size_t kMaxOps = 100;
static constexpr size_t kMaxKeySize = 128;
static constexpr size_t kMaxValueSize = 256;
static constexpr size_t kMaxIterSteps = 30;
static constexpr size_t kPreInsertCount = 20;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    FuzzedDataProvider provider(data, size);

    Arena arena;
    SkipList list(&arena);

    // Pre-populate with some entries for meaningful iteration
    size_t pre_insert = provider.ConsumeIntegralInRange<size_t>(0, kPreInsertCount);
    for (size_t i = 0; i < pre_insert && provider.remaining_bytes() > 0; i++) {
        auto key_data = provider.ConsumeRandomLengthString(kMaxKeySize);
        auto value_data = provider.ConsumeRandomLengthString(kMaxValueSize);
        uint64_t seq = provider.ConsumeIntegral<uint64_t>();

        InternalKey key(Slice(key_data.data(), key_data.size()), seq, KeyType::Put);
        list.insert(key, Slice(value_data.data(), value_data.size()));
    }

    // Now fuzz iterator operations
    SkipList::Iterator it(&list);
    size_t ops = 0;

    while (provider.remaining_bytes() > 0 && ops++ < kMaxOps) {
        uint8_t op = provider.ConsumeIntegral<uint8_t>() % 7;

        switch (op) {
            case 0: { // seek
                auto target = provider.ConsumeRandomLengthString(kMaxKeySize);
                it.seek(Slice(target.data(), target.size()));
                break;
            }
            case 1: { // seek_to_first
                it.seek_to_first();
                break;
            }
            case 2: { // seek_to_last
                it.seek_to_last();
                break;
            }
            case 3: { // next (bounded)
                size_t steps = provider.ConsumeIntegralInRange<size_t>(1, kMaxIterSteps);
                for (size_t i = 0; i < steps && it.valid(); i++) {
                    (void)it.key();
                    (void)it.value();
                    it.next();
                }
                break;
            }
            case 4: { // prev (bounded)
                size_t steps = provider.ConsumeIntegralInRange<size_t>(1, kMaxIterSteps);
                for (size_t i = 0; i < steps && it.valid(); i++) {
                    (void)it.key();
                    (void)it.value();
                    it.prev();
                }
                break;
            }
            case 5: { // Check validity and access
                if (it.valid()) {
                    InternalKey k = it.key();
                    Slice v = it.value();
                    (void)k.user_key.size();
                    (void)v.size();
                }
                break;
            }
            case 6: { // Mixed forward/backward traversal
                size_t steps = provider.ConsumeIntegralInRange<size_t>(1, kMaxIterSteps / 2);
                for (size_t i = 0; i < steps && it.valid(); i++) {
                    bool go_forward = provider.ConsumeBool();
                    if (go_forward) {
                        it.next();
                    } else {
                        it.prev();
                    }
                }
                break;
            }
        }
    }

    return 0;
}
