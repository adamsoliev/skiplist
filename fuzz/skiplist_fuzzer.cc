// Skiplist Operations Fuzzer
//
// DESIGN NOTES:
// - Narrow focus: only skiplist insert/get/iterate
// - Uses FuzzedDataProvider to prevent input reuse
// - Limits iteration to prevent timeouts
// - No debug output
// - Deterministic (no random not from input)

#include "../src/skiplist.hpp"
#include "../src/arena.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

using namespace minilsm;

// Limit operations to maintain >1000 exec/s
static constexpr size_t kMaxOps = 100;
static constexpr size_t kMaxKeySize = 256;
static constexpr size_t kMaxValueSize = 1024;
static constexpr size_t kMaxIterSteps = 50;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    FuzzedDataProvider provider(data, size);

    // Fresh arena per run - no state leakage
    Arena arena;
    SkipList list(&arena);

    size_t ops = 0;
    while (provider.remaining_bytes() > 0 && ops++ < kMaxOps) {
        uint8_t op = provider.ConsumeIntegral<uint8_t>() % 4;

        switch (op) {
            case 0: { // Insert
                auto key_data = provider.ConsumeRandomLengthString(kMaxKeySize);
                auto value_data = provider.ConsumeRandomLengthString(kMaxValueSize);
                uint64_t seq = provider.ConsumeIntegral<uint64_t>();
                KeyType type = static_cast<KeyType>(
                    provider.ConsumeIntegral<uint8_t>() % 6);

                InternalKey key(Slice(key_data.data(), key_data.size()), seq, type);
                list.insert(key, Slice(value_data.data(), value_data.size()));
                break;
            }
            case 1: { // Get
                auto key_data = provider.ConsumeRandomLengthString(kMaxKeySize);
                std::string result;
                list.get(Slice(key_data.data(), key_data.size()), &result);
                break;
            }
            case 2: { // Iterator forward (bounded)
                auto key_data = provider.ConsumeRandomLengthString(kMaxKeySize);
                SkipList::Iterator it(&list);
                it.seek(Slice(key_data.data(), key_data.size()));
                for (size_t i = 0; i < kMaxIterSteps && it.valid(); i++) {
                    (void)it.key();
                    (void)it.value();
                    it.next();
                }
                break;
            }
            case 3: { // Iterator reverse (bounded)
                SkipList::Iterator it(&list);
                it.seek_to_last();
                for (size_t i = 0; i < kMaxIterSteps && it.valid(); i++) {
                    (void)it.key();
                    (void)it.value();
                    it.prev();
                }
                break;
            }
        }
    }

    return 0;  // Always return 0; non-zero reserved for future use
}
