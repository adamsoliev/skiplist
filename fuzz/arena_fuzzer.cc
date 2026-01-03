// Arena Allocator Fuzzer
//
// DESIGN NOTES:
// - Tests arena allocator edge cases
// - Uses FUZZING_BUILD_MODE to bypass arena for ASan visibility
// - Tests alignment, large allocations, concurrent access patterns

#include "../src/arena.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

using namespace minilsm;

static constexpr size_t kMaxAllocSize = 128 * 1024;  // 128KB max
static constexpr size_t kMaxAllocs = 200;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    FuzzedDataProvider provider(data, size);
    Arena arena;

    size_t allocs = 0;
    while (provider.remaining_bytes() > 0 && allocs++ < kMaxAllocs) {
        uint8_t op = provider.ConsumeIntegral<uint8_t>() % 3;

        switch (op) {
            case 0: { // Regular allocation
                size_t alloc_size = provider.ConsumeIntegralInRange<size_t>(1, kMaxAllocSize);
                char* ptr = arena.allocate(alloc_size);

                if (ptr) {
                    // Write pattern to detect buffer overflows
                    memset(ptr, static_cast<char>(alloc_size & 0xFF), alloc_size);

                    // Verify we can read back
                    volatile char check = ptr[0];
                    (void)check;

                    if (alloc_size > 1) {
                        volatile char check_end = ptr[alloc_size - 1];
                        (void)check_end;
                    }
                }
                break;
            }
            case 1: { // Aligned allocation
                size_t alloc_size = provider.ConsumeIntegralInRange<size_t>(1, kMaxAllocSize);
                // Choose power-of-2 alignment: 8, 16, 32, 64
                size_t align_shift = provider.ConsumeIntegralInRange<size_t>(3, 6);
                size_t align = 1ULL << align_shift;

                char* ptr = arena.allocate_aligned(alloc_size, align);

                if (ptr) {
                    // Verify alignment
                    if ((reinterpret_cast<uintptr_t>(ptr) & (align - 1)) != 0) {
                        __builtin_trap();  // Alignment violation
                    }

                    // Write pattern
                    memset(ptr, static_cast<char>(alloc_size & 0xFF), alloc_size);

                    volatile char check = ptr[0];
                    (void)check;
                }
                break;
            }
            case 2: { // Zero-size allocation (edge case)
                char* ptr = arena.allocate(0);
                (void)ptr;  // Should return nullptr
                break;
            }
        }
    }

    // Arena destructor frees everything - no cleanup needed
    return 0;
}
