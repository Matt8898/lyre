#include <stdint.h>
#include <stddef.h>
#include <mm/pmm.hpp>
#include <mm/vmm.hpp>
#include <lib/bitmap.hpp>
#include <lib/math.hpp>
#include <lib/lock.hpp>
#include <lib/builtins.h>

static Bitmap bitmap;
static size_t last_used_index = 0;
static uintptr_t highest_page = 0;

static Lock pmm_lock;

void pmm_init(StivaleMemmap memmap) {
    // First, calculate how big the bitmap needs to be.
    for (size_t i = 0; i < memmap.entries; i++) {
        if (memmap.address[i].type != STIVALE_USABLE)
            continue;

        uintptr_t top = memmap.address[i].base + memmap.address[i].size;

        if (top > highest_page)
            highest_page = top;
    }

    size_t bitmap_size = div_roundup(highest_page, PAGE_SIZE) / 8;

    // Second, find a location with enough free pages to host the bitmap.
    for (size_t i = 0; i < memmap.entries; i++) {
        if (memmap.address[i].type != STIVALE_USABLE)
            continue;

        if (memmap.address[i].size >= bitmap_size) {
            void *bitmap_addr = (void *)(memmap.address[i].base + MEM_PHYS_OFFSET);

            // Initialise entire bitmap to 1 (non-free)
            memset(bitmap_addr, 0xff, bitmap_size);

            bitmap.set_bitmap(bitmap_addr);

            memmap.address[i].size -= bitmap_size;
            memmap.address[i].base += bitmap_size;

            break;
        }
    }

    // Third, populate free bitmap entries according to memory map.
    for (size_t i = 0; i < memmap.entries; i++) {
        if (memmap.address[i].type != STIVALE_USABLE)
            continue;

        for (uintptr_t j = 0; j < memmap.address[i].size; j += PAGE_SIZE)
            bitmap.unset((memmap.address[i].base + j) / PAGE_SIZE);
    }
}

static void *inner_alloc(size_t count, size_t limit) {
    size_t p = 0;

    while (last_used_index < limit) {
        if (!bitmap.is_set(last_used_index++)) {
            if (++p == count) {
                size_t page = last_used_index - count;
                for (size_t i = page; i < last_used_index; i++) {
                    bitmap.set(i);
                }
                return (void *)(page * PAGE_SIZE);
            }
        } else {
            p = 0;
        }
    }

    return nullptr;
}

void *pmm_alloc(size_t count) {
    pmm_lock.acquire();

    size_t l = last_used_index;
    void *ret = inner_alloc(count, highest_page / PAGE_SIZE);
    if (ret == nullptr) {
        last_used_index = 0;
        ret = inner_alloc(count, l);
    }

    pmm_lock.release();
    return ret;
}

void *pmm_allocz(size_t count) {
    char *ret = (char *)pmm_alloc(count);

    if (ret == nullptr)
        return nullptr;

    uint64_t *ptr = (uint64_t *)(ret + MEM_PHYS_OFFSET);

    for (size_t i = 0; i < count * (PAGE_SIZE / sizeof(uint64_t)); i++)
        ptr[i] = 0;

    return ret;
}

void pmm_free(void *ptr, size_t count) {
    pmm_lock.acquire();
    size_t page = (size_t)ptr / PAGE_SIZE;
    for (size_t i = page; i < page + count; i++)
        bitmap.unset(i);
    pmm_lock.release();
}