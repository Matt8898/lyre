#pragma once

#include <stdint.h>
#include <stddef.h>
#include <lib/dynarray.hpp>
#include <mm/pmm.hpp>
#include <lib/print.hpp>

#define PAGE_SIZE ((size_t)4096)
#define MEM_PHYS_OFFSET ((uintptr_t)0xffff800000000000)

#define VMM_PRESENT (1 << 0)
#define VMM_WRITE (1 << 1)
#define VMM_USER (1 << 2)
#define VMM_DIRTY (1 << 5)
#define VMM_LARGE (1 << 7)
#define VMM_NX (1 << 63)
#define VMM_FIXED (1 << 10)
#define PHYS_TO_VIRT(phys) (((uintptr_t)phys + MEM_PHYS_OFFSET))
#define ADDRESS_MASK ~0xFFF
#define ENTRIES_PER_TABLE 512

struct Hole {
	uintptr_t start;
	size_t len;
	Hole *prev;
	Hole *next;

	Hole(uintptr_t _start, size_t _len) : start(_start), len(_len) { };
};

struct AddressSpaceHoles {
	//remove memory from the holes at a specfic address
	bool allocate_exact(uintptr_t start, size_t len);
	//allocate any memory that fits
	uintptr_t allocate_any(size_t len, uintptr_t min_addr, uintptr_t max_addr);
	//add memory to the holes
	void deallocate(uintptr_t start, size_t len);
	void fill_hole(Hole* hole, size_t len);

	AddressSpaceHoles() {
		holes = new Hole(0, 0x7fffffffffff);
		holes->prev = nullptr;
		holes->next = new Hole(0xffff800000000000, 0x7fffffffffff);
		holes->next->prev = holes;
		holes->next->next = nullptr;
	}

	void dump_holes();

	private:
		Hole *holes;
};

struct Mapping {
	uintptr_t base;
	size_t len;
	uint64_t flags;
	Mapping(uintptr_t _base, size_t _len, uint64_t _flags) : base(_base), len(_len), flags(_flags) { };
};

struct AddressSpace {
	AddressSpaceHoles holes;
	DynArray<Mapping> mappings;

	uintptr_t map(size_t base, size_t len, uint64_t flags);
	uintptr_t map(size_t len, uint64_t flags, uintptr_t min_addr, uintptr_t max_addr);
	void switch_to();

	AddressSpace() : holes(), mappings() {
		print("constructor called\n");
		cr3 = (uint64_t*)pmm_allocz(1);
	}

	private:
		uint64_t *cr3;
		void _map(uintptr_t phys, uintptr_t virt, uint64_t flags);
};
