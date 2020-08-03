#include <mm/vmm.hpp>
#include <lib/print.hpp>

bool AddressSpaceHoles::allocate_exact(uintptr_t start, size_t len) {
	Hole* current = holes;
	//check if there is a hole that contains our allocation range
	while(current != nullptr) {
		if((start >= current->start) && ((start + len) <= (current->start + current->len))) {
			//hole found
			break;
		}
		current = current->next;
	}
	if(current == nullptr) {
		return false;
	}
	print("found hole at: %X, %X\n", current->start, current->len);
	if(start == current->start) {
		fill_hole(current, len);
	} else {
		size_t left_len = start - current->start;
		size_t right_len = current->len - (left_len + len);
		current->len = left_len;
		Hole* newHole = new Hole(start + len, right_len);
		newHole->next = current->next;
		current->next = newHole;
	}
	return true;
}

uintptr_t AddressSpaceHoles::allocate_any(size_t len, uintptr_t min_addr, uintptr_t max_addr) {
	Hole* current = holes;
	while(current != nullptr) {
		print("current: %X %X %X\n", (current->start >= min_addr), current->start, min_addr);
//		if((current->start >= min_addr) && ((current->start + len) <= max_addr) && (current->len >= len)) {
		if((len <= current->len) && ((min_addr + len) <= (current->start + current->len)) && (min_addr >= current->start)) {
			print("hole found\n");
			//hole found
			break;
		}
		current = current->next;
	}
	if(current == nullptr) {
		return false;
	}
	uintptr_t ret = current->start;
	fill_hole(current, len);
	return ret;
}

void AddressSpaceHoles::fill_hole(Hole* current, size_t len) {
	if(len < current->len) {
		current->start += len;
		current->len -= len;
	} else {
		print("a hole needs to be removed\n");
		if(current == holes) {
			print("first hole replaced\n");
			holes = current->next;
		} else {
			current->prev = current->next;
		}
	}
}

/*
 * Add a new hole with size start, len
 *
 * if any range within start, len is already in a hole it will be merged
 *
 * TODO add a check that no non-canonical memory is deallocated
 */
void AddressSpaceHoles::deallocate(uintptr_t start, size_t len) {
	print("==== deallocate start ====\n");
	/*
	 * cases:
	 * - the hole does not interesect any other holes
	 *   - check if there are any previous or next holes and set the relative pointers
	 * - the hole partially interesects one or two holes
	 *   - resize the intersected holes and set the prev/next pointers
	 * - the hole covers an arbitrary amount of holes
	 *   - the hole partially intersects either 1 or 2 holes
	 *      - remove all the holes in the middle, adjust the prev and next pointers and resize the intersected holes
	 *   - the hole does not intersect any other holes, remove the holes in the middle and adjust prev and next
	 * - the hole is completely covered by another hole
	 */
	Hole *current = holes;
	Hole *prevhole = nullptr;
	Hole *nexthole = nullptr;
	Hole *intersectleft = nullptr;
	Hole *intersectright = nullptr;
	bool foundnext = false;

	while(current != nullptr) {
		//partially intersection by a hole from the left
		if(current->start < start && ((current->start + current->len) > start)) {
			print("found hole intersecting from the left\n");
			intersectleft = current;
		}

		//this will end up setting the last hole which does not intersect with the current one
		if(current->start < start && ((current->start + current->len) <= start)) {
			prevhole = current;
		}

		//partially intersection by a hole from the right
		if((current->start > start) && (current->start <= (start + len)) && ((current->start + current->len) > (start + len))) {
			print("found hole intersecting from the right: %X %X\n", current->start, current->len);
			intersectright = current;
		}

		if((current->start > (start + len)) && !foundnext) {
			print("found next hole: %X %X\n", current->start, current->len);
			foundnext = true;
			nexthole = current;
		}

		//skip over all holes that are inside of the current hole
		while(current != nullptr) {
			if(!(current->start > start && ((current->start + current->len) < (start + len)))) {
				break;
			} else {
				print("skipping hole: %X %X\n", current->start, current->len);
			}
			//unlink the nodes
		}
		current = current->next;
	}

	if(intersectleft != nullptr) {
		start = intersectleft->start;
		len += intersectleft->len;
	}

	Hole* newhole = new Hole(start, len);

	if(intersectright != nullptr) {
		newhole->len = intersectright->len + len;
		print("intersect right new len: %X\n", newhole->len);
		if(intersectright->prev == nullptr) {
			holes = newhole;
		}
	}

	newhole->prev = prevhole;
	newhole->next = nexthole;
	if(prevhole != nullptr) {
		prevhole->next = newhole;
	}
	if(nexthole != nullptr) {
		if(nexthole->prev == nullptr) {
			holes = newhole;
		}
		nexthole->prev = newhole;
	}
	print("==== deallocate done ====\n");
}

void AddressSpaceHoles::dump_holes() {
	print("======= begin hole dump =======\n");
	Hole* current = holes;
	//check if there is a hole that contains our allocation range
	while(current != nullptr) {
		print("start: %X, end: %X\n", current->start, current->start + current->len);
		current = current->next;
	}
	print("======= end hole dump =======\n");
}

void AddressSpace::_map(uintptr_t phys, uintptr_t virt, uint64_t flags) {
    uint64_t p4idx = ((uint64_t) virt >> 39) & 0x1FF;
    uint64_t p3idx = ((uint64_t) virt >> 30) & 0x1FF;
    uint64_t p2idx = ((uint64_t) virt >> 21) & 0x1FF;
    uint64_t p1idx = ((uint64_t) virt >> 12) & 0x1FF;

    uint64_t *p4 = this->cr3;
    uint64_t* p3 = nullptr;
    uint64_t* p2 = nullptr;
    uint64_t* p1 = nullptr;

    if (p4[p4idx] & VMM_PRESENT) {
        p3 = (uint64_t *) PHYS_TO_VIRT(p4[p4idx] & ADDRESS_MASK);
    } else {
        p3 = (uint64_t *) pmm_allocz(1);
        p4[p4idx] = (uint64_t) p3 | VMM_PRESENT;
        p3 = (uint64_t *) PHYS_TO_VIRT(p3);
    }

    if (p3[p3idx] & VMM_PRESENT) {
        p2 = (uint64_t *) PHYS_TO_VIRT(p3[p3idx] & ADDRESS_MASK);
    } else {
        p2 = (uint64_t *) pmm_allocz(1);
        p3[p3idx] = (uint64_t) p2 | VMM_PRESENT;
        p2 = (uint64_t *) PHYS_TO_VIRT(p2);
    }

    if (p2[p2idx] & VMM_PRESENT) {
        p1 = (uint64_t *) PHYS_TO_VIRT(p2[p2idx] & ADDRESS_MASK);
    } else {
        p1 = (uint64_t *) pmm_allocz(1);
        p2[p2idx] = (uint64_t) p1 | VMM_PRESENT;
        p1 = (uint64_t *) PHYS_TO_VIRT(p1);
    }

    p1[p1idx] = ((uint64_t) phys) | flags;
}

uintptr_t AddressSpace::map(size_t len, uint64_t flags, uintptr_t min_addr, uintptr_t max_addr) {
	uintptr_t addr = holes.allocate_any(len * PAGE_SIZE, min_addr, max_addr);
	print("addr found %X\n", addr);
	mappings.push_back(Mapping(addr, len, flags));
	for(size_t i = 0; i < len; i++) {
		print("mapping addr %X", addr + 0x1000 * i);
		_map((uintptr_t)pmm_allocz(1), addr + 0x1000 * i, flags);
	}
	return addr;
}

void AddressSpace::switch_to() {
    print("switching to pagemap at %X\n", this->cr3);
    asm volatile("mov cr3, %0" : : "r"(cr3));
}
