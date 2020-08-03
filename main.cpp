#include <sys/gdt.hpp>
#include <sys/idt.hpp>
#include <sys/pci.hpp>
#include <sys/apic.hpp>
#include <sys/hpet.hpp>
#include <sys/cpu.hpp>
#include <mm/pmm.hpp>
#include <lib/stivale.hpp>
#include <lib/dmesg.hpp>
#include <lib/print.hpp>
#include <lib/alarm.hpp>
#include <acpi/acpi.hpp>
#include <mm/vmm.hpp>

extern "C" void main(Stivale *sti) {
    gdt_init();
    idt_init();
    pmm_init(sti->memmap);
    dmesg_enable();
    print("Lyre says hello world!\n");

    acpi_init((RSDP *)sti->rsdp);
    apic_init();
    hpet_init();
    cpu_init();

    alarm_init();
    pci_init();
	//AddressSpaceHoles holes = AddressSpaceHoles();
	//holes.allocate_any(0x10000, 0xffffffff80000000, 0xffffffffffffffff);
//	holes.allocate_any(0x10000, 0xffff800000000000, 0xffffffffffffffff);
//	holes.deallocate(0, 0x100010);
//	print("allocated\n");
//	holes.dump_holes();
	auto space = new AddressSpace();
	space->map(10, 1, 0xffffffff80000000, 0xffffffffffffffff);
	print("done\n");
	space->holes.dump_holes();
	space->switch_to();

    for (;;) {
        asm volatile ("hlt":::"memory");
    }
}
