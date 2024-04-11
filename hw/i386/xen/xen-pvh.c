/*
 * QEMU Xen PVH Machine
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "hw/boards.h"
#include "sysemu/sysemu.h"
#include "hw/xen/arch_hvm.h"
#include "hw/xen/xen.h"
#include "hw/xen/xen-pvh-common.h"

#define TYPE_XEN_PVH_X86  MACHINE_TYPE_NAME("xenpvh")
OBJECT_DECLARE_SIMPLE_TYPE(XenPVHx86State, XEN_PVH_X86)

#define PVH_MAX_CPUS 128

struct XenPVHx86State {
    /*< private >*/
    MachineState parent;

    DeviceState *cpu[PVH_MAX_CPUS];
    XenPVHCommonState pvh;
};

enum {
    PVH_MEM,
    PVH_MEM_HIGH,
    PVH_LAPIC,
    PVH_LAPIC_MSI,
    PVH_PCI_ECAM,
    PVH_PCI_MMIO,
    PVH_PCI_MMIO_HIGH,
};

/*
 * This table describes the x86 PVH memory-map.
 * TODO: Probe Xen for the memory-map.
 */
static const MemMapEntry base_memmap[] = {
    [PVH_MEM]           =  {               0, 0x80000000U },     /* 2 GB */
    [PVH_LAPIC]         =  {     0xFEC00000U, 0 },               /* Unmapped */
    [PVH_LAPIC_MSI]     =  {     0xFEE00000U, 0x100000 },
    [PVH_PCI_ECAM]      =  {   0xE0000000ULL, 0x10000000 },      /* 256 MB */
    [PVH_PCI_MMIO]      =  {   0xC0000000ULL, 0x20000000 },      /* 512 MB */

    /* Highmem.  */
    [PVH_MEM_HIGH]      =  {  0x100000000ULL, 0xBF00000000ULL }, /* 764 GB */
    [PVH_PCI_MMIO_HIGH] =  { 0xC000000000ULL, 0x4000000000ULL }, /* 256 GB */
};

static void xenpvh_cpu_new(MachineState *ms,
                           XenPVHx86State *xp,
                           int cpu_idx,
                           int64_t apic_id)
{
    Object *cpu = object_new(ms->cpu_type);

    object_property_add_child(OBJECT(ms), "cpu[*]", cpu);
    object_property_set_uint(cpu, "apic-id", apic_id, &error_fatal);
    qdev_realize(DEVICE(cpu), NULL, &error_fatal);
    object_unref(cpu);

    xp->cpu[cpu_idx] = DEVICE(cpu);
}

static void xenpvh_init(MachineState *machine)
{
    MemoryRegion *sysmem = get_system_memory();
    XenPVHx86State *xp = XEN_PVH_X86(machine);
    int i;

    /* Describe the memory map.  */
    xp->pvh.cfg.ram_low = base_memmap[PVH_MEM];
    xp->pvh.cfg.ram_high = base_memmap[PVH_MEM_HIGH];
    xp->pvh.cfg.pci.ecam = base_memmap[PVH_PCI_ECAM];
    xp->pvh.cfg.pci.mmio = base_memmap[PVH_PCI_MMIO];
    xp->pvh.cfg.pci.mmio_high = base_memmap[PVH_PCI_MMIO_HIGH];
    /* GSI's 16 - 20 are used for legacy PCIe INTX IRQs.  */
    xp->pvh.cfg.pci.intx_irq_base = 16;

    /* Create dummy cores. This will also create the APIC MSI window.  */
    for (i = 0; i < machine->smp.cpus; i++) {
        xenpvh_cpu_new(machine, xp, i, i);
    }

    xen_pvh_common_init(machine, &xp->pvh, sysmem);
}

static void xenpvh_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Xen PVH x86 machine";
    mc->init = xenpvh_init;
    mc->max_cpus = PVH_MAX_CPUS;
    mc->default_cpu_type = TARGET_DEFAULT_CPU_TYPE;
    mc->default_machine_opts = "accel=xen";
    /* Set explicitly here to make sure that real ram_size is passed */
    mc->default_ram_size = 0;
}

static const TypeInfo xenpvh_machine_type = {
    .name = TYPE_XEN_PVH_X86,
    .parent = TYPE_MACHINE,
    .class_init = xenpvh_machine_class_init,
    .instance_size = sizeof(XenPVHx86State),
};

static void xenpvh_machine_register_types(void)
{
    type_register_static(&xenpvh_machine_type);
}

type_init(xenpvh_machine_register_types)
