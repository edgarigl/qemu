/*
 * Common Xen PVH code.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "sysemu/sysemu.h"
#include "hw/xen/xen-pvh-common.h"
#include "trace.h"

static const MemoryListener xen_memory_listener = {
    .region_add = xen_region_add,
    .region_del = xen_region_del,
    .log_start = NULL,
    .log_stop = NULL,
    .log_sync = NULL,
    .log_global_start = NULL,
    .log_global_stop = NULL,
    .priority = MEMORY_LISTENER_PRIORITY_ACCEL,
};

static void xen_pvh_init_ram(MachineState *machine, XenPVHCommonState *s,
                             MemoryRegion *sysmem)
{
    ram_addr_t block_len, ram_size[2];

    if (machine->ram_size <= s->cfg.ram_low.size) {
        ram_size[0] = machine->ram_size;
        ram_size[1] = 0;
        block_len = s->cfg.ram_low.base + ram_size[0];
    } else {
        ram_size[0] = s->cfg.ram_low.size;
        ram_size[1] = machine->ram_size - s->cfg.ram_low.size;
        block_len = s->cfg.ram_high.base + ram_size[1];
    }

    memory_region_init_ram(&xen_memory, NULL, "xen.ram", block_len,
                           &error_fatal);

    memory_region_init_alias(&s->ram.low, NULL, "xen.ram.lo", &xen_memory,
                             s->cfg.ram_low.base, ram_size[0]);
    memory_region_add_subregion(sysmem, s->cfg.ram_low.base, &s->ram.low);
    if (ram_size[1] > 0) {
        memory_region_init_alias(&s->ram.high, NULL, "xen.ram.hi", &xen_memory,
                                 s->cfg.ram_high.base, ram_size[1]);
        memory_region_add_subregion(sysmem, s->cfg.ram_high.base, &s->ram.high);
    }
}

static void xen_set_pci_intx_irq(void *opaque, int irq, int level)
{
    if (xendevicemodel_set_pci_intx_level(xen_dmod, xen_domid,
                0, 0, 0, irq % 4, level)) {
        error_report("xendevicemodel_set_pci_intx_level failed");
    }
}

static inline void xenpvh_gpex_init(MachineState *ms,
                                    XenPVHCommonState *s,
                                    MemoryRegion *sysmem,
                                    hwaddr ecam_base, hwaddr ecam_size,
                                    hwaddr mmio_base, hwaddr mmio_size,
                                    hwaddr mmio_high_base,
                                    hwaddr mmio_high_size,
                                    int intx_irq_base)
{
    MemoryRegion *ecam_reg;
    MemoryRegion *mmio_reg;
    DeviceState *dev;
    int i;

    object_initialize_child(OBJECT(ms), "gpex", &s->pci.gpex,
                            TYPE_GPEX_HOST);
    dev = DEVICE(&s->pci.gpex);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);

    ecam_reg = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0);
    memory_region_init_alias(&s->pci.ecam_alias, OBJECT(dev), "pcie-ecam",
                             ecam_reg, 0, ecam_size);
    memory_region_add_subregion(sysmem, ecam_base, &s->pci.ecam_alias);

    mmio_reg = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 1);
    memory_region_init_alias(&s->pci.mmio_alias, OBJECT(dev), "pcie-mmio",
                             mmio_reg, mmio_base, mmio_size);
    memory_region_add_subregion(sysmem, mmio_base, &s->pci.mmio_alias);

    if (mmio_high_size) {
        memory_region_init_alias(&s->pci.mmio_high_alias, OBJECT(dev),
                "pcie-mmio-high",
                mmio_reg, mmio_high_base, mmio_high_size);
        memory_region_add_subregion(sysmem, mmio_high_base,
                &s->pci.mmio_high_alias);
    }

    for (i = 0; i < GPEX_NUM_IRQS; i++) {
        qemu_irq irq = qemu_allocate_irq(xen_set_pci_intx_irq, NULL,
                                         intx_irq_base + i);

        sysbus_connect_irq(SYS_BUS_DEVICE(dev), i, irq);
        gpex_set_irq_num(GPEX_HOST(dev), i, intx_irq_base + i);
        xen_set_pci_link_route(i, intx_irq_base + i);
    }
}

void xen_pvh_common_init(MachineState *machine, XenPVHCommonState *s,
                         MemoryRegion *sysmem)
{
    if (machine->ram_size == 0) {
        warn_report("%s non-zero ram size not specified. QEMU machine started"
                    " without IOREQ (no emulated devices including virtio)",
                    MACHINE_CLASS(object_get_class(OBJECT(machine)))->desc);
        return;
    }

    xen_pvh_init_ram(machine, s, sysmem);
    xen_register_ioreq(&s->ioreq, machine->smp.cpus, &xen_memory_listener);

    if (s->cfg.pci.ecam.size) {
        xenpvh_gpex_init(machine, s, sysmem,
                         s->cfg.pci.ecam.base, s->cfg.pci.ecam.size,
                         s->cfg.pci.mmio.base, s->cfg.pci.mmio.size,
                         s->cfg.pci.mmio_high.base, s->cfg.pci.mmio_high.size,
                         s->cfg.pci.intx_irq_base);
    }
}
