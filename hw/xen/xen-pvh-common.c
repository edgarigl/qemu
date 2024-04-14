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
                                 s->cfg.ram_low.base, ram_size[1]);
        memory_region_add_subregion(sysmem, s->cfg.ram_high.base, &s->ram.high);
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
}
