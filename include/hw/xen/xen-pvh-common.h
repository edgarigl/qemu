/*
 * QEMU Xen PVH machine common code.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef XEN_PVH_COMMON_H__
#define XEN_PVH_COMMON_H__

#include <assert.h>
#include "hw/hw.h"
#include "hw/xen/xen-hvm-common.h"
#include "hw/pci-host/gpex.h"

typedef struct XenPVHCommonState {
    XenIOState ioreq;

    struct {
        MemoryRegion low;
        MemoryRegion high;
    } ram;

    struct {
        GPEXHost gpex;
        MemoryRegion ecam_alias;
        MemoryRegion mmio_alias;
        MemoryRegion mmio_high_alias;
    } pci;

    struct {
        MemMapEntry ram_low;
        MemMapEntry ram_high;

        struct {
            MemMapEntry ecam;
            MemMapEntry mmio;
            MemMapEntry mmio_high;

            int intx_irq_base;
        } pci;
    } cfg;
} XenPVHCommonState;

void xen_pvh_common_init(MachineState *machine, XenPVHCommonState *s,
                         MemoryRegion *sysmem);
#endif
