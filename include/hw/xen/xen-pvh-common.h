/*
 * QEMU Xen PVH machine - common code.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef XEN_PVH_COMMON_H__
#define XEN_PVH_COMMON_H__

#include <assert.h>
#include "hw/sysbus.h"
#include "hw/hw.h"
#include "hw/xen/xen-hvm-common.h"
#include "hw/pci-host/gpex.h"

#define TYPE_XEN_PVH_COMMON "xen-pvh-common"
OBJECT_DECLARE_SIMPLE_TYPE(XenPVHCommonState, XEN_PVH_COMMON)

typedef struct XenPVHCommonState {
    /*< private >*/
    SysBusDevice parent_obj;

    XenIOState ioreq;

    struct {
        MemoryRegion low;
        MemoryRegion high;
    } ram;

    struct {
        uint64_t ram_size;
        uint32_t max_cpus;
        uint32_t virtio_mmio_num;
        uint32_t virtio_mmio_irq_base;
        struct {
            uint64_t base;
            uint64_t size;
        } ram_low, ram_high,
          virtio_mmio,
          tpm;
    } cfg;
} XenPVHCommonState;
#endif
