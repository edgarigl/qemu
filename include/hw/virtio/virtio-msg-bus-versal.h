/*
 * Virtio-msg bus for versal designs.
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VIRTIO_MSG_BUS_VERSAL_H
#define QEMU_VIRTIO_MSG_BUS_VERSAL_H

#include "qom/object.h"
#include "qemu/vfio-helpers.h"
#include "sysemu/hostmem.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/spsc_queue.h"

#define TYPE_VIRTIO_MSG_BUS_VERSAL "virtio-msg-bus-versal"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGBusVersal,
                           VIRTIO_MSG_BUS_VERSAL)
#define VIRTIO_MSG_BUS_VERSAL_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_MSG_BUS_VERSAL)

typedef struct VirtIOMSGBusVersal {
    VirtIOMSGBusDevice parent;

    AddressSpace as;
    MemoryRegion mr;
    MemoryRegion mr_host;
    MemoryRegion mr_host_ram;
    MemoryRegion mr_host_ram_alias;

    EventNotifier notifier;

    struct {
        spsc_queue driver;
        spsc_queue device;
    } shm_queues;

    struct {
        int fd;
        int fd_devmem;

        /* Memmap.  */
        uint32_t *doorbell;
        uint32_t *irq;
        uint32_t *cfg_bram;
        void *driver;
        void *device;
        void *host;
    } msg;

    struct {
        char *dev;
        bool reset_queues;
        uint64_t spsc_base;
        uint64_t doorbell_base;
        uint64_t bram_base;
        uint64_t irq_base;
        uint64_t mem_offset;
        uint64_t mem_size;

        char *iommu;
    } cfg;
} VirtIOMSGBusVersal;
#endif
