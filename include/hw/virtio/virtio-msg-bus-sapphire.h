/*
 * VirtIO MSG bus for sapphire with VEK280.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VIRTIO_MSG_BUS_SAPPHIRE_H
#define QEMU_VIRTIO_MSG_BUS_SAPHHIRE_H

#include "qom/object.h"
#include "qemu/vfio-helpers.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/spsc_queue.h"

#define TYPE_VIRTIO_MSG_BUS_SAPPHIRE "virtio-msg-bus-sapphire"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGBusSapphire, VIRTIO_MSG_BUS_SAPPHIRE)
#define VIRTIO_MSG_BUS_SAPPHIRE_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_MSG_BUS_SAPPHIRE)

typedef struct VirtIOMSGBusSapphire {
    VirtIOMSGBusDevice parent;

    EventNotifier notifier;
    QEMUTimer timer;

    struct {
        MemoryRegion mr;
        spsc_queue *driver;
        spsc_queue *device;
        bool flowing;
    } shm_queues;

    struct {
        QEMUVFIOState *dev;

        /* Memmap.  */
        uint8_t *doorbell;
        void *driver;
        void *device;
        void *ram;
    } msg;

    struct {
        char *dev;
        bool reset_queues;

        char *iommu;
    } cfg;
} VirtIOMSGBusSapphire;

#endif
