/*
 * VirtIO MSG bus over IVSHMEM.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VIRTIO_MSG_BUS_IVSHMEM_H
#define QEMU_VIRTIO_MSG_BUS_IVSHMEM_H

#include "qom/object.h"
#include "qemu/vfio-helpers.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/spsc_queue.h"

#define TYPE_VIRTIO_MSG_BUS_IVSHMEM "virtio-msg-bus-ivshmem"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGBusIVSHMEM, VIRTIO_MSG_BUS_IVSHMEM)
#define VIRTIO_MSG_BUS_IVSHMEM_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_MSG_BUS_IVSHMEM)

typedef struct VirtIOMSGBusIVSHMEM {
    VirtIOMSGBusDevice parent;

    QEMUVFIOState *mem_dev;
    EventNotifier notifier;

    struct {
        spsc_queue *driver;
        spsc_queue *device;
    } shm_queues;

    struct {
        QEMUVFIOState *dev;

        /* Memmap.  */
        uint8_t *doorbell;
        void *driver;
        void *device;
    } msg;

    struct {
        QEMUVFIOState *dev;

        /* Memmap.  */
        void *mem;
    } mem;

    struct {
        char *msg_dev;
        char *mem_dev;
        uint64_t mem_size;
        uint32_t remote_vmid;
    } cfg;
} VirtIOMSGBusIVSHMEM;

#endif
