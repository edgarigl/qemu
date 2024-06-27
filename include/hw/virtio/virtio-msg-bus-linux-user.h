/*
 * VirtIO MSG bus between user-space proccesses on the same Linux host.
 * A QEMU Chardev (preferably UNIX sockets) is used for notifications
 * and an SPSC shared memory queue is used to move virtio-msg messages.
 *
 * The SPSC was borrowed from switchboard:
 * https://github.com/zeroasiccorp/switchboard/
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VIRTIO_MSG_BUS_LINUX_USER_H
#define QEMU_VIRTIO_MSG_BUS_LINUX_USER_H

#include "qom/object.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "sysemu/hostmem.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/spsc_queue.h"

#define TYPE_VIRTIO_MSG_BUS_LINUX_USER "virtio-msg-bus-linux-user"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGBusLinuxUser, VIRTIO_MSG_BUS_LINUX_USER)
#define VIRTIO_MSG_BUS_LINUX_USER_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_MSG_BUS_LINUX_USER)

typedef struct VirtIOMSGBusLinuxUser {
    VirtIOMSGBusDevice parent;

    AddressSpace as;
    MemoryRegion mr;
    MemoryRegion mr_lowmem;
    MemoryRegion mr_highmem;
    MemoryRegion *mr_memdev;

    struct {
        spsc_queue *driver;
        spsc_queue *device;
    } shm_queues;

    struct {
        char *name;
        CharBackend chr;
        HostMemoryBackend *memdev;

        /* FIXME: Need a better way  */
        uint64_t mem_offset;
        uint64_t mem_low_size;
        uint64_t mem_hole;
    } cfg;
} VirtIOMSGBusLinuxUser;

#endif
