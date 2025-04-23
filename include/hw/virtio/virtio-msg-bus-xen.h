/*
 * VirtIO MSG bus on top of Xen. 
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VIRTIO_MSG_BUS_XEN_H
#define QEMU_VIRTIO_MSG_BUS_XEN_H

#include "qom/object.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/spsc_queue.h"

#define TYPE_VIRTIO_MSG_BUS_XEN "virtio-msg-bus-xen"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGBusXen, VIRTIO_MSG_BUS_XEN)
#define VIRTIO_MSG_BUS_XEN_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_MSG_BUS_XEN)

typedef struct VirtIOMSGBusXen {
    VirtIOMSGBusDevice parent;

    struct {
        xenevtchn_handle *eh;

        char *shm;
        uint16_t port;
        evtchn_port_t local_port;

        bool connected;
    } xen;

    struct {
        spsc_queue *driver;
        spsc_queue *device;
    } shm_queues;

    struct {
        uint64_t shm_base;
        uint64_t shm_gnt_ref;
        uint32_t bus_id;
    } cfg;
} VirtIOMSGBusXen;
#endif
