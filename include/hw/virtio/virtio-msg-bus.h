/*
 * VirtIO MSG bus.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VIRTIO_MSG_BUS_H
#define QEMU_VIRTIO_MSG_BUS_H

#include "qom/object.h"
#include "system/dma.h"
#include "hw/qdev-core.h"
#include "hw/virtio/virtio-msg-prot.h"

#define TYPE_VIRTIO_MSG_BUS "virtio-msg-bus"
DECLARE_INSTANCE_CHECKER(BusState, VIRTIO_MSG_BUS,
                         TYPE_VIRTIO_MSG_BUS)


#define TYPE_VIRTIO_MSG_BUS_DEVICE "virtio-msg-bus-device"
OBJECT_DECLARE_TYPE(VirtIOMSGBusDevice, VirtIOMSGBusDeviceClass,
                    VIRTIO_MSG_BUS_DEVICE)

typedef struct VirtIOMSGBusPort {
    int (*receive)(VirtIOMSGBusDevice *bus, VirtIOMSG *msg);
    bool is_driver;
} VirtIOMSGBusPort;

struct VirtIOMSGBusDeviceClass {
    /*< private >*/
    DeviceClass parent_class;

    DeviceRealize parent_realize;

    /*
     * Ask the bus to receive and process all messages that
     * are readily available. The bus will call the registered
     * VirtIOMSGBusPort.receive() function for each message.
     *
     * Will return immediately if no messages are available.
     */
    void (*process)(VirtIOMSGBusDevice *bd);

    /* Called when the bus connects.  */
    void (*connect)(VirtIOMSGBusDevice *bd);

    /*
     * Called by the transport to send a message and optionally
     * wait for a response.
     */
    int (*send)(VirtIOMSGBusDevice *bd, VirtIOMSG *msg_req,
                VirtIOMSG *msg_resp);

    /*
     * A bus device can construct a view into the guests address-space.
     */
    AddressSpace *(*get_remote_as)(VirtIOMSGBusDevice *bd);
};

typedef struct VirtIOMSGBusDevice {
    DeviceState parent;

    IOMMUTLBEntry (*iommu_translate)(VirtIOMSGBusDevice *bd,
                                     uint64_t va, uint8_t prot);

    /* Out of order queue.  */
    struct {
        VirtIOMSG msg[128];
        int num;
        int pos;
    } ooo_queue;

    /* SW IOMMUs.  */
    int pagemap_fd;
    int virt2gfn_fd;

    const VirtIOMSGBusPort *peer;
    void *opaque;
} VirtIOMSGBusDevice;

static inline VirtIOMSGBusDevice *virtio_msg_bus_get_device(BusState *qbus)
{
    BusChild *kid = QTAILQ_FIRST(&qbus->children);
    DeviceState *qdev = kid ? kid->child : NULL;

    return (VirtIOMSGBusDevice *)qdev;
}

static inline bool virtio_msg_bus_connected(BusState *bus)
{
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);

    return bd && bd->peer != NULL;
}

void virtio_msg_bus_ooo_receive(VirtIOMSGBusDevice *bd,
                                VirtIOMSG *msg_req,
                                VirtIOMSG *msg_resp);
void virtio_msg_bus_ooo_process(VirtIOMSGBusDevice *bd);
void virtio_msg_bus_process(VirtIOMSGBusDevice *bd);

bool virtio_msg_bus_connect(BusState *bus,
                            const VirtIOMSGBusPort *port,
                            void *opaque);

static inline void
virtio_msg_bus_receive(VirtIOMSGBusDevice *bd, VirtIOMSG *msg)
{
    virtio_msg_unpack(msg);
    bd->peer->receive(bd, msg);
}

int virtio_msg_bus_send(BusState *bus,
                        VirtIOMSG *msg_req, VirtIOMSG *msg_resp);

static inline AddressSpace *virtio_msg_bus_get_remote_as(BusState *bus)
{
    VirtIOMSGBusDeviceClass *bdc;

    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));

    if (bdc->get_remote_as) {
        return bdc->get_remote_as(bd);
    }
    return NULL;
}

IOMMUTLBEntry virtio_msg_bus_xen_gfn2mfn_translate(VirtIOMSGBusDevice *bd,
                                                   uint64_t va,
                                                   uint8_t prot);

IOMMUTLBEntry virtio_msg_bus_xen_virt2gfn_translate(VirtIOMSGBusDevice *bd,
                                                    uint64_t va,
                                                    uint8_t prot);

IOMMUTLBEntry virtio_msg_bus_pagemap_translate(VirtIOMSGBusDevice *bd,
                                               uint64_t va,
                                               uint8_t prot);

static inline IOMMUTLBEntry
virtio_msg_bus_iommu_translate(BusState *bus,
                               uint64_t va, uint8_t prot)
{
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    IOMMUTLBEntry dummy = {0};

    if (bd->iommu_translate) {
        return bd->iommu_translate(bd, va, prot);
    }
    return dummy;
}
#endif
