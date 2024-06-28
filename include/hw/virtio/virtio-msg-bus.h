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

    void (*connect)(VirtIOMSGBusDevice *bd, const VirtIOMSGBusPort *port,
                    void *opaque);
    void (*process)(VirtIOMSGBusDevice *bd);
    int (*send)(VirtIOMSGBusDevice *bd, VirtIOMSG *msg_req,
                VirtIOMSG *msg_resp);

    /*
     * A bus device can construct a view into the guests address-space.
     */
    AddressSpace *(*get_remote_as)(VirtIOMSGBusDevice *bd);
};

typedef struct VirtIOMSGBusDevice {
    DeviceState parent;

    /* Out of order queue.  */
    struct {
        VirtIOMSG msg[128];
        int num;
        int pos;
    } ooo_queue;

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
#endif
