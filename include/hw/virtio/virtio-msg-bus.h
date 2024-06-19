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
};

typedef struct VirtIOMSGBusDevice {
    DeviceState parent;

    const VirtIOMSGBusPort *peer;
    void *opaque;
} VirtIOMSGBusDevice;

static inline VirtIOMSGBusDevice *virtio_msg_bus_get_device(BusState *qbus)
{
    BusChild *kid = QTAILQ_FIRST(&qbus->children);
    DeviceState *qdev = kid ? kid->child : NULL;

    return (VirtIOMSGBusDevice *)qdev;
}

static inline void virtio_msg_bus_connect(BusState *bus,
                                          const VirtIOMSGBusPort *port,
                                          void *opaque)
{
    VirtIOMSGBusDeviceClass *bdc;

    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));

    bd->peer = port;
    bd->opaque = opaque;
    if (bdc->connect) {
        bdc->connect(bd, port, opaque);
    }
}

static inline bool virtio_msg_bus_connected(BusState *bus)
{
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);

    return bd && bd->peer != NULL;
}

static inline void virtio_msg_bus_process(BusState *bus)
{
    VirtIOMSGBusDeviceClass *bdc;

    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));

    if (bdc->process) {
        bdc->process(bd);
    }
}

static inline int virtio_msg_bus_send(BusState *bus,
                                      VirtIOMSG *msg_req,
                                      VirtIOMSG *msg_resp)
{
    VirtIOMSGBusDeviceClass *bdc;
    int r = VIRTIO_MSG_NO_ERROR;

    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));

    if (bdc->send) {
        r = bdc->send(bd, msg_req, msg_resp);
    }
    return r;
}
#endif
