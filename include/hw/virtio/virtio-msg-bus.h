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
#include "hw/core/qdev.h"
#include "hw/virtio/virtio-msg-prot.h"

#define TYPE_VIRTIO_MSG_BUS "virtio-msg-bus"
DECLARE_INSTANCE_CHECKER(BusState, VIRTIO_MSG_BUS,
                         TYPE_VIRTIO_MSG_BUS)


#define TYPE_VIRTIO_MSG_BUS_DEVICE "virtio-msg-bus-device"
OBJECT_DECLARE_TYPE(VirtIOMSGBusDevice, VirtIOMSGBusDeviceClass,
                    VIRTIO_MSG_BUS_DEVICE)

typedef struct VirtIOMSGBusPort {
    int (*receive)(VirtIOMSGBusDevice *bd, VirtIOMSG *msg);
    bool is_driver;
} VirtIOMSGBusPort;

typedef struct VirtIOMSGTransportCaps {
    AddressSpace *dma_as;
    uint64_t extra_features;
    uint64_t transport_features;
    uint32_t revision;
    uint16_t max_msg_size;
    bool ready;
} VirtIOMSGTransportCaps;

struct VirtIOMSGBusDeviceClass {
    /*< private >*/
    DeviceClass parent_class;

    DeviceRealize parent_realize;
    DeviceUnrealize parent_unrealize;

    /*
     * Ask the bus to receive and process all messages that
     * are readily available. The bus will call the registered
     * VirtIOMSGBusPort.receive() function for each message.
     *
     * Will return immediately if no messages are available.
     */
    void (*process)(VirtIOMSGBusDevice *bd);

    /*
     * Called by the transport to send a message.
     */
    int (*send)(VirtIOMSGBusDevice *bd, VirtIOMSG *msg_req);

    /* Send protocol responses and events that must not be dropped. */
    int (*send_must_deliver)(VirtIOMSGBusDevice *bd, VirtIOMSG *msg_req);

    /*
     * A bus device can construct a view into the guests address-space.
     */
    AddressSpace *(*get_remote_as)(VirtIOMSGBusDevice *bd);

    /* Return the stable capabilities exported by this bus instance. */
    void (*get_transport_caps)(VirtIOMSGBusDevice *bd,
                               VirtIOMSGTransportCaps *caps);
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

static inline bool virtio_msg_bus_connected(BusState *bus)
{
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);

    return bd && bd->peer != NULL;
}

void virtio_msg_bus_process(VirtIOMSGBusDevice *bd);

bool virtio_msg_bus_connect(BusState *bus,
                            const VirtIOMSGBusPort *port,
                            void *opaque);

static inline int
virtio_msg_bus_receive(VirtIOMSGBusDevice *bd, VirtIOMSG *msg)
{
    if (!bd || !bd->peer) {
        return VIRTIO_MSG_ERROR_RETRY;
    }

    virtio_msg_unpack(msg);
    return bd->peer->receive(bd, msg);
}

int virtio_msg_bus_send(BusState *bus, VirtIOMSG *msg_req);
int virtio_msg_bus_send_must_deliver(BusState *bus, VirtIOMSG *msg_req);
void virtio_msg_bus_get_transport_caps(BusState *bus,
                                       VirtIOMSGTransportCaps *caps);

static inline AddressSpace *virtio_msg_bus_get_remote_as(BusState *bus)
{
    VirtIOMSGBusDeviceClass *bdc;
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);

    /*
     * A virtio device can be plugged before -- or without -- the bus device
     * that reaches the peer.  There is no remote address space to hand out
     * yet, so name the local one rather than dereferencing NULL.
     */
    if (!bd) {
        return &address_space_memory;
    }

    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));

    if (bdc->get_remote_as) {
        return bdc->get_remote_as(bd);
    }

    return &address_space_memory;
}
#endif
