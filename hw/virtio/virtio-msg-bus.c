/*
 * VirtIO MSG bus.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/virtio/virtio-msg-bus.h"

bool virtio_msg_bus_connect(BusState *bus,
                            const VirtIOMSGBusPort *port,
                            void *opaque)
{
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);

    if (!bd) {
        /* Nothing connected to this virtio-msg device. Ignore. */
        return false;
    }

    bd->peer = port;
    bd->opaque = opaque;
    return true;
}

void virtio_msg_bus_process(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusDeviceClass *bdc;
    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));

    bdc->process(bd);
}

int virtio_msg_bus_send(BusState *bus, VirtIOMSG *msg_req)
{
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    VirtIOMSGBusDeviceClass *bdc;
    int r = VIRTIO_MSG_NO_ERROR;

    if (!bd || !bd->peer) {
        return VIRTIO_MSG_ERROR_RETRY;
    }

    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));

    if (bdc->send) {
        r = bdc->send(bd, msg_req);
    }
    return r;
}

int virtio_msg_bus_send_must_deliver(BusState *bus, VirtIOMSG *msg_req)
{
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    VirtIOMSGBusDeviceClass *bdc;

    if (!bd || !bd->peer) {
        return VIRTIO_MSG_ERROR_RETRY;
    }

    bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(object_get_class(OBJECT(bd)));
    if (bdc->send_must_deliver) {
        return bdc->send_must_deliver(bd, msg_req);
    }

    return virtio_msg_bus_send(bus, msg_req);
}

void virtio_msg_bus_get_transport_caps(BusState *bus,
                                       VirtIOMSGTransportCaps *caps)
{
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    VirtIOMSGBusDeviceClass *bdc;

    *caps = (VirtIOMSGTransportCaps) {
        .dma_as = &address_space_memory,
        .revision = VIRTIO_MSG_TRANSPORT_REVISION,
        .max_msg_size = VIRTIO_MSG_MAX_SIZE,
    };
    if (!bd) {
        return;
    }

    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));
    if (bdc->get_transport_caps) {
        bdc->get_transport_caps(bd, caps);
        return;
    }

    caps->ready = true;
}

static void virtio_msg_bus_class_init(ObjectClass *klass, const void *data)
{
    BusClass *bc = BUS_CLASS(klass);

    bc->max_dev = 1;
}

static const TypeInfo virtio_msg_bus_info = {
    .name = TYPE_VIRTIO_MSG_BUS,
    .parent = TYPE_BUS,
    .instance_size = sizeof(BusState),
    .class_init = virtio_msg_bus_class_init,
};

static void virtio_msg_bus_device_class_init(ObjectClass *klass,
                                             const void *data)
{
    DeviceClass *k = DEVICE_CLASS(klass);

    k->bus_type = TYPE_VIRTIO_MSG_BUS;
}

static const TypeInfo virtio_msg_bus_device_type_info = {
    .name = TYPE_VIRTIO_MSG_BUS_DEVICE,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(VirtIOMSGBusDevice),
    .abstract = true,
    .class_size = sizeof(VirtIOMSGBusDeviceClass),
    .class_init = virtio_msg_bus_device_class_init,
};

static void virtio_msg_bus_register_types(void)
{
    type_register_static(&virtio_msg_bus_info);
    type_register_static(&virtio_msg_bus_device_type_info);
}

type_init(virtio_msg_bus_register_types)
