/*
 * VirtIO MSG bus.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/virtio/virtio-msg-bus.h"

bool virtio_msg_bus_connect(BusState *bus,
                            const VirtIOMSGBusPort *port,
                            void *opaque)
{
    VirtIOMSGBusDeviceClass *bdc;

    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    if (!bd) {
        /* Nothing connected to this virtio-msg device. Ignore. */
        return false;
    }

    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));

    bd->peer = port;
    bd->opaque = opaque;
    if (bdc->connect) {
        bdc->connect(bd, port, opaque);
    }

    return true;
}

static void virtio_msg_bus_class_init(ObjectClass *klass, void *data)
{
    BusClass *bc = BUS_CLASS(klass);

    /*
    bc->print_dev = sysbus_dev_print;
    bc->get_fw_dev_path = sysbus_get_fw_dev_path;
    */
    bc->max_dev = 1;
}

static const TypeInfo virtio_msg_bus_info = {
    .name = TYPE_VIRTIO_MSG_BUS,
    .parent = TYPE_BUS,
    .instance_size = sizeof(BusState),
    .class_init = virtio_msg_bus_class_init,
};

static void virtio_msg_bus_device_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *k = DEVICE_CLASS(klass);
    //k->realize = virtio_msg_bus_device_realize;
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
