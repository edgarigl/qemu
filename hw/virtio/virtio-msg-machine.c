/*
 * A machine that is nothing but virtio-msg backends.
 *
 * There is no CPU, no interrupt controller and no board device here.  The
 * machine exists so a QEMU process can act purely as the device side of a
 * virtio-msg link: it creates the proxy, and the bus device that reaches the
 * peer is plugged onto the proxy's msg-bus from the command line, e.g.
 *
 *   qemu-system-aarch64 -M x-virtio-msg -m 2G -accel qtest \
 *       -device virtio-msg-bus-user,dev=/dev/virtio-msg-0 \
 *       -device virtio-net-device,netdev=n0 ...
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "qemu/target-info.h"
#include "system/dma.h"
#include "system/memory.h"
#include "hw/core/qdev.h"
#include "hw/virtio/virtio-msg-machine.h"

/*
 * The proxy has dc->bus_type set, so it has to be realized onto an outer bus,
 * and a bus in turn has to belong to a device.  On a board that device is the
 * thing carrying the link -- the AMP PCI endpoint, say.  Here there is none,
 * so this holds the bus and nothing else.
 */
static void virtio_msg_backend_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBackend *s = VIRTIO_MSG_BACKEND(dev);

    qbus_init(&s->outer_bus, sizeof(s->outer_bus),
              TYPE_VIRTIO_MSG_OUTER_BUS, dev, "outer");

    object_initialize_child(OBJECT(s), "proxy", &s->proxy, TYPE_VIRTIO_MSG);
    qdev_realize(DEVICE(&s->proxy), BUS(&s->outer_bus), errp);
}

static void virtio_msg_backend_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = virtio_msg_backend_realize;
}

static const TypeInfo virtio_msg_backend_info = {
    .name          = TYPE_VIRTIO_MSG_BACKEND,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGBackend),
    .class_init    = virtio_msg_backend_class_init,
};

static void virtio_msg_machine_init(MachineState *machine)
{
    VirtIOMSGMachineState *s = VIRTIO_MSG_MACHINE(machine);
    int i;

    for (i = 0; i < ARRAY_SIZE(s->backends); i++) {
        object_initialize_child(OBJECT(s), "backend[*]", &s->backends[i],
                                TYPE_VIRTIO_MSG_BACKEND);
        sysbus_realize(SYS_BUS_DEVICE(&s->backends[i]), &error_fatal);
    }
}

static void virtio_msg_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->init = virtio_msg_machine_init;
    mc->desc = "Experimental virtio-msg machine";
}

static const TypeInfo virtio_msg_machine = {
    .name = TYPE_VIRTIO_MSG_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(VirtIOMSGMachineState),
    .class_init = virtio_msg_machine_class_init,
};

static void virtio_msg_machine_register_types(void)
{
    /*
     * -M only lists machines implementing the running target's machine
     * interface.  Unlike the machines that name theirs literally, this file is
     * compiled once for every target rather than per target, so ask which one
     * we are.  type_new() copies the strings, so the stack is fine here.
     */
    InterfaceInfo ifs[] = {
        { TYPE_HOTPLUG_HANDLER },
        { target_machine_typename() },
        { }
    };
    TypeInfo ti = virtio_msg_machine;

    type_register_static(&virtio_msg_backend_info);

    ti.interfaces = ifs;
    type_register_static(&ti);
}

type_init(virtio_msg_machine_register_types);
