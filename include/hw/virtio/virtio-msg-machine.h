/*
 * A machine that is nothing but virtio-msg backends.
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_VIRTIO_VIRTIO_MSG_MACHINE_H
#define HW_VIRTIO_VIRTIO_MSG_MACHINE_H

#include "qom/object.h"
#include "hw/core/boards.h"
#include "hw/core/sysbus.h"
#include "hw/virtio/virtio-msg.h"

struct VirtIOMSGBackend {
    SysBusDevice parent_obj;

    BusState outer_bus;
    VirtIOMSGProxy proxy;
};

#define TYPE_VIRTIO_MSG_BACKEND "virtio-msg-backend"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGBackend, VIRTIO_MSG_BACKEND)

struct VirtIOMSGMachineState {
    MachineState parent_obj;

    VirtIOMSGBackend backends[1];
};

#define TYPE_VIRTIO_MSG_MACHINE "x-virtio-msg-machine"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGMachineState, VIRTIO_MSG_MACHINE)
#endif
