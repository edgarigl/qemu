/*
 * VirtIO MSG proxy driver.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VIRTIO_MSG_PROXY_DRIVER_H
#define QEMU_VIRTIO_MSG_PROXY_DRIVER_H

#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "qom/object.h"

#define TYPE_VIRTIO_MSG_PROXY_DRIVER "virtio-msg-proxy-driver"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGProxyDriver, VIRTIO_MSG_PROXY_DRIVER)
#define VIRTIO_MSG_PROXY_DRIVER_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_MSG_PROXY_DRIVER)

struct VirtIOMSGProxyDriver {
    VirtIODevice parent_obj;

    BusState bus;
    VirtQueue *vq;

    struct {
        uint16_t virtio_id;
        bool iommu_enable;
    } cfg;
};
#endif
