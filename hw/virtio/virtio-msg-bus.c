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
#include "hw/virtio/pagemap.h"
#include "hw/virtio/virtio-msg-bus.h"


IOMMUTLBEntry virtio_msg_bus_pagemap_translate(VirtIOMSGBusDevice *bd,
                                               uint64_t va,
                                               uint8_t prot)
{
    IOMMUTLBEntry ret = {0};
    hwaddr plen = VIRTIO_MSG_IOMMU_PAGE_SIZE;
    void *p;

    if (bd->pagemap_fd == -1) {
        bd->pagemap_fd = pagemap_open_self();
        if (bd->pagemap_fd == -1) {
            return ret;
        }
    }

    assert((va & VIRTIO_MSG_IOMMU_PAGE_MASK) == 0);

    p = address_space_map(&address_space_memory, va, &plen,
                          prot & VIRTIO_MSG_IOMMU_PROT_WRITE,
                          MEMTXATTRS_UNSPECIFIED);

    if (!p) {
        return ret;
    }

    ret.iova = va;
    ret.translated_addr = pagemap_virt_to_phys(p);
    ret.perm = IOMMU_ACCESS_FLAG(prot & VIRTIO_MSG_IOMMU_PROT_READ,
                                 prot & VIRTIO_MSG_IOMMU_PROT_WRITE);

    address_space_unmap(&address_space_memory, p, plen,
                        prot & VIRTIO_MSG_IOMMU_PROT_WRITE,
                        0);

//    printf("%s: %lx.%lx  ->  %lx\n", __func__, va, ret.iova, ret.translated_addr);
    return ret;
}


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

static inline void virtio_msg_bus_ooo_enqueue(VirtIOMSGBusDevice *bd,
                                              VirtIOMSG *msg)
{
    /* TODO: Add support for wrapping the queue.  */
    assert(bd->ooo_queue.num < ARRAY_SIZE(bd->ooo_queue.msg));
    bd->ooo_queue.msg[bd->ooo_queue.num++] = *msg;
}

void virtio_msg_bus_ooo_process(VirtIOMSGBusDevice *bd)
{
    while (bd->ooo_queue.pos < bd->ooo_queue.num) {
        int pos = bd->ooo_queue.pos++;
        bd->peer->receive(bd, &bd->ooo_queue.msg[pos]);
    }
    bd->ooo_queue.num = 0;
    bd->ooo_queue.pos = 0;
}

void virtio_msg_bus_ooo_receive(VirtIOMSGBusDevice *bd,
                                VirtIOMSG *msg_req,
                                VirtIOMSG *msg_resp)
{
    /*
     * Event notifications are posted and shouldn't be handled immediately
     * because they may trigger additional recursive requests further
     * further complicating the situation.
     *
     * Instead, queue events and wait for the notification path to re-trigger
     * processing of messages and process the OOO queue there.
     */
    if (msg_resp->id == VIRTIO_MSG_EVENT_AVAIL ||
            msg_resp->id == VIRTIO_MSG_EVENT_USED ||
            msg_resp->id == VIRTIO_MSG_EVENT_CONF) {
        virtio_msg_bus_ooo_enqueue(bd, msg_resp);
    } else {
        bd->peer->receive(bd, msg_resp);
    }
}

void virtio_msg_bus_process(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusDeviceClass *bdc;
    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));

    virtio_msg_bus_ooo_process(bd);
    bdc->process(bd);
}

int virtio_msg_bus_send(BusState *bus,
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

static void virtio_msg_bus_device_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(dev);

    bd->pagemap_fd = -1;
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

    k->realize = virtio_msg_bus_device_realize;
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
