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

#ifdef CONFIG_XEN
#include "hw/xen/xen_native.h"
#endif

#include <linux/types.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>

#define IOCTL_VIRT2GFN \
_IOC(_IOC_READ|_IOC_WRITE, 'G', 5, sizeof(struct ioctl_xen_virt2gfn))
struct ioctl_xen_virt2gfn {
    /* Number of pages to map */
    __u32 count;
    /* padding.  */
    __u32 padding;

    /* Variable array with virt address to convert to gfns.  */
    union {
        __u64 addr[1];
        __DECLARE_FLEX_ARRAY(__u64, addr_flex);
    };
};

IOMMUTLBEntry virtio_msg_bus_xen_gfn2mfn_translate(VirtIOMSGBusDevice *bd,
                                                   uint64_t va,
                                                   uint8_t prot)
{
    IOMMUTLBEntry ret = {0};
#ifdef CONFIG_XEN
    hwaddr plen = VIRTIO_MSG_IOMMU_PAGE_SIZE;
    xenmem_access_t access;
    uint64_t mfn;
    void *p;
    int r;

    assert((va & VIRTIO_MSG_IOMMU_PAGE_MASK) == 0);

    p = address_space_map(&address_space_memory, va, &plen,
                          prot & VIRTIO_MSG_IOMMU_PROT_WRITE,
                          MEMTXATTRS_UNSPECIFIED);

    if (!p) {
        return ret;
    }

    ret.iova = va;
    r = xc_domain_gfn2mfn(xen_xc, xen_domid,
                          va >> XC_PAGE_SHIFT, &mfn, &access);
    assert(r == 0);
    ret.translated_addr = mfn << XC_PAGE_SHIFT;
    ret.perm = IOMMU_ACCESS_FLAG(1, 1);

    address_space_unmap(&address_space_memory, p, plen,
                        prot & VIRTIO_MSG_IOMMU_PROT_WRITE,
                        0);
//    printf("%s: %lx.%lx  ->  %lx\n", __func__, va, ret.iova, ret.translated_addr);
#endif
    return ret;
}

IOMMUTLBEntry virtio_msg_bus_xen_virt2gfn_translate(VirtIOMSGBusDevice *bd,
                                                    uint64_t va,
                                                    uint8_t prot)
{
    struct ioctl_xen_virt2gfn op = {0};
    IOMMUTLBEntry ret = {0};
    hwaddr plen = VIRTIO_MSG_IOMMU_PAGE_SIZE;
    void *p;
    int rc;

    if (bd->virt2gfn_fd == -1) {
        bd->virt2gfn_fd = open("/dev/xen/xv2g", O_RDWR);
        if (bd->virt2gfn_fd == -1) {
            printf("failed to open /dev/xen/x2vg!\n");
            return ret;
        }
    }

    assert((va & VIRTIO_MSG_IOMMU_PAGE_MASK) == 0);

    /* The assumption here is that the memory we're trying to access has
     * already previously been mapped via address_space_map().
     * So we're taking a second ref just to get hold of p.
     * But the underlying mapping is expected to live beyond this translation.
     */
    p = address_space_map(&address_space_memory, va, &plen,
                          prot & VIRTIO_MSG_IOMMU_PROT_WRITE,
                          MEMTXATTRS_UNSPECIFIED);

    if (!p) {
        return ret;
    }

    ret.iova = va;
    op.count = 1;
    op.addr[0] = (uintptr_t) p;
    rc = ioctl(bd->virt2gfn_fd, IOCTL_VIRT2GFN, (uintptr_t) &op);
    assert(rc == 0);
    ret.translated_addr = op.addr[0];
    ret.perm = IOMMU_ACCESS_FLAG(prot & VIRTIO_MSG_IOMMU_PROT_READ,
                                 prot & VIRTIO_MSG_IOMMU_PROT_WRITE);

#if 0
    IOMMUTLBEntry ret2 = {0};

    if (bd->pagemap_fd == -1) {
        bd->pagemap_fd = pagemap_open_self();
        if (bd->pagemap_fd == -1) {
            printf("failed to open /proc/self/pagemap!\n");
            return ret;
        }
    }

    ret2.iova = va;
    ret2.translated_addr = pagemap_virt_to_phys_fd(bd->pagemap_fd, p);
    ret2.perm = IOMMU_ACCESS_FLAG(prot & VIRTIO_MSG_IOMMU_PROT_READ,
                                 prot & VIRTIO_MSG_IOMMU_PROT_WRITE);

    if (ret.translated_addr != ret2.translated_addr) {
        printf("%s: iommu missmatch va %lx %lx != %lx\n", __func__,
                va, ret.translated_addr, ret2.translated_addr);
    }
#endif

//    printf("%s: %p %lx.%lx  ->  %lx\n", __func__,
//           p, va, ret.iova, ret.translated_addr);
    return ret;
}

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
            printf("failed to open /proc/self/pagemap!\n");
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
    ret.translated_addr = pagemap_virt_to_phys_fd(bd->pagemap_fd, p);
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
    VirtIOMSGBusDevice *bd = virtio_msg_bus_get_device(bus);
    VirtIOMSGBusDeviceClass *bdc;

    if (!bd) {
        /* Nothing connected to this virtio-msg device. Ignore. */
        return false;
    }

    bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(object_get_class(OBJECT(bd)));
    bd->peer = port;
    bd->opaque = opaque;

    if (bdc->connect) {
        bdc->connect(bd);
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
        virtio_msg_bus_receive(bd, &bd->ooo_queue.msg[pos]);
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
    if (msg_resp->msg_id == VIRTIO_MSG_EVENT_AVAIL ||
            msg_resp->msg_id == VIRTIO_MSG_EVENT_USED ||
            msg_resp->msg_id == VIRTIO_MSG_EVENT_CONFIG) {
        virtio_msg_bus_ooo_enqueue(bd, msg_resp);
    } else {
        virtio_msg_bus_receive(bd, msg_resp);
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
    bd->virt2gfn_fd = -1;
}

static void virtio_msg_bus_class_init(ObjectClass *klass, const void *data)
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

static void virtio_msg_bus_device_class_init(ObjectClass *klass,
                                             const void *data)
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
