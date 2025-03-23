/*
 * Virtio MSG bindings
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/virtio-msg.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "trace.h"

#define TYPE_VIRTIO_MSG_IOMMU_MEMORY_REGION "virtio-msg-iommu-memory-region"

static void virtio_msg_device_info(VirtIOMSGProxy *s,
                                   VirtIOMSG *msg)
{
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    uint32_t device_id = 0;
    VirtIOMSG msg_resp;

    if (vdev) {
        device_id = vdev->device_id;
    } else {
        printf("%s: No virtio device on bus %s!\n",
                __func__, BUS(&s->bus)->name);
    }

    virtio_msg_pack_get_device_info_resp(&msg_resp, device_id,
                                         VIRTIO_MSG_VENDOR_ID,
                                         64, /* feature bits.  */
                                         vdev->config_len);
    virtio_msg_bus_send(&s->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_get_features(VirtIOMSGProxy *s,
                                    VirtIOMSG *msg)
{
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_GET_CLASS(vdev);
    VirtIOMSG msg_resp;
    uint64_t features;

    /*
     * The peer's host_features shouldn't matter here. When we're
     * connected to a QEMU proxy, we need to advertise our local
     * host features and not anything provided by the proxy.
     */
    features = vdc->get_features(vdev, vdev->host_features, &error_abort);

    virtio_msg_pack_get_features_resp(&msg_resp, 0, 2, features);
    virtio_msg_bus_send(&s->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_set_features(VirtIOMSGProxy *s,
                                    VirtIOMSG *msg)
{
    VirtIOMSG msg_resp;

    s->guest_features = msg->set_features.features;

    virtio_msg_pack_set_features_resp(&msg_resp, 0, 2, s->guest_features);
    virtio_msg_bus_send(&s->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_soft_reset(VirtIOMSGProxy *s)
{
    virtio_bus_reset(&s->bus);
    s->guest_features = 0;
}

static void virtio_msg_set_device_status(VirtIOMSGProxy *s,
                                         VirtIOMSG *msg)
{
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    uint32_t status = msg->set_device_status.status;
    VirtIOMSG msg_resp;

    printf("set_device_status: %x %x\n", status, vdev->status);

    if (!(status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        virtio_bus_stop_ioeventfd(&s->bus);
    }

    if (status & VIRTIO_CONFIG_S_FEATURES_OK) {
        virtio_set_features(vdev, s->guest_features);
    }

    virtio_set_status(vdev, status);
    assert(vdev->status == status);

    if (status & VIRTIO_CONFIG_S_DRIVER_OK) {
        virtio_bus_start_ioeventfd(&s->bus);
    }

    if (status == 0) {
        virtio_msg_soft_reset(s);
    }

    virtio_msg_pack_set_device_status_resp(&msg_resp, vdev->status);
    virtio_msg_bus_send(&s->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_get_device_status(VirtIOMSGProxy *s,
                                         VirtIOMSG *msg)
{
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    VirtIOMSG msg_resp;

    virtio_msg_pack_get_device_status_resp(&msg_resp, vdev->status);
    virtio_msg_print(&msg_resp);
    virtio_msg_bus_send(&s->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_get_config(VirtIOMSGProxy *s,
                                  VirtIOMSG *msg)
{
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    uint32_t size = msg->get_config.size;
    uint32_t offset = msg->get_config.offset;
    uint64_t data = 0;
    VirtIOMSG msg_resp;

    switch (size) {
    case 4:
        data = virtio_config_modern_readl(vdev, offset);
        break;
    case 2:
        data = virtio_config_modern_readw(vdev, offset);
        break;
    case 1:
        data = virtio_config_modern_readb(vdev, offset);
        break;
    case 0:
        /* Used to read the generation count.  */
        break;
    default:
        g_assert_not_reached();
        break;
    }

    virtio_msg_pack_get_config_resp(&msg_resp, size, offset,
                                    vdev->generation, data);
    virtio_msg_bus_send(&s->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_set_config(VirtIOMSGProxy *s,
                                  VirtIOMSG *msg)
{
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    uint32_t size = msg->set_config.size;
    uint32_t offset = msg->set_config.offset;
    uint64_t data = msg->set_config.data;
    VirtIOMSG msg_resp;

    switch (size) {
    case 4:
        virtio_config_modern_writel(vdev, offset, data);
        break;
    case 2:
        virtio_config_modern_writew(vdev, offset, data);
        break;
    case 1:
        virtio_config_modern_writeb(vdev, offset, data);
        break;
    default:
        g_assert_not_reached();
        break;
    }

    virtio_msg_pack_set_config_resp(&msg_resp, size, offset,
                                    vdev->generation, data);
    virtio_msg_bus_send(&s->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_get_vqueue(VirtIOMSGProxy *s,
                                  VirtIOMSG *msg)
{
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    VirtIOMSG msg_resp;
    uint32_t max_size = VIRTQUEUE_MAX_SIZE;
    uint32_t index = msg->get_vqueue.index;
    hwaddr desc, avail, used;
    uint32_t size;

    size = virtio_queue_get_num(vdev, index);
    if (!size) {
        max_size = 0;
    }

    virtio_queue_get_rings(vdev, index, &desc, &avail, &used);

    virtio_msg_pack_get_vqueue_resp(&msg_resp, index, max_size, size,
                                    desc, avail, used);
    virtio_msg_bus_send(&s->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_set_vqueue(VirtIOMSGProxy *s,
                                  VirtIOMSG *msg)
{
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    hwaddr desc, avail, used;
    VirtIOMSG msg_resp;
    uint32_t index = msg->set_vqueue.index;
    uint32_t size;

    virtio_queue_set_num(vdev, index, msg->set_vqueue.size);
    virtio_queue_set_rings(vdev, index,
                           msg->set_vqueue.descriptor_addr,
                           msg->set_vqueue.driver_addr,
                           msg->set_vqueue.device_addr);
    virtio_queue_enable(vdev, index);

    size = virtio_queue_get_num(vdev, index);
    virtio_queue_get_rings(vdev, index, &desc, &avail, &used);
    virtio_msg_pack_set_vqueue_resp(&msg_resp, index, size,
                                    desc, avail, used);
    virtio_msg_bus_send(&s->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_event_avail(VirtIOMSGProxy *s,
                                   VirtIOMSG *msg)
{
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    uint16_t vq_idx = msg->event_avail.index;

    if (!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        VirtIOMSG msg_ev;

        virtio_error(vdev, "Notification while driver not OK?");
        virtio_msg_pack_event_config(&msg_ev, vdev->status,
                                     0, 0, NULL);
        virtio_msg_bus_send(&s->msg_bus, &msg_ev, NULL);
        return;
    }

    if (vq_idx >= VIRTIO_QUEUE_MAX) {
        virtio_error(vdev, "Notification to bad VQ!");
        return;
    }

    if (!virtio_queue_get_num(vdev, vq_idx)) {
        virtio_error(vdev, "Notification to unconfigured VQ!");
        return;
    }

    /* NOTIFICATION_DATA doesn't exist in QEMU 8.2.7. if (0) it */
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_NOTIFICATION_DATA) && 0) {
        VirtQueue *vq = virtio_get_queue(vdev, vq_idx);
        uint32_t next_offset_wrap = msg->event_avail.next_offset_wrap;
        uint16_t qsize = virtio_queue_get_num(vdev, vq_idx);
        uint32_t offset = next_offset_wrap & 0x7fffffff;
        bool wrap = next_offset_wrap & 0x80000000;
        uint16_t data;

        if (offset > 0x7fff || offset >= qsize) {
            virtio_error(vdev, "Next offset to large!");
            /* Bail out without notification???  */
            return;
        }

        data = wrap << 15;
        data |= offset & 0x7fff;

        virtio_queue_set_shadow_avail_idx(vq, data);
    }
    virtio_queue_notify(vdev, msg->event_avail.index);
}

static void virtio_msg_iommu_enable(VirtIOMSGProxy *s,
                                    VirtIOMSG *msg)
{
    s->iommu_enabled = msg->iommu_enable.enable;
}

typedef void (*VirtIOMSGHandler)(VirtIOMSGProxy *s,
                                 VirtIOMSG *msg);

static const VirtIOMSGHandler msg_handlers[] = {
    [VIRTIO_MSG_DEVICE_INFO] = virtio_msg_device_info,
    [VIRTIO_MSG_GET_FEATURES] = virtio_msg_get_features,
    [VIRTIO_MSG_SET_FEATURES] = virtio_msg_set_features,
    [VIRTIO_MSG_GET_DEVICE_STATUS] = virtio_msg_get_device_status,
    [VIRTIO_MSG_SET_DEVICE_STATUS] = virtio_msg_set_device_status,
    [VIRTIO_MSG_GET_CONFIG] = virtio_msg_get_config,
    [VIRTIO_MSG_SET_CONFIG] = virtio_msg_set_config,
    [VIRTIO_MSG_GET_VQUEUE] = virtio_msg_get_vqueue,
    [VIRTIO_MSG_SET_VQUEUE] = virtio_msg_set_vqueue,
    [VIRTIO_MSG_EVENT_AVAIL] = virtio_msg_event_avail,
    [VIRTIO_MSG_IOMMU_ENABLE] = virtio_msg_iommu_enable,
};

static int virtio_msg_receive_msg(VirtIOMSGBusDevice *bd, VirtIOMSG *msg)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(bd->opaque);
    VirtIOMSGHandler handler;

    //virtio_msg_print(msg);
    if (msg->msg_id > ARRAY_SIZE(msg_handlers)) {
        return VIRTIO_MSG_ERROR_UNSUPPORTED_MESSAGE_ID;
    }

    handler = msg_handlers[msg->msg_id];
    assert((msg->type & VIRTIO_MSG_TYPE_RESPONSE) == 0);

    if (handler) {
        handler(s, msg);
    }

    return VIRTIO_MSG_NO_ERROR;
}

static const VirtIOMSGBusPort virtio_msg_port = {
    .receive = virtio_msg_receive_msg,
    .is_driver = false
};

static void virtio_msg_notify_queue(DeviceState *opaque, uint16_t index)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(opaque);
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    VirtIOMSG msg;

    if (!vdev || !virtio_msg_bus_connected(&s->msg_bus)) {
        return;
    }

    virtio_msg_pack_event_used(&msg, index);
    virtio_msg_bus_send(&s->msg_bus, &msg, NULL);
}

static void virtio_msg_notify(DeviceState *opaque, uint16_t vector)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(opaque);
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);
    VirtIOMSG msg;

    if (!virtio_msg_bus_connected(&s->msg_bus)) {
        return;
    }

    /* Check if we're notifying for VQ or CONFIG updates.  */
    if (vdev->isr & 2) {
        virtio_msg_pack_event_config(&msg, vdev->status, 0, 0, NULL);
        virtio_msg_bus_send(&s->msg_bus, &msg, NULL);
    }
}

static const VMStateDescription vmstate_virtio_msg_state_sub = {
    .name = "virtio_msg_device",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(guest_features, VirtIOMSGProxy),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_virtio_msg = {
    .name = "virtio_msg_proxy_backend",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_virtio_msg_state_sub,
        NULL
    }
};

static void virtio_msg_save_extra_state(DeviceState *opaque, QEMUFile *f)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(opaque);

    vmstate_save_state(f, &vmstate_virtio_msg, s, NULL);
}

static int virtio_msg_load_extra_state(DeviceState *opaque, QEMUFile *f)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(opaque);

    return vmstate_load_state(f, &vmstate_virtio_msg, s, 1);
}

static bool virtio_msg_has_extra_state(DeviceState *opaque)
{
    return true;
}

static void virtio_msg_reset_hold(Object *obj)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(obj);
    bool r;

    virtio_msg_soft_reset(s);

    r = virtio_msg_bus_connect(&s->msg_bus, &virtio_msg_port, s);
    if (r) {
        s->bus_as = virtio_msg_bus_get_remote_as(&s->msg_bus);
    }
}

static void virtio_msg_pre_plugged(DeviceState *d, Error **errp)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(d);
    VirtIODevice *vdev = virtio_bus_get_device(&s->bus);

    virtio_add_feature(&vdev->host_features, VIRTIO_F_VERSION_1);
}

static AddressSpace *virtio_msg_get_dma_as(DeviceState *d)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(d);
    AddressSpace *as;

    if (s->iommu_enabled) {
        as = &s->dma_as;
    } else {
        as = virtio_msg_bus_get_remote_as(&s->msg_bus);
    }

    g_assert(as);
    return as;
}

static void virtio_msg_realize(DeviceState *d, Error **errp)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(d);

    qbus_init(&s->bus, sizeof(s->bus),
              TYPE_VIRTIO_MSG_PROXY_BUS, d, NULL);
    qbus_init(&s->msg_bus, sizeof(s->msg_bus),
              TYPE_VIRTIO_MSG_BUS, d, NULL);

    memory_region_init_iommu(&s->mr_iommu, sizeof(s->mr_iommu),
                             TYPE_VIRTIO_MSG_IOMMU_MEMORY_REGION,
                             OBJECT(d), "virtio-msg-iommu", UINT64_MAX);
    address_space_init(&s->dma_as, MEMORY_REGION(&s->mr_iommu), "dma");
}

static void virtio_msg_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    dc->realize = virtio_msg_realize;
    dc->user_creatable = true;
    rc->phases.hold  = virtio_msg_reset_hold;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo virtio_msg_info = {
    .name          = TYPE_VIRTIO_MSG,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGProxy),
    .class_init    = virtio_msg_class_init,
};

static IOMMUTLBEntry virtio_msg_iommu_translate(IOMMUMemoryRegion *iommu,
                                                hwaddr addr,
                                                IOMMUAccessFlags flags,
                                                int iommu_idx)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(container_of(iommu,
                                                VirtIOMSGProxy, mr_iommu));
    VirtIOMSG msg, msg_resp;
    uint8_t prot;

    IOMMUTLBEntry ret = {
        .iova = addr & ~VIRTIO_MSG_IOMMU_PAGE_MASK,
        .translated_addr = addr & ~VIRTIO_MSG_IOMMU_PAGE_MASK,
        .addr_mask = VIRTIO_MSG_IOMMU_PAGE_MASK,
        .perm = IOMMU_RW,
        .target_as = s->bus_as,
    };

    if (!s->iommu_enabled) {
        /* identity mapped.  */
        return ret;
    }

    prot = flags & IOMMU_RO ? VIRTIO_MSG_IOMMU_PROT_READ : 0;
    prot |= flags & IOMMU_WO ? VIRTIO_MSG_IOMMU_PROT_WRITE : 0;

    virtio_msg_pack_iommu_translate(&msg, ret.iova, prot);
    virtio_msg_bus_send(&s->msg_bus, &msg, &msg_resp);

    ret.iova = msg_resp.iommu_translate_resp.va;
    ret.translated_addr = msg_resp.iommu_translate_resp.pa;
    prot = msg_resp.iommu_translate_resp.prot;
    ret.perm = IOMMU_ACCESS_FLAG(prot & VIRTIO_MSG_IOMMU_PROT_READ,
                                 prot & VIRTIO_MSG_IOMMU_PROT_WRITE);

    return ret;
}

static char *virtio_msg_bus_get_dev_path(DeviceState *dev)
{
    BusState *virtio_msg_bus;
    VirtIOMSGProxy *virtio_msg_proxy;
    char *proxy_path;

    virtio_msg_bus = qdev_get_parent_bus(dev);
    virtio_msg_proxy = VIRTIO_MSG(virtio_msg_bus->parent);
    proxy_path = qdev_get_dev_path(DEVICE(virtio_msg_proxy));

    if (!proxy_path) {
        const char *path = object_get_canonical_path(OBJECT(virtio_msg_proxy));
        proxy_path = strdup(path);
    }
    return proxy_path;
}

static void virtio_msg_bus_class_init(ObjectClass *klass, void *data)
{
    BusClass *bus_class = BUS_CLASS(klass);
    VirtioBusClass *k = VIRTIO_BUS_CLASS(klass);

    k->notify_queue = virtio_msg_notify_queue;
    k->notify = virtio_msg_notify;
    k->save_extra_state = virtio_msg_save_extra_state;
    k->load_extra_state = virtio_msg_load_extra_state;
    k->has_extra_state = virtio_msg_has_extra_state;
    k->pre_plugged = virtio_msg_pre_plugged;
    k->has_variable_vring_alignment = true;
    k->get_dma_as = virtio_msg_get_dma_as;
    bus_class->max_dev = 1;
    bus_class->get_dev_path = virtio_msg_bus_get_dev_path;
}

static const TypeInfo virtio_msg_bus_info = {
    .name          = TYPE_VIRTIO_MSG_PROXY_BUS,
    .parent        = TYPE_VIRTIO_BUS,
    .instance_size = sizeof(VirtioBusState),
    .class_init    = virtio_msg_bus_class_init,
};

static void virtio_msg_iommu_memory_region_class_init(ObjectClass *klass,
                                                      void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = virtio_msg_iommu_translate;
}

static const TypeInfo virtio_msg_iommu_info = {
    .name = TYPE_VIRTIO_MSG_IOMMU_MEMORY_REGION,
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .class_init = virtio_msg_iommu_memory_region_class_init,
};

static void virtio_msg_register_types(void)
{
    type_register_static(&virtio_msg_iommu_info);
    type_register_static(&virtio_msg_bus_info);
    type_register_static(&virtio_msg_info);
}

type_init(virtio_msg_register_types)
