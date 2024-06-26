/*
 * VirtIO MSG proxy driver.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/iov.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "qemu/error-report.h"
#include "hw/virtio/virtio.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/virtio-msg-prot.h"
#include "hw/virtio/virtio-msg-proxy-driver.h"

#include "standard-headers/linux/virtio_ids.h"

static void virtio_msg_pd_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(vdev);
    uint32_t index = virtio_get_queue_index(vq);
    VirtIOMSG msg;

    virtio_msg_pack_event_driver(&msg, index, 0, 0);
    virtio_msg_bus_send(&vpd->bus, &msg, NULL);
}

static bool virtio_msg_pd_probe_queue(VirtIOMSGProxyDriver *vpd, int i)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(vpd);
    VirtIOMSG msg, msg_resp;

    virtio_msg_pack_get_vqueue(&msg, i);
    virtio_msg_bus_send(&vpd->bus, &msg, &msg_resp);
    virtio_msg_unpack_resp(&msg_resp);

    if (msg_resp.payload.get_vqueue_resp.max_size) {
        printf("%s: VQ add %d\n", __func__, i);
        virtio_add_queue(vdev, msg_resp.payload.get_vqueue_resp.max_size,
                         virtio_msg_pd_handle_output);
    }

    return msg_resp.payload.get_vqueue_resp.max_size != 0;
}

static void virtio_msg_pd_probe_queues(VirtIOMSGProxyDriver *vpd)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(vpd);
    int i;

    /* First, delete all queues.  */
    for (i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        if (!virtio_queue_get_num(vdev, i)) {
            break;
        }
        printf("%s: VQ Remove %d\n", __func__, i);
        virtio_del_queue(vdev, i);
    }

    /* And start re-adding active queue's from the peer.  */
    for (i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        if (!virtio_msg_pd_probe_queue(vpd, i)) {
            break;
        }
    }
}

static void vmb_event_device(VirtIOMSGProxyDriver *vpd,
                             VirtIOMSG *msg,
                             VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(vpd);
    VirtQueue *vq;

    vq = virtio_get_queue(vdev, mp->event_device.index);
    virtio_notify_force(vdev, vq);
}

static void vmb_event_conf(VirtIOMSGProxyDriver *vpd,
                           VirtIOMSG *msg,
                           VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(vpd);

    virtio_notify_config(vdev);
}

static int vmb_receive_msg(VirtIOMSGBusDevice *bd, VirtIOMSG *msg)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(bd->opaque);

    //virtio_msg_print(msg, false);
    virtio_msg_unpack(msg);

    switch (msg->type) {
    case VIRTIO_MSG_EVENT_DEVICE:
        vmb_event_device(vpd, msg, &msg->payload);
        break;
    case VIRTIO_MSG_EVENT_CONF:
        vmb_event_conf(vpd, msg, &msg->payload);
        break;
    default:
        /* Ignore.  */
        break;
    }
    return VIRTIO_MSG_NO_ERROR;
}

static const VirtIOMSGBusPort vmb_port = {
    .receive = vmb_receive_msg,
    .is_driver = true
};

static uint64_t vmpd_get_features(VirtIODevice *vdev, uint64_t f, Error **errp)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(vdev);
    VirtIOMSG msg, msg_resp;

    if (virtio_msg_bus_connected(&vpd->bus)) {
        virtio_msg_pack_get_device_feat(&msg, 0);
        virtio_msg_bus_send(&vpd->bus, &msg, &msg_resp);
        virtio_msg_unpack_resp(&msg_resp);

        f = msg_resp.payload.get_device_feat_resp.features;
    }

    return f;
}

static void vmpd_set_features(VirtIODevice *vdev, uint64_t f)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(vdev);
    VirtIOMSG msg;

    virtio_msg_pack_set_device_feat(&msg, 0, f);
    virtio_msg_bus_send(&vpd->bus, &msg, NULL);
}

static void virtio_msg_pd_set_status(VirtIODevice *vdev, uint8_t status)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(vdev);
    VirtIOMSG msg, msg_resp;

    printf("%s: 0x%x\n", __func__, status);
    if (!vdev->vm_running) {
        return;
    }

    /*
     * We need to update our view of available queue's from
     * the peer after feature negotiation. This is because:
     *
     * Guests will first feature negotiate and then setup queues.
     * Setting up the queues involves checking which queues are enabled
     * by checking for non-zero virtio_queue_get_num(vdev, queue_index).
     *
     * When the guest queries for the max size over virtio-mmio or
     * virtio-pci, QEMU will simply return the local view of
     * virtio_queue_get_num(), which may get updated during feature
     * negotiation (see virtio-net mq support for an example).
     */
    if (status & VIRTIO_CONFIG_S_FEATURES_OK) {
        virtio_msg_pd_probe_queues(vpd);
    }

    virtio_msg_pack_set_device_status(&msg, status);
    virtio_msg_bus_send(&vpd->bus, &msg, NULL);

    virtio_msg_pack_get_device_status(&msg);
    virtio_msg_bus_send(&vpd->bus, &msg, &msg_resp);
    virtio_msg_unpack_resp(&msg_resp);

    vdev->status = msg_resp.payload.get_device_status_resp.status;
}

static uint32_t virtio_msg_pd_read_config(VirtIODevice *vdev,
                                          int size, uint32_t addr)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(vdev);
    VirtIOMSG msg, msg_resp;

    virtio_msg_pack_get_device_conf(&msg, size, addr);
    virtio_msg_bus_send(&vpd->bus, &msg, &msg_resp);
    virtio_msg_unpack_resp(&msg_resp);

    return msg_resp.payload.get_device_conf_resp.data;
}

static void virtio_msg_pd_write_config(VirtIODevice *vdev,
                                      int size, uint32_t addr, uint32_t val)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(vdev);
    VirtIOMSG msg;

    virtio_msg_pack_set_device_conf(&msg, size, addr, val);
    virtio_msg_bus_send(&vpd->bus, &msg, NULL);
}

static void virtio_msg_pd_queue_enable(VirtIODevice *vdev, uint32_t n)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(vdev);
    VirtIOMSG msg;
    uint64_t descriptor_addr = virtio_queue_get_addr(vdev, n);
    uint64_t driver_addr = virtio_queue_get_avail_addr(vdev, n);
    uint64_t device_addr = virtio_queue_get_used_addr(vdev, n);
    uint32_t size = virtio_queue_get_num(vdev, n);

    virtio_msg_pack_set_vqueue(&msg, n, size,
                               descriptor_addr,
                               driver_addr,
                               device_addr);
    virtio_msg_bus_send(&vpd->bus, &msg, NULL);
}

static void virtio_msg_pd_reset_hold(Object *obj, ResetType type)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(obj);
    VirtIODevice *vdev = VIRTIO_DEVICE(vpd);
    VirtIOMSG msg, msg_resp;

    if (!virtio_msg_bus_connect(&vpd->bus, &vmb_port, vpd)) {
        error_report("virtio-msg-proxy: Failed to connect!");
        exit(EXIT_FAILURE);
    }

    virtio_msg_pack_get_device_info(&msg);
    virtio_msg_bus_send(&vpd->bus, &msg, &msg_resp);
    virtio_msg_unpack_resp(&msg_resp);

    if (vpd->cfg.virtio_id != msg_resp.payload.get_device_info_resp.device_id) {
        error_report("virtio-msg-proxy: Device-id missmatch! %x != %x",
                     msg_resp.payload.get_device_info_resp.device_id,
                     vpd->cfg.virtio_id);
        exit(EXIT_FAILURE);
    }

    /* Update host features.  */
    vdev->host_features = vmpd_get_features(vdev, vdev->host_features,
                                            &error_abort);
    virtio_msg_pd_probe_queues(vpd);
}

static void virtio_msg_pd_device_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGProxyDriver *vpd = VIRTIO_MSG_PROXY_DRIVER(dev);
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    qbus_init(&vpd->bus, sizeof(vpd->bus), TYPE_VIRTIO_MSG_BUS, dev, NULL);

    /* TODO: Figure out a way to read this from the peer.  */
    virtio_init(vdev, vpd->cfg.virtio_id, 0);
}

static void virtio_msg_pd_device_unrealize(DeviceState *dev)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    virtio_del_queue(vdev, 0);
    virtio_cleanup(vdev);
}

static const VMStateDescription vmstate_virtio_msg_pd = {
    .name = "virtio-msg-proxy-driver",
    .minimum_version_id = 1,
    .version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static Property virtio_msg_pd_properties[] = {
    DEFINE_PROP_UINT16("virtio-id", VirtIOMSGProxyDriver, cfg.virtio_id,
                       VIRTIO_ID_NET),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_pd_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    device_class_set_props(dc, virtio_msg_pd_properties);
    dc->vmsd = &vmstate_virtio_msg_pd;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    rc->phases.hold  = virtio_msg_pd_reset_hold;

    vdc->realize = virtio_msg_pd_device_realize;
    vdc->unrealize = virtio_msg_pd_device_unrealize;
    vdc->get_features = vmpd_get_features;
    vdc->set_features = vmpd_set_features;
    vdc->set_status = virtio_msg_pd_set_status;
    vdc->read_config = virtio_msg_pd_read_config;
    vdc->write_config = virtio_msg_pd_write_config;
    vdc->queue_enable = virtio_msg_pd_queue_enable;
}

static const TypeInfo virtio_msg_pd_info = {
    .name = TYPE_VIRTIO_MSG_PROXY_DRIVER,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOMSGProxyDriver),
    .class_init = virtio_msg_pd_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_msg_pd_info);
}

type_init(virtio_register_types)
