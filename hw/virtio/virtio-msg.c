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
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/virtio-msg.h"
#include "migration/qemu-file.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "trace.h"

#define VIRTIO_MSG_VENDOR_ID 0x554D4551 /* 'QEMU' */
#define VIRTIO_MSG_SUPPORTED_EXTRA_FEATURES \
    (1ULL << VIRTIO_F_IOMMU_PLATFORM)
#define VIRTIO_MSG_SUPPORTED_TRANSPORT_FEATURES 0ULL

#define VIRTIO_MSG_VQ_FIELD_SIZE   (1U << 0)
#define VIRTIO_MSG_VQ_FIELD_DESC   (1U << 1)
#define VIRTIO_MSG_VQ_FIELD_DRIVER (1U << 2)
#define VIRTIO_MSG_VQ_FIELD_DEVICE (1U << 3)
#define VIRTIO_MSG_VQ_FIELDS_ALL   0xfU

static uint16_t virtio_msg_active_max_msg_size(VirtIOMSGProxy *s)
{
    if (!s->latched_caps_valid || !s->latched_caps.ready ||
        !s->latched_caps.max_msg_size) {
        return VIRTIO_MSG_MAX_SIZE;
    }

    return s->latched_caps.max_msg_size;
}

static unsigned int virtio_msg_max_feature_blocks(VirtIOMSGProxy *s)
{
    size_t prefix = offsetof(VirtIOMSG,
                             get_device_features_resp.features);
    uint16_t max_size = virtio_msg_active_max_msg_size(s);

    return max_size > prefix ? (max_size - prefix) / sizeof(uint32_t) : 0;
}

static unsigned int virtio_msg_max_config_bytes(VirtIOMSGProxy *s)
{
    size_t prefix = offsetof(VirtIOMSG, set_config.data);
    uint16_t max_size = virtio_msg_active_max_msg_size(s);

    return max_size > prefix ? max_size - prefix : 0;
}

static int virtio_msg_send_must_deliver(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    int ret;

    if (le16_to_cpu(msg->msg_size) > virtio_msg_active_max_msg_size(s)) {
        return VIRTIO_MSG_ERROR_BAD_MESSAGE;
    }

    ret = virtio_msg_bus_send_must_deliver(&s->msg_bus, msg);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: failed to send required message id %u: ret=%d\n",
                      __func__, msg->msg_id, ret);
    }

    return ret;
}

static bool virtio_msg_bad(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    bool drop = false;
    size_t min_size;
    unsigned int n;

    min_size = virtio_msg_header_size();
    switch (msg->msg_id) {
    case VIRTIO_MSG_GET_DEVICE_STATUS:
    case VIRTIO_MSG_GET_DEVICE_INFO:
        break;
    case VIRTIO_MSG_GET_DEVICE_FEATURES:
        n = msg->get_device_features.num_blocks;
        if (!n || n > virtio_msg_max_feature_blocks(s)) {
            drop = true;
            break;
        }
        min_size += sizeof msg->get_device_features;
        break;
    case VIRTIO_MSG_SET_DRIVER_FEATURES:
        n = msg->set_driver_features.num_blocks;

        if (!n || n > virtio_msg_max_feature_blocks(s)) {
            drop = true;
            break;
        }

        min_size += sizeof msg->set_driver_features + n * 4;
        break;
    case VIRTIO_MSG_GET_CONFIG:
        if (msg->get_config.length > virtio_msg_max_config_bytes(s)) {
            drop = true;
            break;
        }
        min_size += sizeof msg->get_config;
        break;
    case VIRTIO_MSG_SET_CONFIG:
        if (msg->set_config.length > virtio_msg_max_config_bytes(s)) {
            drop = true;
            break;
        }

        min_size += sizeof msg->set_config + msg->set_config.length;
        break;
    case VIRTIO_MSG_SET_DEVICE_STATUS:
        min_size += sizeof msg->set_device_status;
        break;
    case VIRTIO_MSG_GET_VQUEUE:
        min_size += sizeof msg->get_vqueue;
        break;
    case VIRTIO_MSG_SET_VQUEUE:
        min_size += sizeof msg->set_vqueue;
        break;
    case VIRTIO_MSG_RESET_VQUEUE:
        min_size += sizeof msg->reset_vqueue;
        break;
    case VIRTIO_MSG_GET_SHM:
        min_size += sizeof msg->get_shm;
        break;
    case VIRTIO_MSG_EVENT_AVAIL:
        min_size += sizeof msg->event_avail;
        break;
    default:
        /* Unexpected message.  */
        drop = true;
        break;
    }

    /* Accept large messages allowing future backwards compatible extensions. */
    if (drop ||
        msg->msg_size < min_size ||
        msg->msg_size > virtio_msg_active_max_msg_size(s)) {
        return true;
    }

    if (msg->dev_num >= ARRAY_SIZE(s->devs)) {
        return true;
    }

    return false;
}

static bool virtio_msg_bus_bad(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    size_t min_size = virtio_msg_header_size();

    if (msg->dev_num != 0 || msg->msg_size < min_size ||
        msg->msg_size > virtio_msg_active_max_msg_size(s)) {
        return true;
    }

    if (msg->type & VIRTIO_MSG_TYPE_RESPONSE) {
        return false;
    }

    switch (msg->msg_id) {
    case VIRTIO_MSG_BUS_GET_DEVICES:
        min_size += sizeof(msg->bus_get_devices);
        break;
    case VIRTIO_MSG_BUS_PING:
        min_size += sizeof(msg->bus_ping);
        break;
    default:
        return true;
    }

    return msg->msg_size < min_size;
}

static VirtIODevice *virtio_msg_vdev(VirtIOMSGProxy *s, uint16_t dev_num)
{
    VirtIODevice *vdev;

    vdev = virtio_bus_get_device(&s->devs[dev_num].bus);
    return vdev;
}

static VirtIODevice *virtio_msg_lookup_vdev(VirtIOMSGProxy *s, uint16_t dev_num,
                                            const char *what)
{
    VirtIODevice *vdev = virtio_msg_vdev(s, dev_num);

    if (!vdev) {
        error_report("%s: No virtio device on bus %s!",
                     what, BUS(&s->devs[dev_num].bus)->name);
    }

    return vdev;
}

static int virtio_msg_require_vdev(VirtIOMSGProxy *s, uint16_t dev_num,
                                   VirtIODevice **vdev)
{
    VirtIODevice *target;

    if (dev_num >= ARRAY_SIZE(s->devs)) {
        return VIRTIO_MSG_ERROR_BAD_MESSAGE;
    }

    target = virtio_msg_vdev(s, dev_num);
    if (!target) {
        return VIRTIO_MSG_ERROR_NO_DEVICE;
    }

    if (vdev) {
        *vdev = target;
    }
    return VIRTIO_MSG_NO_ERROR;
}

static int virtio_msg_bus_get_devices(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIOMSG msg_resp;
    uint8_t data[VIRTIO_MSG_MAX_DEVS / 8] = {0};
    uint16_t req_offset = msg->bus_get_devices.offset;
    uint16_t offset = req_offset;
    uint16_t max_window = offset < VIRTIO_MSG_MAX_DEVS ?
                          VIRTIO_MSG_MAX_DEVS - offset : 0;
    uint16_t num = MIN(msg->bus_get_devices.count, max_window);
    uint16_t next_offset = num && offset + num < VIRTIO_MSG_MAX_DEVS ?
                           offset + num : 0;
    int i;

    for (i = 0; i < num; i++) {
        uint16_t dev_idx = offset + i;
        VirtIODevice *vdev = virtio_msg_vdev(s, dev_idx);

        if (vdev) {
            data[i / 8] |= 1U << (i & 7);
        }
    }

    virtio_msg_pack_bus_get_devices_resp(&msg_resp,
                                         msg->token, offset, num, next_offset,
                                         data);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_bus_ping(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIOMSG msg_resp;

    virtio_msg_pack_bus_ping_resp(&msg_resp, msg->token,
                                  msg->bus_ping.data);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_device_info(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    uint32_t max_virtqueues;
    VirtIOMSG msg_resp;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }
    max_virtqueues = virtio_get_num_queues(vdev);

    virtio_msg_pack_get_device_info_resp(&msg_resp, msg->dev_num, msg->token,
                                         vdev->device_id,
                                         VIRTIO_MSG_VENDOR_ID,
                                         /* 64 feature bits in 32-bit blocks */
                                         2,
                                         vdev->config_len,
                                         max_virtqueues,
                                         0, 0);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_get_features(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    VirtIOMSG msg_resp;
    uint32_t index = msg->get_device_features.block_index;
    uint32_t f[VIRTIO_MSG_MAX_FEATURE_NUM] = { 0 };
    uint32_t num = msg->get_device_features.num_blocks;
    uint64_t features = 0;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    features = vdev->host_features &
               ~VIRTIO_DEVICE_GET_CLASS(vdev)->legacy_features;
    /* v23 carries VIRTIO_F_NOTIFICATION_DATA in EVENT_AVAIL. */
    features &= ~(1ULL << VIRTIO_F_NOTIF_CONFIG_DATA);

    /* We only have 64 feature bits. If driver asks for more, return zeros  */
    if (index < 2) {
        features >>= index * 32;
        f[0] = features;
        f[1] = features >> 32;
    }

    /* Blocks beyond QEMU's 64 feature bits stay zero, as v23 requires. */
    virtio_msg_pack_get_device_features_resp(&msg_resp, msg->dev_num,
                                             msg->token, index, num, f);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_set_features(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIOMSG msg_resp;
    unsigned int i;
    uint64_t f;
    VirtIODevice *vdev;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    f = s->devs[msg->dev_num].guest_features;

    for (i = 0; i < msg->set_driver_features.num_blocks; i++) {
        uint64_t feature_index =
            i + msg->set_driver_features.block_index;

        /* We only support up to 64bits  */
        if (feature_index >= 2) {
            break;
        }

        f = deposit64(f, feature_index * 32, 32,
                      msg->set_driver_features.features[i]);
    }

    /* Keep NOTIFICATION_DATA; only NOTIF_CONFIG_DATA is unsupported. */
    f &= ~(1ULL << VIRTIO_F_NOTIF_CONFIG_DATA);
    s->devs[msg->dev_num].guest_features = f;

    virtio_msg_pack_set_driver_features_resp(&msg_resp, msg->dev_num,
                                             msg->token);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static void virtio_msg_soft_reset(VirtIOMSGProxy *s, uint16_t dev_num)
{
    assert(dev_num < ARRAY_SIZE(s->devs));

    virtio_bus_reset(&s->devs[dev_num].bus);
    s->devs[dev_num].guest_features = 0;
    memset(s->devs[dev_num].queue_enabled, 0,
           sizeof(s->devs[dev_num].queue_enabled));
    memset(s->devs[dev_num].queue_fields, 0,
           sizeof(s->devs[dev_num].queue_fields));
}

static int virtio_msg_set_device_status(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    uint32_t status = msg->set_device_status.status;
    VirtIOMSG msg_resp;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    if (!(status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        virtio_bus_stop_ioeventfd(&s->devs[msg->dev_num].bus);
    }

    if ((status & VIRTIO_CONFIG_S_FEATURES_OK) &&
        virtio_set_features(vdev,
                            s->devs[msg->dev_num].guest_features) < 0) {
        status &= ~VIRTIO_CONFIG_S_FEATURES_OK;
    }

    virtio_set_status(vdev, status);

    if (status & VIRTIO_CONFIG_S_DRIVER_OK) {
        virtio_bus_start_ioeventfd(&s->devs[msg->dev_num].bus);
    }

    if (status == 0) {
        virtio_msg_soft_reset(s, msg->dev_num);
    }

    virtio_msg_pack_set_device_status_resp(&msg_resp, msg->dev_num, msg->token,
                                           vdev->status);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_get_device_status(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    VirtIOMSG msg_resp;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    virtio_msg_pack_get_device_status_resp(&msg_resp, msg->dev_num, msg->token,
                                           vdev->status);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_get_config(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    VirtioDeviceClass *vdc;
    uint32_t size = msg->get_config.length;
    uint32_t offset = msg->get_config.offset;
    uint8_t data[VIRTIO_MSG_MAX_CONFIG_BYTES];
    VirtIOMSG msg_resp;
    uint32_t response_size = size;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    memset(data, 0, size);
    if (size && (offset > vdev->config_len ||
                 size > vdev->config_len - offset)) {
        response_size = 0;
    } else {
        vdc = VIRTIO_DEVICE_GET_CLASS(vdev);
        if (vdc->get_config) {
            vdc->get_config(vdev, vdev->config);
        }
        memcpy(data, vdev->config + offset, size);
    }

    virtio_msg_pack_get_config_resp(&msg_resp, msg->dev_num, msg->token,
                                    response_size, offset,
                                    vdev->generation, data);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_set_config(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    VirtioDeviceClass *vdc;
    uint32_t offset = msg->set_config.offset;
    uint32_t size = msg->set_config.length;
    uint8_t *data = msg->set_config.data;
    VirtIOMSG msg_resp;
    uint32_t response_size = size;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    if (size && (offset > vdev->config_len ||
                 size > vdev->config_len - offset)) {
        response_size = 0;
    } else {
        /* Baseline profile: request generation is intentionally ignored. */
        memcpy(vdev->config + offset, data, size);
        vdc = VIRTIO_DEVICE_GET_CLASS(vdev);
        if (vdc->set_config) {
            vdc->set_config(vdev, vdev->config);
        }
        if (size) {
            vdev->generation++;
        }
    }

    virtio_msg_pack_set_config_resp(&msg_resp, msg->dev_num, msg->token,
                                    response_size, offset,
                                    vdev->generation, data);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_get_shm(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIOMSG msg_resp;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, NULL);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    /* This backend does not expose device-owned shared-memory regions. */
    virtio_msg_pack_get_shm_resp(&msg_resp, msg->dev_num, msg->token,
                                 msg->get_shm.shmid, 0, 0);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_get_vqueue(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    VirtIOMSGDev *mdev = &s->devs[msg->dev_num];
    uint32_t max_size = 0;
    uint32_t index = msg->get_vqueue.index;
    uint32_t flags = 0;
    hwaddr desc = 0, avail = 0, used = 0;
    VirtIOMSG msg_resp;
    uint32_t cur_size = 0;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    if (index < virtio_get_num_queues(vdev)) {
        max_size = virtio_queue_get_max_num(vdev, index);
        if (mdev->queue_fields[index] & VIRTIO_MSG_VQ_FIELD_SIZE) {
            cur_size = virtio_queue_get_num(vdev, index);
        }
        if (mdev->queue_fields[index] & VIRTIO_MSG_VQ_FIELD_DESC) {
            desc = virtio_queue_get_desc_addr(vdev, index);
        }
        if (mdev->queue_fields[index] & VIRTIO_MSG_VQ_FIELD_DRIVER) {
            avail = virtio_queue_get_avail_addr(vdev, index);
        }
        if (mdev->queue_fields[index] & VIRTIO_MSG_VQ_FIELD_DEVICE) {
            used = virtio_queue_get_used_addr(vdev, index);
        }
        if (mdev->queue_enabled[index]) {
            flags = VIRTIO_MSG_VQUEUE_F_ENABLED;
        }
        virtio_msg_pack_get_vqueue_resp(&msg_resp, msg->dev_num, msg->token,
                                        index, max_size, cur_size, flags,
                                        desc, avail, used);
    } else {
        /* OOB index or missing device, respond with all zeroes. */
        virtio_msg_pack_get_vqueue_resp(&msg_resp, msg->dev_num, msg->token,
                                        index, 0, 0, 0, 0, 0, 0);
    }

    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_set_vqueue(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    VirtIOMSGDev *mdev = &s->devs[msg->dev_num];
    uint32_t index = msg->set_vqueue.index;
    uint32_t flags = msg->set_vqueue.flags;
    uint32_t state = flags & VIRTIO_MSG_VQUEUE_STATE_MASK;
    bool update_size = !(flags & VIRTIO_MSG_VQUEUE_F_SIZE_IGNORE);
    bool update_desc = !(flags & VIRTIO_MSG_VQUEUE_F_DESC_IGNORE);
    bool update_driver = !(flags & VIRTIO_MSG_VQUEUE_F_DRIVER_IGNORE);
    bool update_device = !(flags & VIRTIO_MSG_VQUEUE_F_DEVICE_IGNORE);
    hwaddr desc, driver, device;
    VirtIOMSG msg_resp;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    if (index >= virtio_get_num_queues(vdev)) {
        goto respond;
    }
    if (msg->set_vqueue.reserved ||
        (flags & ~VIRTIO_MSG_VQUEUE_F_VALID_MASK) || state == 3) {
        goto respond;
    }
    if (mdev->queue_enabled[index] &&
        (state == VIRTIO_MSG_VQUEUE_STATE_DISABLED || update_size ||
         update_desc || update_driver || update_device)) {
        goto respond;
    }
    if (update_size &&
        (!msg->set_vqueue.size ||
         msg->set_vqueue.size > virtio_queue_get_max_num(vdev, index))) {
        goto respond;
    }

    desc = virtio_queue_get_desc_addr(vdev, index);
    driver = virtio_queue_get_avail_addr(vdev, index);
    device = virtio_queue_get_used_addr(vdev, index);
    if (update_desc) {
        desc = msg->set_vqueue.desc_addr;
    }
    if (update_driver) {
        driver = msg->set_vqueue.driver_addr;
    }
    if (update_device) {
        device = msg->set_vqueue.device_addr;
    }

    if (state == VIRTIO_MSG_VQUEUE_STATE_ENABLED &&
        ((mdev->queue_fields[index] |
          (update_size ? VIRTIO_MSG_VQ_FIELD_SIZE : 0) |
          (update_desc ? VIRTIO_MSG_VQ_FIELD_DESC : 0) |
          (update_driver ? VIRTIO_MSG_VQ_FIELD_DRIVER : 0) |
          (update_device ? VIRTIO_MSG_VQ_FIELD_DEVICE : 0)) !=
         VIRTIO_MSG_VQ_FIELDS_ALL)) {
        goto respond;
    }

    virtio_queue_set_vector(vdev, index, index);
    if (update_size) {
        virtio_queue_set_num(vdev, index, msg->set_vqueue.size);
        mdev->queue_fields[index] |= VIRTIO_MSG_VQ_FIELD_SIZE;
    }
    if (update_desc || update_driver || update_device) {
        virtio_queue_set_rings(vdev, index, desc, driver, device);
        if (update_desc) {
            mdev->queue_fields[index] |= VIRTIO_MSG_VQ_FIELD_DESC;
        }
        if (update_driver) {
            mdev->queue_fields[index] |= VIRTIO_MSG_VQ_FIELD_DRIVER;
        }
        if (update_device) {
            mdev->queue_fields[index] |= VIRTIO_MSG_VQ_FIELD_DEVICE;
        }
    }

    if (state == VIRTIO_MSG_VQUEUE_STATE_ENABLED) {
        mdev->queue_enabled[index] = true;
        virtio_queue_enable(vdev, index);
    }

respond:
    virtio_msg_pack_set_vqueue_resp(&msg_resp, msg->dev_num, msg->token);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_reset_vqueue(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    VirtIOMSGDev *mdev = &s->devs[msg->dev_num];
    VirtIOMSG msg_resp;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    if (msg->reset_vqueue.index < virtio_get_num_queues(vdev) &&
        virtio_vdev_has_feature(vdev, VIRTIO_F_RING_RESET)) {
        virtio_queue_reset(vdev, msg->reset_vqueue.index);
        mdev->queue_enabled[msg->reset_vqueue.index] = false;
        mdev->queue_fields[msg->reset_vqueue.index] = 0;
    }

    virtio_msg_pack_reset_vqueue_resp(&msg_resp, msg->dev_num, msg->token);
    return virtio_msg_send_must_deliver(s, &msg_resp);
}

static int virtio_msg_event_avail(VirtIOMSGProxy *s, VirtIOMSG *msg)
{
    VirtIODevice *vdev;
    VirtIOMSGDev *mdev = &s->devs[msg->dev_num];
    uint16_t vq_idx = msg->event_avail.vq_index;
    VirtQueue *vq;
    int ret;

    ret = virtio_msg_require_vdev(s, msg->dev_num, &vdev);
    if (ret != VIRTIO_MSG_NO_ERROR) {
        return ret;
    }

    if (!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        VirtIOMSG msg_ev;

        virtio_error(vdev, "Notification while driver not OK?");
        virtio_msg_pack_event_config(&msg_ev, msg->dev_num,
                                     vdev->status, vdev->generation,
                                     0, 0, NULL);
        return virtio_msg_send_must_deliver(s, &msg_ev);
    }

    if (vq_idx >= virtio_get_num_queues(vdev)) {
        virtio_error(vdev, "Notification to bad VQ!");
        return VIRTIO_MSG_NO_ERROR;
    }

    if (!mdev->queue_enabled[vq_idx]) {
        virtio_error(vdev, "Notification to unconfigured VQ!");
        return VIRTIO_MSG_NO_ERROR;
    }

    vq = virtio_get_queue(vdev, vq_idx);
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_NOTIFICATION_DATA)) {
        uint32_t next_offset = msg->event_avail.next_offset;
        uint16_t qsize = virtio_queue_get_num(vdev, vq_idx);
        uint32_t offset = next_offset & 0x7fffffff;
        bool wrap = next_offset & 0x80000000;
        uint16_t data;

        if (offset > 0x7fff || offset >= qsize) {
            virtio_error(vdev, "Next offset to large!");
            /* Bail out without notification???  */
            return VIRTIO_MSG_NO_ERROR;
        }

        data = wrap << 15;
        data |= offset & 0x7fff;

        virtio_queue_set_shadow_avail_idx(vq, data);
    }
    virtio_queue_notify(vdev, msg->event_avail.vq_index);
    return VIRTIO_MSG_NO_ERROR;
}

typedef int (*VirtIOMSGHandler)(VirtIOMSGProxy *s, VirtIOMSG *msg);

static const VirtIOMSGHandler msg_handlers[] = {
    [VIRTIO_MSG_GET_DEVICE_INFO] = virtio_msg_device_info,
    [VIRTIO_MSG_GET_DEVICE_FEATURES] = virtio_msg_get_features,
    [VIRTIO_MSG_SET_DRIVER_FEATURES] = virtio_msg_set_features,
    [VIRTIO_MSG_GET_DEVICE_STATUS] = virtio_msg_get_device_status,
    [VIRTIO_MSG_SET_DEVICE_STATUS] = virtio_msg_set_device_status,
    [VIRTIO_MSG_GET_CONFIG] = virtio_msg_get_config,
    [VIRTIO_MSG_SET_CONFIG] = virtio_msg_set_config,
    [VIRTIO_MSG_GET_VQUEUE] = virtio_msg_get_vqueue,
    [VIRTIO_MSG_SET_VQUEUE] = virtio_msg_set_vqueue,
    [VIRTIO_MSG_RESET_VQUEUE] = virtio_msg_reset_vqueue,
    [VIRTIO_MSG_GET_SHM] = virtio_msg_get_shm,
    [VIRTIO_MSG_EVENT_AVAIL] = virtio_msg_event_avail,
};

static int virtio_msg_receive_msg(VirtIOMSGBusDevice *bd, VirtIOMSG *msg)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(bd->opaque);
    VirtIOMSGHandler handler;
    uint8_t msg_type = msg->type & VIRTIO_MSG_TYPE_MASK;

    /* virtio_msg_print(msg); */

    /* We handle some generic bus messages. */
    if (msg_type & VIRTIO_MSG_TYPE_BUS) {
        /*
         * Only requests get an answer.  Replying to a reply is what turns a
         * single keepalive BUS_PING into a storm: the peer answers our ping
         * response, we answer that, and the link saturates on ping traffic --
         * measured on rave2 as a full core burnt and virtio-net down to a few
         * Mbit/s.  The device-message path below already drops responses; the
         * bus path returns before ever reaching that check.
         */
        if (virtio_msg_bus_bad(s, msg)) {
            return VIRTIO_MSG_NO_ERROR;
        }
        if (msg_type & VIRTIO_MSG_TYPE_RESPONSE) {
            return VIRTIO_MSG_NO_ERROR;
        }

        if (msg->msg_id == VIRTIO_MSG_BUS_GET_DEVICES) {
            return virtio_msg_bus_get_devices(s, msg);
        }
        if (msg->msg_id == VIRTIO_MSG_BUS_PING) {
            return virtio_msg_bus_ping(s, msg);
        }
        return VIRTIO_MSG_NO_ERROR;
    }

    if (msg->msg_id >= ARRAY_SIZE(msg_handlers)) {
        return VIRTIO_MSG_NO_ERROR;
    }

    handler = msg_handlers[msg->msg_id];

    /* We don't expect responses.  */
    if ((msg_type & VIRTIO_MSG_TYPE_RESPONSE) || virtio_msg_bad(s, msg)) {
        /* Drop bad messages.  */
        return VIRTIO_MSG_NO_ERROR;
    }

    if (handler) {
        return handler(s, msg);
    }

    return VIRTIO_MSG_NO_ERROR;
}

static const VirtIOMSGBusPort virtio_msg_port = {
    .receive = virtio_msg_receive_msg,
    .is_driver = false
};

static void virtio_msg_notify(DeviceState *opaque, uint16_t vector)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(opaque);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);
    VirtIODevice *vdev = virtio_msg_lookup_vdev(s, mdev->dev_num, __func__);
    VirtIOMSG msg;

    if (!vdev || !virtio_msg_bus_connected(&s->msg_bus)) {
        return;
    }

    if (vector < VIRTIO_QUEUE_MAX && mdev->queue_enabled[vector]) {
        virtio_msg_pack_event_used(&msg, mdev->dev_num, vector);
        virtio_msg_send_must_deliver(s, &msg);
        return;
    }

    if (vector < VIRTIO_NO_VECTOR) {
        virtio_msg_pack_event_config(&msg, mdev->dev_num,
                                     vdev->status, vdev->generation,
                                     0, 0, NULL);
        virtio_msg_send_must_deliver(s, &msg);
        return;
    }
}

static void virtio_msg_save_queue(DeviceState *opaque, int n, QEMUFile *f)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(opaque);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);
    VirtIODevice *vdev = virtio_msg_vdev(s, mdev->dev_num);
    uint16_t vector = VIRTIO_NO_VECTOR;

    if (vdev) {
        vector = virtio_queue_vector(vdev, n);
    }

    /* Preserve per-queue MSI-X vector so notifications keep working. */
    qemu_put_be16(f, vector);
}

static int virtio_msg_load_queue(DeviceState *opaque, int n, QEMUFile *f)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(opaque);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);
    VirtIODevice *vdev = virtio_msg_vdev(s, mdev->dev_num);
    uint16_t vector;

    /* Restore the MSI-X vector saved by virtio_msg_save_queue(). */
    qemu_get_be16s(f, &vector);

    if (!vdev) {
        return -ENODEV;
    }

    if (vector != VIRTIO_NO_VECTOR && vector >= VIRTIO_QUEUE_MAX) {
        return -EINVAL;
    }

    virtio_queue_set_vector(vdev, n, vector);
    return 0;
}

static bool virtio_msg_has_vdevs(VirtIOMSGProxy *s)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(s->devs); i++) {
        if (virtio_msg_vdev(s, i)) {
            return true;
        }
    }

    return false;
}

static void virtio_msg_connect_bus(VirtIOMSGProxy *s, bool has_vdevs)
{
    if (!has_vdevs) {
        return;
    }

    if (!virtio_msg_bus_connect(&s->msg_bus, &virtio_msg_port, s)) {
        /* This is a user error, forgetting to setup a msg-bus.  */
        error_report("%s: No bus connected!",
                     object_get_canonical_path(OBJECT(s)));
        exit(EXIT_FAILURE);
    }
}

static int virtio_msg_post_load(void *opaque, int version_id)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(opaque);

    virtio_msg_connect_bus(s, virtio_msg_has_vdevs(s));
    return 0;
}

static void virtio_msg_vmstate_change(DeviceState *d, bool running)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(d);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);
    VirtIOMSGBusDevice *bd;

    if (!running) {
        return;
    }

    if (!virtio_msg_bus_connected(&s->msg_bus)) {
        return;
    }

    bd = virtio_msg_bus_get_device(&s->msg_bus);
    if (!bd) {
        return;
    }

    /* Resume path: ensure any pending bus work is processed post-migration. */
    virtio_msg_bus_process(bd);
}

static const VMStateDescription vmstate_virtio_msg_dev = {
    .name = "virtio_msg/dev",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64(guest_features, VirtIOMSGDev),
        VMSTATE_BOOL_ARRAY_V(queue_enabled, VirtIOMSGDev,
                             VIRTIO_QUEUE_MAX, 2),
        VMSTATE_UINT8_ARRAY_V(queue_fields, VirtIOMSGDev,
                              VIRTIO_QUEUE_MAX, 2),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_virtio_msg_state_sub = {
    .name = "virtio_msg_proxy_backend/state",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(devs, VirtIOMSGProxy, VIRTIO_MSG_MAX_DEVS, 0,
                             vmstate_virtio_msg_dev, VirtIOMSGDev),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_virtio_msg = {
    .name = "virtio_msg_proxy_backend",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = virtio_msg_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * []) {
        &vmstate_virtio_msg_state_sub,
        NULL
    }
};

static void virtio_msg_save_extra_state(DeviceState *opaque, QEMUFile *f)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(opaque);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);

    vmstate_save_state(f, &vmstate_virtio_msg, s, NULL, &error_fatal);
}

static int virtio_msg_load_extra_state(DeviceState *opaque, QEMUFile *f)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(opaque);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);

    return vmstate_load_state(f, &vmstate_virtio_msg, s, 1, &error_fatal);
}

static bool virtio_msg_has_extra_state(DeviceState *opaque)
{
    return true;
}

static void virtio_msg_reset_hold(Object *obj, ResetType type)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(obj);
    VirtIODevice *vdev;
    bool found_a_vdev = false;
    int i;

    for (i = 0; i < ARRAY_SIZE(s->devs); i++) {
        virtio_msg_soft_reset(s, i);

        vdev = virtio_msg_vdev(s, i);
        if (vdev) {
            found_a_vdev = true;
        }
    }

    /* Only connect transports with virtio-devs.  */
    virtio_msg_connect_bus(s, found_a_vdev);
}

static bool virtio_msg_ioeventfd_enabled(DeviceState *d)
{
    /*
     * There is no MMIO/PIO notify register here for the kernel to bind an
     * eventfd to, but the host notifiers still work: virtio_msg_event_avail()
     * signals the per-queue one by hand when a kick arrives.  That is all a
     * dataplane needs, and saying otherwise costs virtio-blk and virtio-scsi
     * their iothreads ("ioeventfd is required for iothread") -- worth roughly
     * 7x on net p99 on rave2.
     */
    return true;
}

static int virtio_msg_ioeventfd_assign(DeviceState *d,
                                        EventNotifier *notifier,
                                        int n, bool assign)
{
    /*
     * virtio-msg has no MMIO/PIO notify register to bind an ioeventfd to.
     * Host kicks arrive via EVENT_AVAIL messages, and we explicitly signal
     * the per-queue host notifier in virtio_msg_event_avail().
     * Nothing to map here; return success so vhost can proceed.
     */
    return 0;
}

static int virtio_msg_set_guest_notifier(DeviceState *d, int n, bool assign,
                                          bool with_irqfd)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(d);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);
    VirtIODevice *vdev = virtio_msg_lookup_vdev(s, mdev->dev_num, __func__);
    VirtioDeviceClass *vdc;
    int r;

    if (!vdev) {
        return -ENODEV;
    }

    vdc = VIRTIO_DEVICE_GET_CLASS(vdev);

    r = virtio_set_guest_notifier(vdev, n, assign, with_irqfd);
    if (r < 0) {
        return r;
    }

    if (vdc->guest_notifier_mask && vdev->use_guest_notifier_mask) {
        vdc->guest_notifier_mask(vdev, n, !assign);
    }

    return 0;
}

static int virtio_msg_set_config_guest_notifier(DeviceState *d, bool assign,
                                                 bool with_irqfd)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(d);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);
    VirtIODevice *vdev = virtio_msg_lookup_vdev(s, mdev->dev_num, __func__);
    VirtioDeviceClass *vdc;
    int r;

    if (!vdev) {
        return -ENODEV;
    }

    vdc = VIRTIO_DEVICE_GET_CLASS(vdev);

    r = virtio_set_guest_notifier(vdev, VIRTIO_CONFIG_IRQ_IDX, assign,
                                  with_irqfd);
    if (r < 0) {
        return r;
    }

    if (vdc->guest_notifier_mask && vdev->use_guest_notifier_mask) {
        vdc->guest_notifier_mask(vdev, VIRTIO_CONFIG_IRQ_IDX, !assign);
    }
    return r;
}

static int virtio_msg_set_guest_notifiers(DeviceState *d, int nvqs,
                                          bool assign)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(d);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);
    VirtIODevice *vdev = virtio_msg_lookup_vdev(s, mdev->dev_num, __func__);
    /* Mirror virtio-mmio: use eventfd handlers and skip irqfd for now. */
    bool with_irqfd = false;
    int r, n;

    if (!vdev) {
        return -ENODEV;
    }

    nvqs = MIN(nvqs, VIRTIO_QUEUE_MAX);

    for (n = 0; n < nvqs; n++) {
        if (!virtio_queue_get_num(vdev, n)) {
            break;
        }

        r = virtio_msg_set_guest_notifier(d, n, assign, with_irqfd);
        if (r < 0) {
            goto assign_error;
        }
    }
    r = virtio_msg_set_config_guest_notifier(d, assign, with_irqfd);
    if (r < 0) {
        goto assign_error;
    }

    return 0;

assign_error:
    /* We get here on assignment failure. Recover by undoing for VQs 0 .. n. */
    assert(assign);
    while (--n >= 0) {
        virtio_msg_set_guest_notifier(d, n, !assign, false);
    }
    return r;
}

static void virtio_msg_reset_transport_caps(VirtIOMSGProxy *s)
{
    s->latched_caps = (VirtIOMSGTransportCaps) {
        .dma_as = &address_space_memory,
        .revision = VIRTIO_MSG_TRANSPORT_REVISION,
        .max_msg_size = VIRTIO_MSG_MAX_SIZE,
    };
    s->latched_caps_valid = false;
}

static bool virtio_msg_latch_transport_caps(VirtIOMSGProxy *s, Error **errp)
{
    VirtIOMSGTransportCaps caps;

    if (s->latched_caps_valid) {
        return true;
    }

    virtio_msg_bus_get_transport_caps(&s->msg_bus, &caps);
    if (!caps.ready) {
        error_setg(errp, "virtio-msg transport is not ready");
        return false;
    }
    if (caps.revision != VIRTIO_MSG_TRANSPORT_REVISION) {
        error_setg(errp,
                   "virtio-msg transport reported unsupported revision %u",
                   caps.revision);
        return false;
    }
    if (caps.max_msg_size < VIRTIO_MSG_MIN_SIZE ||
        caps.max_msg_size > sizeof(VirtIOMSG)) {
        error_setg(errp,
                   "virtio-msg transport reported max message size %u "
                   "outside supported range %u..%zu",
                   caps.max_msg_size, VIRTIO_MSG_MIN_SIZE,
                   sizeof(VirtIOMSG));
        return false;
    }
    if (caps.extra_features & ~VIRTIO_MSG_SUPPORTED_EXTRA_FEATURES) {
        error_setg(errp,
                   "virtio-msg transport reported unsupported extra "
                   "features 0x%" PRIx64,
                   (uint64_t)(caps.extra_features &
                              ~VIRTIO_MSG_SUPPORTED_EXTRA_FEATURES));
        return false;
    }
    if (!caps.dma_as) {
        error_setg(errp, "virtio-msg transport reported no DMA address space");
        return false;
    }

    caps.transport_features &= VIRTIO_MSG_SUPPORTED_TRANSPORT_FEATURES;
    s->latched_caps = caps;
    s->latched_caps_valid = true;
    return true;
}

static void virtio_msg_pre_plugged(DeviceState *d, Error **errp)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(d);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);
    VirtIODevice *vdev = virtio_msg_lookup_vdev(s, mdev->dev_num, __func__);

    if (!vdev) {
        return;
    }

    if (!virtio_msg_latch_transport_caps(s, errp)) {
        return;
    }

    virtio_add_feature(&vdev->host_features, VIRTIO_F_VERSION_1);
    vdev->host_features |= s->latched_caps.extra_features;
    virtio_clear_feature(&vdev->host_features,
                         VIRTIO_F_NOTIF_CONFIG_DATA);
}

static AddressSpace *virtio_msg_get_dma_as(DeviceState *d)
{
    /*
     * As with every other hook on this class, @d is the per-device
     * VirtIOMSGDev and not the proxy -- the msg bus hangs off the proxy, so
     * go through the device's back-pointer to reach it.  Casting @d straight
     * to VirtIOMSGProxy reads msg_bus out of the wrong object, which a build
     * with --disable-qom-cast-debug will not catch: it segfaults on the first
     * -device plugged onto the bus.
     */
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(d);
    VirtIOMSGProxy *s = VIRTIO_MSG(mdev->proxy);

    if (!s->latched_caps_valid || !s->latched_caps.ready ||
        !s->latched_caps.dma_as) {
        return &address_space_memory;
    }

    return s->latched_caps.dma_as;
}

static int virtio_msg_query_nvectors(DeviceState *d)
{
    return VIRTIO_QUEUE_MAX;
}

static bool virtio_msg_queue_enabled(DeviceState *d, int n)
{
    VirtIOMSGDev *mdev = VIRTIO_MSG_DEV(d);

    return n >= 0 && n < VIRTIO_QUEUE_MAX && mdev->queue_enabled[n];
}

static void virtio_msg_realize(DeviceState *d, Error **errp)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(d);
    Object *o = OBJECT(d);
    int i;

    virtio_msg_reset_transport_caps(s);

    for (i = 0; i < ARRAY_SIZE(s->devs); i++) {
        g_autofree char *outer_bus_name = g_strdup_printf("bus%d", i);

        qbus_init(&s->devs_bus[i], sizeof(s->devs_bus[i]),
                  TYPE_VIRTIO_MSG_OUTER_BUS, d, outer_bus_name);

        object_initialize_child(o, "dev[*]", &s->devs[i], TYPE_VIRTIO_MSG_DEV);
        s->devs[i].proxy = s;
        s->devs[i].dev_num = i;
        qdev_realize(DEVICE(&s->devs[i]), BUS(&s->devs_bus[i]), &error_fatal);

        qbus_init(&s->devs[i].bus, sizeof(s->devs[i].bus),
                  TYPE_VIRTIO_MSG_PROXY_BUS, DEVICE(&s->devs[i]), "bus");
    }

    qbus_init(&s->msg_bus, sizeof(s->msg_bus),
              TYPE_VIRTIO_MSG_BUS, d, "msg-bus");
}

static void virtio_msg_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    dc->realize = virtio_msg_realize;
    dc->bus_type = TYPE_VIRTIO_MSG_OUTER_BUS;
    dc->user_creatable = true;
    rc->phases.hold = virtio_msg_reset_hold;
}

static void virtio_msg_dev_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->bus_type = TYPE_VIRTIO_MSG_OUTER_BUS;
}

static const TypeInfo virtio_msg_types[] = {
    {
        .name          = TYPE_VIRTIO_MSG,
        .parent        = TYPE_DEVICE,
        .instance_size = sizeof(VirtIOMSGProxy),
        .class_init    = virtio_msg_class_init,
    },
    {
        .name          = TYPE_VIRTIO_MSG_DEV,
        .parent        = TYPE_DEVICE,
        .instance_size = sizeof(VirtIOMSGDev),
        .class_init    = virtio_msg_dev_class_init,
    },
};
DEFINE_TYPES(virtio_msg_types);

static char *virtio_msg_bus_get_dev_path(DeviceState *dev)
{
    BusState *bus = qdev_get_parent_bus(dev);
    return strdup(object_get_canonical_path(OBJECT(bus->parent)));
}

static void virtio_msg_bus_class_init(ObjectClass *klass, const void *data)
{
    BusClass *bus_class = BUS_CLASS(klass);
    VirtioBusClass *k = VIRTIO_BUS_CLASS(klass);

    k->notify = virtio_msg_notify;
    k->save_queue = virtio_msg_save_queue;
    k->load_queue = virtio_msg_load_queue;
    k->save_extra_state = virtio_msg_save_extra_state;
    k->load_extra_state = virtio_msg_load_extra_state;
    k->has_extra_state = virtio_msg_has_extra_state;
    k->pre_plugged = virtio_msg_pre_plugged;
    k->has_variable_vring_alignment = true;
    k->get_dma_as = virtio_msg_get_dma_as;
    k->query_nvectors = virtio_msg_query_nvectors;
    k->queue_enabled = virtio_msg_queue_enabled;

    k->set_guest_notifiers = virtio_msg_set_guest_notifiers;
    k->ioeventfd_enabled = virtio_msg_ioeventfd_enabled;
    k->ioeventfd_assign = virtio_msg_ioeventfd_assign;
    k->vmstate_change = virtio_msg_vmstate_change;

    /* Needed for multiple devs of the same kind (virtio-net).  */
    bus_class->get_dev_path = virtio_msg_bus_get_dev_path;

    /*
     * One virtio device per proxy bus.  Without this the bus never reads as
     * full and qdev puts every -device on the first one it finds, so only a
     * single device is ever visible to the driver -- and a second device of
     * the same kind trips the vmstate assert, because get_dev_path above
     * names the bus owner and both then share an idstr.
     */
    bus_class->max_dev = 1;
}

static const TypeInfo virtio_msg_bus_types[] = {
    {
        /* Specialized virtio-bus with our custom callbacks.  */
        .name          = TYPE_VIRTIO_MSG_PROXY_BUS,
        .parent        = TYPE_VIRTIO_BUS,
        .instance_size = sizeof(VirtioBusState),
        .class_init    = virtio_msg_bus_class_init,
    },
    {
        /*
         * Outer bus to hold virtio-msg objects making them visible to the
         * qom-tree.
         */
        .name          = TYPE_VIRTIO_MSG_OUTER_BUS,
        .parent        = TYPE_BUS,
        .instance_size = sizeof(BusState),
    },
};

DEFINE_TYPES(virtio_msg_bus_types);
