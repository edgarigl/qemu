/*
 * Virtio MSG - Message packing/unpacking functions.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VIRTIO_MSG_H
#define QEMU_VIRTIO_MSG_H

#include <stdint.h>
#include "standard-headers/linux/virtio_config.h"

enum {
    VIRTIO_MSG_NO_ERROR = 0,
    VIRTIO_MSG_ERROR_RETRY,
    VIRTIO_MSG_ERROR_TIMEOUT,
    VIRTIO_MSG_ERROR_UNSUPPORTED_MESSAGE_ID,
    VIRTIO_MSG_ERROR_BAD_MESSAGE,
    VIRTIO_MSG_ERROR_NO_DEVICE,
    VIRTIO_MSG_ERROR_MEMORY, /* General memory error. */
};

enum {
    VIRTIO_MSG_GET_DEVICE_INFO       = 0x02,
    VIRTIO_MSG_GET_DEVICE_FEATURES   = 0x03,
    VIRTIO_MSG_SET_DRIVER_FEATURES   = 0x04,
    VIRTIO_MSG_GET_CONFIG        = 0x05,
    VIRTIO_MSG_SET_CONFIG        = 0x06,
    VIRTIO_MSG_GET_DEVICE_STATUS = 0x07,
    VIRTIO_MSG_SET_DEVICE_STATUS = 0x08,
    VIRTIO_MSG_GET_VQUEUE        = 0x09,
    VIRTIO_MSG_SET_VQUEUE        = 0x0a,
    VIRTIO_MSG_RESET_VQUEUE      = 0x0b,
    VIRTIO_MSG_GET_SHM           = 0x0c, /* Not yet supported */
    VIRTIO_MSG_EVENT_CONFIG      = 0x40,
    VIRTIO_MSG_EVENT_AVAIL       = 0x41,
    VIRTIO_MSG_EVENT_USED        = 0x42,

    /* Generic bus messages.  */
    VIRTIO_MSG_BUS_GET_DEVICES   = 0x02,
    VIRTIO_MSG_BUS_PING          = 0x03,
    VIRTIO_MSG_BUS_EVENT_DEVICE  = 0x40,

    VIRTIO_MSG_MAX = VIRTIO_MSG_EVENT_USED,
};

#define VIRTIO_MSG_MIN_SIZE 52
#define VIRTIO_MSG_MAX_SIZE 64
#define VIRTIO_MSG_TRANSPORT_REVISION 1

#define VIRTIO_MSG_F_STRICT_CONFIG_GENERATION 0

#define VIRTIO_MSG_TYPE_RESPONSE  (1 << 0)
#define VIRTIO_MSG_TYPE_BUS       (1 << 1)
#define VIRTIO_MSG_TYPE_MASK      0x3
#define VIRTIO_MSG_ID_EVENT       (1 << 6)

#define VIRTIO_MSG_VQUEUE_F_ENABLED       (1U << 0)
#define VIRTIO_MSG_VQUEUE_STATE_MASK      0x3U
#define VIRTIO_MSG_VQUEUE_STATE_DISABLED  0x0U
#define VIRTIO_MSG_VQUEUE_STATE_ENABLED   0x1U
#define VIRTIO_MSG_VQUEUE_STATE_KEEP      0x2U
#define VIRTIO_MSG_VQUEUE_F_SIZE_IGNORE   (1U << 2)
#define VIRTIO_MSG_VQUEUE_F_DESC_IGNORE   (1U << 3)
#define VIRTIO_MSG_VQUEUE_F_DRIVER_IGNORE (1U << 4)
#define VIRTIO_MSG_VQUEUE_F_DEVICE_IGNORE (1U << 5)
#define VIRTIO_MSG_VQUEUE_F_VALID_MASK    0x3fU

typedef struct VirtIOMSG {
    uint8_t type;
    uint8_t msg_id;
    uint16_t dev_num;
    uint16_t token;
    uint16_t msg_size;

    union {
        uint8_t payload_u8[56];

        struct {
            uint32_t device_id;
            uint32_t vendor_id;
            uint8_t device_uuid[16];
            uint32_t num_feature_blocks;
            uint32_t config_size;
            uint32_t max_virtqueues;
            uint32_t admin_vq_start;
            uint32_t admin_vq_count;
        } QEMU_PACKED get_device_info_resp;
        struct {
            uint32_t block_index;
            uint32_t num_blocks;
        } QEMU_PACKED get_device_features;
        struct {
            uint32_t block_index;
            uint32_t num_blocks;
            uint32_t features[];
        } QEMU_PACKED get_device_features_resp;
        struct {
            uint32_t block_index;
            uint32_t num_blocks;
            uint32_t features[];
        } QEMU_PACKED set_driver_features;
        struct {
            uint32_t offset;
            uint32_t length;
        } QEMU_PACKED get_config;
        struct {
            uint32_t generation;
            uint32_t offset;
            uint32_t length;
            uint8_t data[];
        } QEMU_PACKED get_config_resp;
        struct {
            uint32_t generation;
            uint32_t offset;
            uint32_t length;
            uint8_t data[];
        } QEMU_PACKED set_config;
        struct {
            uint32_t generation;
            uint32_t offset;
            uint32_t length;
            uint8_t data[];
        } QEMU_PACKED set_config_resp;
        struct {
            uint32_t status;
        } QEMU_PACKED get_device_status_resp;
        struct {
            uint32_t status;
        } QEMU_PACKED set_device_status;
        struct {
            uint32_t status;
        } QEMU_PACKED set_device_status_resp;
        struct {
            uint32_t index;
        } QEMU_PACKED get_vqueue;
        struct {
            uint32_t index;
            uint32_t max_size;
            uint32_t cur_size;
            uint32_t flags;
            uint64_t desc_addr;
            uint64_t driver_addr;
            uint64_t device_addr;
        } QEMU_PACKED get_vqueue_resp;
        struct {
            uint32_t index;
            uint32_t flags;
            uint32_t size;
            uint32_t reserved;
            uint64_t desc_addr;
            uint64_t driver_addr;
            uint64_t device_addr;
        } QEMU_PACKED set_vqueue;
        struct {
            uint32_t index;
        } QEMU_PACKED reset_vqueue;
        struct {
            uint32_t shmid;
        } QEMU_PACKED get_shm;
        struct {
            uint32_t shmid;
            uint32_t reserved;
            uint64_t length;
            uint64_t address;
        } QEMU_PACKED get_shm_resp;
        struct {
            uint32_t device_status;
            uint32_t generation;
            uint32_t offset;
            uint32_t length;
            uint8_t data[];
        } QEMU_PACKED event_config;
        struct {
            uint32_t vq_index;
            uint32_t next_offset;
        } QEMU_PACKED event_avail;
        struct {
            uint32_t vq_index;
        } QEMU_PACKED event_used;

        /* Generic bus messages.  */
        struct {
            uint16_t offset;
            uint16_t count;
        } QEMU_PACKED bus_get_devices;
        struct {
            uint16_t offset;
            uint16_t next_offset;
            uint16_t count;
            uint8_t bitmap[];
        } QEMU_PACKED bus_get_devices_resp;
        struct {
            uint32_t data;
        } QEMU_PACKED bus_ping;
        struct {
            uint32_t data;
        } QEMU_PACKED bus_ping_resp;
        struct {
            uint16_t device_number;

#define VIRTIO_MSG_DEVICE_BUS_STATE_ADDED   0x0001
#define VIRTIO_MSG_DEVICE_BUS_STATE_REMOVED 0x0002
            uint16_t device_bus_state;
        } QEMU_PACKED bus_event_device;
    };
} QEMU_PACKED VirtIOMSG;

_Static_assert(sizeof(VirtIOMSG) == VIRTIO_MSG_MAX_SIZE,
               "virtio-msg record size must match the bus maximum");
_Static_assert(offsetof(VirtIOMSG, payload_u8) == 8,
               "virtio-msg header must be 8 bytes");
_Static_assert(sizeof(((VirtIOMSG *)0)->get_device_info_resp) == 44,
               "GET_DEVICE_INFO response layout mismatch");
_Static_assert(sizeof(((VirtIOMSG *)0)->get_vqueue_resp) == 40,
               "GET_VQUEUE response layout mismatch");
_Static_assert(sizeof(((VirtIOMSG *)0)->set_vqueue) == 40,
               "SET_VQUEUE request layout mismatch");
_Static_assert(sizeof(((VirtIOMSG *)0)->get_shm_resp) == 24,
               "GET_SHM response layout mismatch");
_Static_assert(sizeof(((VirtIOMSG *)0)->bus_get_devices_resp) == 6,
               "BUS_MSG_GET_DEVICES response layout mismatch");

/* Maximum number of 32b feature-blocks in a single message.  */
#define VIRTIO_MSG_MAX_FEATURE_NUM \
    ((VIRTIO_MSG_MAX_SIZE - \
      offsetof(VirtIOMSG, get_device_features_resp.features)) / 4)

/* Maximum amount of config-data in a single message, in bytes.  */
#define VIRTIO_MSG_MAX_CONFIG_BYTES \
    (VIRTIO_MSG_MAX_SIZE - offsetof(VirtIOMSG, set_config.data))

#define LE_TO_CPU(v)                                        \
{                                                           \
    if (sizeof(v) == 2) {                                   \
        v = le16_to_cpu(v);                                 \
    } else if (sizeof(v) == 4) {                            \
        v = le32_to_cpu(v);                                 \
    } else if (sizeof(v) == 8) {                            \
        v = le64_to_cpu(v);                                 \
    } else {                                                \
        g_assert_not_reached();                             \
    }                                                       \
}

static inline void virtio_msg_unpack_bus(VirtIOMSG *msg)
{
    switch (msg->msg_id) {
    case VIRTIO_MSG_BUS_PING:
        /* Both req and resp have the same layout.  */
        LE_TO_CPU(msg->bus_ping.data);
        break;
    case VIRTIO_MSG_BUS_GET_DEVICES:
        if (msg->type & VIRTIO_MSG_TYPE_RESPONSE) {
            LE_TO_CPU(msg->bus_get_devices_resp.offset);
            LE_TO_CPU(msg->bus_get_devices_resp.next_offset);
            LE_TO_CPU(msg->bus_get_devices_resp.count);
        } else {
            LE_TO_CPU(msg->bus_get_devices.offset);
            LE_TO_CPU(msg->bus_get_devices.count);
        }
        break;
    case VIRTIO_MSG_BUS_EVENT_DEVICE:
        LE_TO_CPU(msg->bus_event_device.device_number);
        LE_TO_CPU(msg->bus_event_device.device_bus_state);
        break;
    default:
        break;
    }
}

/**
 * virtio_msg_unpack_resp: Unpacks a wire virtio message responses into
 *                         a host version
 * @msg: the virtio message to unpack
 *
 * See virtio_msg_unpack().
 */
static inline void virtio_msg_unpack_resp(VirtIOMSG *msg)
{
    int i;

    switch (msg->msg_id) {
    case VIRTIO_MSG_GET_DEVICE_INFO:
        LE_TO_CPU(msg->get_device_info_resp.device_id);
        LE_TO_CPU(msg->get_device_info_resp.vendor_id);
        LE_TO_CPU(msg->get_device_info_resp.num_feature_blocks);
        LE_TO_CPU(msg->get_device_info_resp.config_size);
        LE_TO_CPU(msg->get_device_info_resp.max_virtqueues);
        LE_TO_CPU(msg->get_device_info_resp.admin_vq_start);
        LE_TO_CPU(msg->get_device_info_resp.admin_vq_count);
        break;
    case VIRTIO_MSG_GET_DEVICE_FEATURES:
        LE_TO_CPU(msg->get_device_features_resp.block_index);
        LE_TO_CPU(msg->get_device_features_resp.num_blocks);
        for (i = 0; i < VIRTIO_MSG_MAX_FEATURE_NUM &&
                    i < msg->get_device_features_resp.num_blocks; i++) {
            LE_TO_CPU(msg->get_device_features_resp.features[i]);
        }
        break;
    case VIRTIO_MSG_GET_DEVICE_STATUS:
        LE_TO_CPU(msg->get_device_status_resp.status);
        break;
    case VIRTIO_MSG_GET_CONFIG:
        LE_TO_CPU(msg->get_config_resp.generation);
        LE_TO_CPU(msg->get_config_resp.offset);
        LE_TO_CPU(msg->get_config_resp.length);
        break;
    case VIRTIO_MSG_GET_SHM:
        LE_TO_CPU(msg->get_shm_resp.shmid);
        LE_TO_CPU(msg->get_shm_resp.reserved);
        LE_TO_CPU(msg->get_shm_resp.length);
        LE_TO_CPU(msg->get_shm_resp.address);
        break;
    case VIRTIO_MSG_SET_CONFIG:
        LE_TO_CPU(msg->set_config_resp.generation);
        LE_TO_CPU(msg->set_config_resp.offset);
        LE_TO_CPU(msg->set_config_resp.length);
        break;
    case VIRTIO_MSG_SET_DEVICE_STATUS:
        LE_TO_CPU(msg->set_device_status_resp.status);
        break;
    case VIRTIO_MSG_GET_VQUEUE:
        LE_TO_CPU(msg->get_vqueue_resp.index);
        LE_TO_CPU(msg->get_vqueue_resp.max_size);
        LE_TO_CPU(msg->get_vqueue_resp.cur_size);
        LE_TO_CPU(msg->get_vqueue_resp.flags);
        LE_TO_CPU(msg->get_vqueue_resp.desc_addr);
        LE_TO_CPU(msg->get_vqueue_resp.driver_addr);
        LE_TO_CPU(msg->get_vqueue_resp.device_addr);
        break;
    default:
        break;
    }
}

/**
 * virtio_msg_unpack: Unpacks a wire virtio message into a host version
 * @msg: the virtio message to unpack
 *
 * Virtio messages arriving on the virtio message bus have a specific
 * format (little-endian, packet encoding, etc). To simplify for the
 * the rest of the implementation, we have packers and unpackers that
 * convert the wire messages into host versions. This includes endianess
 * conversion and potentially future decoding and expansion.
 *
 * At the moment, we only do endian conversion, virtio_msg_unpack() should
 * get completely eliminated by the compiler when targetting little-endian
 * hosts.
 */
static inline void virtio_msg_unpack(VirtIOMSG *msg)
{
    int i;

    LE_TO_CPU(msg->dev_num);
    LE_TO_CPU(msg->token);
    LE_TO_CPU(msg->msg_size);

    if (msg->type & VIRTIO_MSG_TYPE_BUS) {
        virtio_msg_unpack_bus(msg);
        return;
    }

    if (msg->type & VIRTIO_MSG_TYPE_RESPONSE) {
        virtio_msg_unpack_resp(msg);
        return;
    }

    switch (msg->msg_id) {
    case VIRTIO_MSG_GET_DEVICE_FEATURES:
        LE_TO_CPU(msg->get_device_features.block_index);
        LE_TO_CPU(msg->get_device_features.num_blocks);
        break;
    case VIRTIO_MSG_SET_DRIVER_FEATURES:
        LE_TO_CPU(msg->set_driver_features.block_index);
        LE_TO_CPU(msg->set_driver_features.num_blocks);
        for (i = 0; i < VIRTIO_MSG_MAX_FEATURE_NUM &&
                    i < msg->set_driver_features.num_blocks; i++) {
            LE_TO_CPU(msg->set_driver_features.features[i]);
        }
        break;
    case VIRTIO_MSG_SET_DEVICE_STATUS:
        LE_TO_CPU(msg->set_device_status.status);
        break;
    case VIRTIO_MSG_GET_CONFIG:
        LE_TO_CPU(msg->get_config.offset);
        LE_TO_CPU(msg->get_config.length);
        break;
    case VIRTIO_MSG_SET_CONFIG:
        LE_TO_CPU(msg->set_config.generation);
        LE_TO_CPU(msg->set_config.offset);
        LE_TO_CPU(msg->set_config.length);
        break;
    case VIRTIO_MSG_GET_SHM:
        LE_TO_CPU(msg->get_shm.shmid);
        break;
    case VIRTIO_MSG_GET_VQUEUE:
        LE_TO_CPU(msg->get_vqueue.index);
        break;
    case VIRTIO_MSG_SET_VQUEUE:
        LE_TO_CPU(msg->set_vqueue.index);
        LE_TO_CPU(msg->set_vqueue.flags);
        LE_TO_CPU(msg->set_vqueue.size);
        LE_TO_CPU(msg->set_vqueue.reserved);
        LE_TO_CPU(msg->set_vqueue.desc_addr);
        LE_TO_CPU(msg->set_vqueue.driver_addr);
        LE_TO_CPU(msg->set_vqueue.device_addr);
        break;
    case VIRTIO_MSG_RESET_VQUEUE:
        LE_TO_CPU(msg->reset_vqueue.index);
        break;
    case VIRTIO_MSG_EVENT_CONFIG:
        LE_TO_CPU(msg->event_config.device_status);
        LE_TO_CPU(msg->event_config.generation);
        LE_TO_CPU(msg->event_config.offset);
        LE_TO_CPU(msg->event_config.length);
        break;
    case VIRTIO_MSG_EVENT_AVAIL:
        LE_TO_CPU(msg->event_avail.vq_index);
        LE_TO_CPU(msg->event_avail.next_offset);
        break;
    case VIRTIO_MSG_EVENT_USED:
        LE_TO_CPU(msg->event_used.vq_index);
        break;
    default:
        break;
    }
}

static inline size_t virtio_msg_header_size(void)
{
    return offsetof(VirtIOMSG, payload_u8);
}

static inline void virtio_msg_pack_header(VirtIOMSG *msg,
                                          uint8_t msg_id,
                                          uint8_t type,
                                          uint16_t dev_num,
                                          uint16_t token,
                                          uint16_t payload_size)
{
    uint16_t msg_size = virtio_msg_header_size() + payload_size;

    msg->type = type;
    msg->msg_id = msg_id;
    msg->dev_num = cpu_to_le16(dev_num);
    msg->token = cpu_to_le16(token);
    msg->msg_size = cpu_to_le16(msg_size);

    /* Keep things predictable.  */
    memset(msg->payload_u8, 0, sizeof msg->payload_u8);
}

static inline void virtio_msg_pack_get_device_info(VirtIOMSG *msg,
                                                   uint16_t dev_num,
                                                   uint16_t token)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_INFO, 0,
                           dev_num, token, 0);
}

static inline void virtio_msg_pack_get_device_info_resp(VirtIOMSG *msg,
                                                   uint16_t dev_num,
                                                   uint16_t token,
                                                   uint32_t device_id,
                                                   uint32_t vendor_id,
                                                   uint32_t num_feature_blocks,
                                                   uint32_t config_size,
                                                   uint32_t max_virtqueues,
                                                   uint32_t admin_vq_start,
                                                   uint32_t admin_vq_count)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_INFO,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token,
                           sizeof msg->get_device_info_resp);

    msg->get_device_info_resp.device_id = cpu_to_le32(device_id);
    msg->get_device_info_resp.vendor_id = cpu_to_le32(vendor_id);
    memset(msg->get_device_info_resp.device_uuid, 0,
           sizeof(msg->get_device_info_resp.device_uuid));
    msg->get_device_info_resp.num_feature_blocks =
        cpu_to_le32(num_feature_blocks);
    msg->get_device_info_resp.config_size = cpu_to_le32(config_size);
    msg->get_device_info_resp.max_virtqueues = cpu_to_le32(max_virtqueues);
    msg->get_device_info_resp.admin_vq_start = cpu_to_le32(admin_vq_start);
    msg->get_device_info_resp.admin_vq_count = cpu_to_le32(admin_vq_count);
}

static inline void virtio_msg_pack_get_device_features(VirtIOMSG *msg,
                                                       uint16_t dev_num,
                                                       uint16_t token,
                                                       uint32_t index,
                                                       uint32_t num)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_FEATURES, 0,
                           dev_num, token,
                           sizeof msg->get_device_features);

    msg->get_device_features.block_index = cpu_to_le32(index);
    msg->get_device_features.num_blocks = cpu_to_le32(num);
}

static inline void virtio_msg_pack_get_device_features_resp(VirtIOMSG *msg,
                                                            uint16_t dev_num,
                                                            uint16_t token,
                                                            uint32_t index,
                                                            uint32_t num,
                                                            uint32_t *f)
{
    unsigned int i;

    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_FEATURES,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token,
                           sizeof msg->get_device_features_resp +
                           num * sizeof(*f));

    msg->get_device_features_resp.block_index = cpu_to_le32(index);
    msg->get_device_features_resp.num_blocks = cpu_to_le32(num);

    assert(num <= VIRTIO_MSG_MAX_FEATURE_NUM);

    for (i = 0; i < num && i < VIRTIO_MSG_MAX_FEATURE_NUM; i++) {
        msg->get_device_features_resp.features[i] = cpu_to_le32(f[i]);
    }
}

static inline void virtio_msg_pack_set_driver_features(VirtIOMSG *msg,
                                                       uint16_t dev_num,
                                                       uint16_t token,
                                                       uint32_t index,
                                                       uint32_t num,
                                                       uint32_t *f)
{
    unsigned int i;

    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DRIVER_FEATURES, 0,
                           dev_num, token,
                           sizeof msg->set_driver_features +
                           num * sizeof(*f));

    msg->set_driver_features.block_index = cpu_to_le32(index);
    msg->set_driver_features.num_blocks = cpu_to_le32(num);

    assert(num <= VIRTIO_MSG_MAX_FEATURE_NUM);

    for (i = 0; i < num && i < VIRTIO_MSG_MAX_FEATURE_NUM; i++) {
        msg->set_driver_features.features[i] = cpu_to_le32(f[i]);
    }
}

static inline void virtio_msg_pack_set_driver_features_resp(VirtIOMSG *msg,
                                                            uint16_t dev_num,
                                                            uint16_t token)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DRIVER_FEATURES,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token, 0);
}

static inline void virtio_msg_pack_set_device_status(VirtIOMSG *msg,
                                                     uint16_t dev_num,
                                                     uint16_t token,
                                                     uint32_t status)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_STATUS, 0, dev_num,
                           token, sizeof msg->set_device_status);

    msg->set_device_status.status = cpu_to_le32(status);
}

static inline void virtio_msg_pack_set_device_status_resp(VirtIOMSG *msg,
                                                          uint16_t dev_num,
                                                          uint16_t token,
                                                          uint32_t status)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_STATUS,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token,
                           sizeof msg->set_device_status_resp);

    msg->set_device_status_resp.status = cpu_to_le32(status);
}

static inline void virtio_msg_pack_get_device_status(VirtIOMSG *msg,
                                                     uint16_t dev_num,
                                                     uint16_t token)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_STATUS, 0,
                           dev_num, token, 0);
}

static inline void virtio_msg_pack_get_device_status_resp(VirtIOMSG *msg,
                                                          uint16_t dev_num,
                                                          uint16_t token,
                                                          uint32_t status)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_STATUS,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token,
                           sizeof msg->get_device_status_resp);

    msg->get_device_status_resp.status = cpu_to_le32(status);
}

static inline void virtio_msg_pack_get_config(VirtIOMSG *msg,
                                              uint16_t dev_num,
                                              uint16_t token,
                                              uint32_t size,
                                              uint32_t offset)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_CONFIG, 0, dev_num, token,
                           sizeof msg->get_config);

    msg->get_config.offset = cpu_to_le32(offset);
    msg->get_config.length = cpu_to_le32(size);
}

static inline void virtio_msg_pack_get_config_resp(VirtIOMSG *msg,
                                                   uint16_t dev_num,
                                                   uint16_t token,
                                                   uint32_t size,
                                                   uint32_t offset,
                                                   uint32_t generation,
                                                   uint8_t data[])
{
    assert(size <= VIRTIO_MSG_MAX_CONFIG_BYTES);

    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_CONFIG,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token,
                           sizeof msg->get_config_resp + size);

    msg->get_config_resp.generation = cpu_to_le32(generation);
    msg->get_config_resp.offset = cpu_to_le32(offset);
    msg->get_config_resp.length = cpu_to_le32(size);

    memcpy(&msg->get_config_resp.data, data, size);
}

static inline void virtio_msg_pack_set_config(VirtIOMSG *msg,
                                              uint16_t dev_num,
                                              uint16_t token,
                                              uint32_t size,
                                              uint32_t offset,
                                              uint32_t generation,
                                              uint8_t data[])
{
    assert(size <= VIRTIO_MSG_MAX_CONFIG_BYTES);

    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_CONFIG, 0, dev_num, token,
                           sizeof msg->set_config + size);

    msg->set_config.offset = cpu_to_le32(offset);
    msg->set_config.length = cpu_to_le32(size);
    msg->set_config.generation = cpu_to_le32(generation);

    memcpy(&msg->set_config.data, data, size);
}

static inline void virtio_msg_pack_set_config_resp(VirtIOMSG *msg,
                                                   uint16_t dev_num,
                                                   uint16_t token,
                                                   uint32_t size,
                                                   uint32_t offset,
                                                   uint32_t generation,
                                                   uint8_t data[])
{
    assert(size <= VIRTIO_MSG_MAX_CONFIG_BYTES);

    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_CONFIG,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token,
                           sizeof msg->set_config_resp + size);

    msg->set_config_resp.offset = cpu_to_le32(offset);
    msg->set_config_resp.length = cpu_to_le32(size);
    msg->set_config_resp.generation = cpu_to_le32(generation);

    memcpy(&msg->set_config_resp.data, data, size);
}

static inline void virtio_msg_pack_get_vqueue(VirtIOMSG *msg,
                                              uint16_t dev_num,
                                              uint16_t token,
                                              uint32_t index)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_VQUEUE, 0, dev_num, token,
                           sizeof msg->get_vqueue);

    msg->get_vqueue.index = cpu_to_le32(index);
}

static inline void virtio_msg_pack_get_vqueue_resp(VirtIOMSG *msg,
                                                   uint16_t dev_num,
                                                   uint16_t token,
                                                   uint32_t index,
                                                   uint32_t max_size,
                                                   uint32_t cur_size,
                                                   uint32_t flags,
                                                   uint64_t desc_addr,
                                                   uint64_t driver_addr,
                                                   uint64_t device_addr)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_VQUEUE,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token,
                           sizeof msg->get_vqueue_resp);

    msg->get_vqueue_resp.index = cpu_to_le32(index);
    msg->get_vqueue_resp.max_size = cpu_to_le32(max_size);
    msg->get_vqueue_resp.cur_size = cpu_to_le32(cur_size);
    msg->get_vqueue_resp.flags = cpu_to_le32(flags);
    msg->get_vqueue_resp.desc_addr = cpu_to_le64(desc_addr);
    msg->get_vqueue_resp.driver_addr = cpu_to_le64(driver_addr);
    msg->get_vqueue_resp.device_addr = cpu_to_le64(device_addr);
}

static inline void virtio_msg_pack_reset_vqueue(VirtIOMSG *msg,
                                                uint16_t dev_num,
                                                uint16_t token,
                                                uint32_t index)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_RESET_VQUEUE, 0, dev_num, token,
                           sizeof msg->reset_vqueue);

    msg->reset_vqueue.index = cpu_to_le32(index);
}

static inline void virtio_msg_pack_reset_vqueue_resp(VirtIOMSG *msg,
                                                     uint16_t dev_num,
                                                     uint16_t token)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_RESET_VQUEUE,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token, 0);
}

static inline void virtio_msg_pack_get_shm(VirtIOMSG *msg,
                                           uint16_t dev_num,
                                           uint16_t token,
                                           uint32_t shmid)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_SHM, 0, dev_num, token,
                           sizeof msg->get_shm);

    msg->get_shm.shmid = cpu_to_le32(shmid);
}

static inline void virtio_msg_pack_get_shm_resp(VirtIOMSG *msg,
                                                uint16_t dev_num,
                                                uint16_t token,
                                                uint32_t shmid,
                                                uint64_t length,
                                                uint64_t address)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_SHM,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token,
                           sizeof msg->get_shm_resp);

    msg->get_shm_resp.shmid = cpu_to_le32(shmid);
    msg->get_shm_resp.reserved = 0;
    msg->get_shm_resp.length = cpu_to_le64(length);
    msg->get_shm_resp.address = cpu_to_le64(address);
}

static inline void virtio_msg_pack_set_vqueue(VirtIOMSG *msg,
                                              uint16_t dev_num,
                                              uint16_t token,
                                              uint32_t index,
                                              uint32_t flags,
                                              uint32_t size,
                                              uint64_t desc_addr,
                                              uint64_t driver_addr,
                                              uint64_t device_addr)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_VQUEUE, 0, dev_num, token,
                           sizeof msg->set_vqueue);

    msg->set_vqueue.index = cpu_to_le32(index);
    msg->set_vqueue.flags = cpu_to_le32(flags);
    msg->set_vqueue.size = cpu_to_le32(size);
    msg->set_vqueue.reserved = 0;
    msg->set_vqueue.desc_addr = cpu_to_le64(desc_addr);
    msg->set_vqueue.driver_addr = cpu_to_le64(driver_addr);
    msg->set_vqueue.device_addr = cpu_to_le64(device_addr);
}

static inline void virtio_msg_pack_set_vqueue_resp(VirtIOMSG *msg,
                                                   uint16_t dev_num,
                                                   uint16_t token)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_VQUEUE,
                           VIRTIO_MSG_TYPE_RESPONSE, dev_num, token, 0);
}

static inline void virtio_msg_pack_event_avail(VirtIOMSG *msg,
                                               uint16_t dev_num,
                                               uint32_t index,
                                               uint32_t next_offset,
                                               bool next_wrap)
{
    uint32_t next_ow;

    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_AVAIL, 0, dev_num, 0,
                           sizeof msg->event_avail);

    /* next_offset is 31b wide.  */
    assert((next_offset & 0x80000000U) == 0);

    /* Pack the next offset and wrap bit. */
    next_ow = next_wrap << 31;
    next_ow |= next_offset;

    msg->event_avail.vq_index = cpu_to_le32(index);
    msg->event_avail.next_offset = cpu_to_le32(next_ow);
}

static inline void virtio_msg_pack_event_used(VirtIOMSG *msg,
                                              uint16_t dev_num,
                                              uint32_t index)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_USED, 0, dev_num, 0,
                           sizeof msg->event_used);

    msg->event_used.vq_index = cpu_to_le32(index);
}

static inline void virtio_msg_pack_event_config(VirtIOMSG *msg,
                                                uint16_t dev_num,
                                                uint32_t status,
                                                uint32_t generation,
                                                uint32_t offset,
                                                uint32_t size,
                                                uint8_t *value)
{
    unsigned int max_size;

    max_size = VIRTIO_MSG_MAX_SIZE;
    max_size -= offsetof(VirtIOMSG, event_config.data);
    assert(size <= max_size);

    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_CONFIG, 0, dev_num, 0,
                           sizeof msg->event_config + size);

    msg->event_config.device_status = cpu_to_le32(status);
    msg->event_config.generation = cpu_to_le32(generation);
    msg->event_config.offset = cpu_to_le32(offset);
    msg->event_config.length = cpu_to_le32(size);

    if (size > 0 && size <= max_size) {
        memcpy(&msg->event_config.data[0], value, size);
    }
}

static inline void virtio_msg_pack_bus_get_devices(VirtIOMSG *msg,
                                                   uint16_t offset,
                                                   uint16_t num)
{
    virtio_msg_pack_header(msg,
                           VIRTIO_MSG_BUS_GET_DEVICES, VIRTIO_MSG_TYPE_BUS,
                           0, 0, sizeof msg->bus_get_devices);

    msg->bus_get_devices.offset = cpu_to_le16(offset);
    msg->bus_get_devices.count = cpu_to_le16(num);
}

static inline void virtio_msg_pack_bus_get_devices_resp(VirtIOMSG *msg,
                                                        uint16_t token,
                                                        uint16_t offset,
                                                        uint16_t num,
                                                        uint16_t next_offset,
                                                        uint8_t *data)
{
    size_t byte_len = (num + 7) / 8;

    virtio_msg_pack_header(msg,
                           VIRTIO_MSG_BUS_GET_DEVICES,
                           VIRTIO_MSG_TYPE_BUS | VIRTIO_MSG_TYPE_RESPONSE,
                           0, token,
                           sizeof msg->bus_get_devices_resp + byte_len);

    msg->bus_get_devices_resp.offset = cpu_to_le16(offset);
    msg->bus_get_devices_resp.next_offset = cpu_to_le16(next_offset);
    msg->bus_get_devices_resp.count = cpu_to_le16(num);

    if (byte_len > 0) {
        memcpy(msg->bus_get_devices_resp.bitmap, data, byte_len);
    }
}

static inline void virtio_msg_pack_bus_ping_resp(VirtIOMSG *msg,
                                                 uint16_t token,
                                                 uint32_t data)
{
    virtio_msg_pack_header(msg,
                           VIRTIO_MSG_BUS_PING,
                           VIRTIO_MSG_TYPE_BUS | VIRTIO_MSG_TYPE_RESPONSE,
                           0, token, sizeof msg->bus_ping_resp);

    msg->bus_ping_resp.data = cpu_to_le32(data);
}

static inline void virtio_msg_pack_bus_event_device(VirtIOMSG *msg,
                                                    uint16_t dev_num,
                                                    uint16_t dev_state)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_BUS_EVENT_DEVICE,
                           VIRTIO_MSG_TYPE_BUS, 0, 0,
                           sizeof msg->bus_event_device);

    msg->bus_event_device.device_number = cpu_to_le16(dev_num);
    msg->bus_event_device.device_bus_state = cpu_to_le16(dev_state);
}

static inline const char *virtio_msg_id_to_str(uint8_t type, uint8_t msg_id)
{
#define VIRTIO_MSG_TYPE2STR(x) [VIRTIO_MSG_ ## x] = stringify(x)
    const char *name;
    static const char *type2str[VIRTIO_MSG_MAX + 1] = {
        VIRTIO_MSG_TYPE2STR(GET_DEVICE_INFO),
        VIRTIO_MSG_TYPE2STR(GET_DEVICE_FEATURES),
        VIRTIO_MSG_TYPE2STR(SET_DRIVER_FEATURES),
        VIRTIO_MSG_TYPE2STR(GET_CONFIG),
        VIRTIO_MSG_TYPE2STR(SET_CONFIG),
        VIRTIO_MSG_TYPE2STR(GET_DEVICE_STATUS),
        VIRTIO_MSG_TYPE2STR(SET_DEVICE_STATUS),
        VIRTIO_MSG_TYPE2STR(GET_VQUEUE),
        VIRTIO_MSG_TYPE2STR(SET_VQUEUE),
        VIRTIO_MSG_TYPE2STR(RESET_VQUEUE),
        VIRTIO_MSG_TYPE2STR(EVENT_CONFIG),
        VIRTIO_MSG_TYPE2STR(EVENT_AVAIL),
        VIRTIO_MSG_TYPE2STR(EVENT_USED),
    };
    static const char *bus_type2str[VIRTIO_MSG_MAX + 1] = {
        VIRTIO_MSG_TYPE2STR(BUS_GET_DEVICES),
        VIRTIO_MSG_TYPE2STR(BUS_PING),
        VIRTIO_MSG_TYPE2STR(BUS_EVENT_DEVICE),
    };

    if (msg_id > VIRTIO_MSG_MAX) {
        return "UNKNOWN";
    }
    if (type & VIRTIO_MSG_TYPE_BUS) {
        name = bus_type2str[msg_id];
    } else {
        name = type2str[msg_id];
    }

    return name ? name : "UNKNOWN";
}

static inline void virtio_msg_print_status(uint32_t status)
{
    printf("status %x", status);

    if (status & VIRTIO_CONFIG_S_ACKNOWLEDGE) {
        printf(" ACKNOWLEDGE");
    }
    if (status & VIRTIO_CONFIG_S_DRIVER) {
        printf(" DRIVER");
    }
    if (status & VIRTIO_CONFIG_S_DRIVER_OK) {
        printf(" DRIVER_OK");
    }
    if (status & VIRTIO_CONFIG_S_FEATURES_OK) {
        printf(" FEATURES_OK");
    }
    if (status & VIRTIO_CONFIG_S_NEEDS_RESET) {
        printf(" NEEDS_RESET");
    }
    if (status & VIRTIO_CONFIG_S_FAILED) {
        printf(" FAILED");
    }

    printf("\n");
}

static inline void virtio_msg_print(VirtIOMSG *msg)
{
    bool resp = msg->type & VIRTIO_MSG_TYPE_RESPONSE;
    size_t payload_size;
    int i;

    assert(msg);
    printf("virtio-msg: id %s 0x%x type 0x%x dev_num 0x%x msg_size 0x%x\n",
           virtio_msg_id_to_str(msg->type, msg->msg_id), msg->msg_id,
           msg->type, msg->dev_num, msg->msg_size);

    payload_size = msg->msg_size - offsetof(VirtIOMSG, payload_u8);
    if (payload_size > ARRAY_SIZE(msg->payload_u8)) {
        printf("Size overflow! %zu > %zu\n",
                payload_size, ARRAY_SIZE(msg->payload_u8));
        payload_size = ARRAY_SIZE(msg->payload_u8);
    }

    for (i = 0; i < payload_size; i++) {
        printf("%2.2x ", msg->payload_u8[i]);
        if (((i + 1) %  16) == 0) {
            printf("\n");
        }
    }

    switch (msg->msg_id) {
    case VIRTIO_MSG_GET_DEVICE_STATUS:
        if (resp) {
            virtio_msg_print_status(msg->get_device_status_resp.status);
        }
        break;
    case VIRTIO_MSG_SET_DEVICE_STATUS:
        virtio_msg_print_status(msg->set_device_status.status);
        break;
    case VIRTIO_MSG_SET_VQUEUE:
        printf("set-vqueue: index=%d size=%d desc-addr=%lx "
               "driver-addr=%lx device-addr=%lx\n",
               msg->set_vqueue.index, msg->set_vqueue.size,
               msg->set_vqueue.desc_addr,
               msg->set_vqueue.driver_addr,
               msg->set_vqueue.device_addr);
        break;
    }
    printf("\n");
}
#endif
