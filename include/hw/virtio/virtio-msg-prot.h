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

/* v0.0.1.  */
#define VIRTIO_MSG_DEVICE_VERSION 0x000001
#define VIRTIO_MSG_VENDOR_ID 0x554D4551 /* 'QEMU' */

enum {
    VIRTIO_MSG_NO_ERROR = 0,
    VIRTIO_MSG_ERROR_UNSUPPORTED_PACKET_TYPE = 1,
};

enum {
    VIRTIO_MSG_CONNECT           = 0x01,
    VIRTIO_MSG_DISCONNECT        = 0x02,
    VIRTIO_MSG_DEVICE_INFO       = 0x10,
    VIRTIO_MSG_GET_DEVICE_FEAT   = 0x14,
    VIRTIO_MSG_SET_DEVICE_FEAT   = 0x15,
    VIRTIO_MSG_GET_DEVICE_CONF   = 0x18,
    VIRTIO_MSG_SET_DEVICE_CONF   = 0x19,
    VIRTIO_MSG_GET_CONF_GEN      = 0x1a,
    VIRTIO_MSG_EVENT_CONF        = 0x1b,
    VIRTIO_MSG_GET_DEVICE_STATUS = 0x20,
    VIRTIO_MSG_SET_DEVICE_STATUS = 0x21,
    VIRTIO_MSG_GET_VQUEUE        = 0x30,
    VIRTIO_MSG_SET_VQUEUE        = 0x31,
    VIRTIO_MSG_RESET_VQUEUE      = 0x32,
    VIRTIO_MSG_EVENT_DRIVER      = 0x33,
    VIRTIO_MSG_EVENT_DEVICE      = 0x34,
    VIRTIO_MSG_MAX = VIRTIO_MSG_EVENT_DEVICE + 1
};

#define VIRTIO_MSG_MAX_SIZE 40

typedef struct VirtIOMSGPayload {
    union {
        uint8_t u8[32];

        struct {
            uint32_t device_version;
            uint32_t device_id;
            uint32_t vendor_id;
        } QEMU_PACKED get_device_info_resp;
        struct {
            uint32_t index;
        } QEMU_PACKED get_device_feat;
        struct {
            uint32_t index;
            uint64_t features;
        } QEMU_PACKED get_device_feat_resp;
        struct {
            uint32_t index;
            uint64_t features;
        } QEMU_PACKED set_device_feat;
        struct {
            uint32_t status;
        } QEMU_PACKED get_device_status_resp;
        struct {
            uint32_t status;
        } QEMU_PACKED set_device_status;
        struct {
            uint32_t size;
            uint32_t offset;
        } QEMU_PACKED get_device_conf;
        struct {
            uint32_t size;
            uint32_t offset;
            uint32_t data;
        } QEMU_PACKED get_device_conf_resp;
        struct {
            uint32_t size;
            uint32_t offset;
            uint32_t data;
        } QEMU_PACKED set_device_conf;
        struct {
            uint32_t generation;
        } QEMU_PACKED get_conf_gen_resp;
        struct {
            uint32_t index;
        } QEMU_PACKED get_vqueue;
        struct {
            uint32_t index;
            uint32_t max_size;
        } QEMU_PACKED get_vqueue_resp;
        struct {
            uint32_t index;
            uint32_t size;
            uint64_t descriptor_addr;
            uint64_t driver_addr;
            uint64_t device_addr;
        } QEMU_PACKED set_vqueue;
        struct {
            uint32_t index;
            uint64_t next_offset;
            uint64_t next_wrap;
        } QEMU_PACKED event_driver;
        struct {
            uint32_t index;
        } QEMU_PACKED event_device;
    };
} QEMU_PACKED VirtIOMSGPayload;

typedef struct VirtIOMSG {
    uint8_t type;
    uint8_t msg_id;
    uint16_t dev_id;
    uint32_t unused;

    VirtIOMSGPayload payload;
} QEMU_PACKED VirtIOMSG;

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


/**
 * virtio_msg_unpack: Unpacks a wire virtio message into a host version
 * @msg: the virtio message to unpack
 *
 * Virtio messages arriving on the virtio message bus have a specific
 * formate (little-endian, packet encoding, etc). To simplify for the
 * the rest of the implementation, we have packers and unpackers that
 * convert the wire messages into host versions. This includes endianess
 * conversion and potentially future decoding and expansion.
 *
 * At the moment, we only do endian conversion, virtio_msg_unpack() should
 * get completely eliminated by the compiler when targetting little-endian
 * hosts.
 */
static inline void virtio_msg_unpack(VirtIOMSG *msg) {
    VirtIOMSGPayload *pl = &msg->payload;

    LE_TO_CPU(msg->dev_id);

    switch (msg->type) {
    case VIRTIO_MSG_GET_DEVICE_FEAT:
        LE_TO_CPU(pl->get_device_feat.index);
        break;
    case VIRTIO_MSG_SET_DEVICE_FEAT:
        LE_TO_CPU(pl->set_device_feat.index);
        LE_TO_CPU(pl->set_device_feat.features);
        break;
    case VIRTIO_MSG_SET_DEVICE_STATUS:
        LE_TO_CPU(pl->set_device_status.status);
        break;
    case VIRTIO_MSG_GET_DEVICE_CONF:
        LE_TO_CPU(pl->get_device_conf.size);
        LE_TO_CPU(pl->get_device_conf.offset);
        break;
    case VIRTIO_MSG_SET_DEVICE_CONF:
        LE_TO_CPU(pl->set_device_conf.size);
        LE_TO_CPU(pl->set_device_conf.offset);
        LE_TO_CPU(pl->set_device_conf.data);
        break;
    case VIRTIO_MSG_GET_VQUEUE:
        LE_TO_CPU(pl->get_vqueue.index);
        break;
    case VIRTIO_MSG_SET_VQUEUE:
        LE_TO_CPU(pl->set_vqueue.index);
        LE_TO_CPU(pl->set_vqueue.size);
        LE_TO_CPU(pl->set_vqueue.descriptor_addr);
        LE_TO_CPU(pl->set_vqueue.driver_addr);
        LE_TO_CPU(pl->set_vqueue.device_addr);
        break;
    case VIRTIO_MSG_EVENT_DRIVER:
        LE_TO_CPU(pl->event_driver.index);
        LE_TO_CPU(pl->event_driver.next_offset);
        LE_TO_CPU(pl->event_driver.next_wrap);
        break;
    case VIRTIO_MSG_EVENT_DEVICE:
        LE_TO_CPU(pl->event_device.index);
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
    VirtIOMSGPayload *pl = &msg->payload;

    LE_TO_CPU(msg->dev_id);

    switch (msg->type) {
    case VIRTIO_MSG_DEVICE_INFO:
        LE_TO_CPU(pl->get_device_info_resp.device_version);
        LE_TO_CPU(pl->get_device_info_resp.device_id);
        LE_TO_CPU(pl->get_device_info_resp.vendor_id);
        break;
    case VIRTIO_MSG_GET_DEVICE_FEAT:
        LE_TO_CPU(pl->get_device_feat_resp.index);
        LE_TO_CPU(pl->get_device_feat_resp.features);
        break;
    case VIRTIO_MSG_GET_DEVICE_STATUS:
        LE_TO_CPU(pl->get_device_status_resp.status);
        break;
    case VIRTIO_MSG_GET_DEVICE_CONF:
        LE_TO_CPU(pl->get_device_conf_resp.size);
        LE_TO_CPU(pl->get_device_conf_resp.offset);
        LE_TO_CPU(pl->get_device_conf_resp.data);
        break;
    case VIRTIO_MSG_GET_VQUEUE:
        LE_TO_CPU(pl->get_vqueue_resp.index);
        LE_TO_CPU(pl->get_vqueue_resp.max_size);
        break;
    default:
        break;
    }
}

static inline void virtio_msg_pack_header(VirtIOMSG *msg,
                                          uint8_t type,
                                          uint8_t msg_id,
                                          uint16_t dev_id)
{
    msg->type = type;
    msg->msg_id = msg_id; /* sequence number? */
    msg->dev_id = cpu_to_le16(dev_id); /* dest demux? */

    /* Keep things predictable.  */
    memset(msg->payload.u8, 0, sizeof msg->payload.u8);
}

static inline void virtio_msg_pack_get_device_info(VirtIOMSG *msg)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_DEVICE_INFO, 0, 0);
}

static inline void virtio_msg_pack_get_device_info_resp(VirtIOMSG *msg,
                                                   uint32_t dev_version,
                                                   uint32_t dev_id,
                                                   uint32_t vendor_id)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_DEVICE_INFO, 0, 0);

    pl->get_device_info_resp.device_version = cpu_to_le32(dev_version);
    pl->get_device_info_resp.device_id = cpu_to_le32(dev_id);
    pl->get_device_info_resp.vendor_id = cpu_to_le32(vendor_id);
}

static inline void virtio_msg_pack_get_device_feat(VirtIOMSG *msg,
                                                   uint32_t index)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_FEAT, 0, 0);

    pl->get_device_feat.index = cpu_to_le32(index);
}

static inline void virtio_msg_pack_get_device_feat_resp(VirtIOMSG *msg,
                                                   uint32_t index,
                                                   uint64_t f)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_FEAT, 0, 0);

    pl->get_device_feat_resp.index = cpu_to_le32(index);
    pl->get_device_feat_resp.features = cpu_to_le64(f);
}

static inline void virtio_msg_pack_set_device_feat(VirtIOMSG *msg,
                                                   uint32_t index,
                                                   uint64_t f)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_FEAT, 0, 0);

    pl->set_device_feat.index = cpu_to_le32(index);
    pl->set_device_feat.features = cpu_to_le64(f);
}

static inline void virtio_msg_pack_set_device_status(VirtIOMSG *msg,
                                                     uint32_t status)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_STATUS, 0, 0);

    pl->set_device_status.status = cpu_to_le32(status);
}

static inline void virtio_msg_pack_get_device_status(VirtIOMSG *msg)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_STATUS, 0, 0);
}

static inline void virtio_msg_pack_get_device_status_resp(VirtIOMSG *msg,
                                                          uint32_t status)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_STATUS, 0, 0);

    pl->get_device_status_resp.status = cpu_to_le32(status);
}

static inline void virtio_msg_pack_get_device_conf(VirtIOMSG *msg,
                                                   uint32_t size,
                                                   uint32_t offset)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_CONF, 0, 0);

    pl->get_device_conf.size = cpu_to_le32(size);
    pl->get_device_conf.offset = cpu_to_le32(offset);
}

static inline void virtio_msg_pack_get_device_conf_resp(VirtIOMSG *msg,
                                                        uint32_t size,
                                                        uint32_t offset,
                                                        uint32_t data)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_CONF, 0, 0);

    pl->get_device_conf_resp.size = cpu_to_le32(size);
    pl->get_device_conf_resp.offset = cpu_to_le32(offset);
    pl->get_device_conf_resp.data = cpu_to_le32(data);
}

static inline void virtio_msg_pack_set_device_conf(VirtIOMSG *msg,
                                                   uint32_t size,
                                                   uint32_t offset,
                                                   uint32_t data)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_CONF, 0, 0);

    pl->set_device_conf.size = cpu_to_le32(size);
    pl->set_device_conf.offset = cpu_to_le32(offset);
    pl->set_device_conf.data = cpu_to_le32(data);
}

static inline void virtio_msg_pack_get_vqueue(VirtIOMSG *msg,
                                              uint32_t index)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_VQUEUE, 0, 0);

    pl->get_vqueue.index = cpu_to_le32(index);
}

static inline void virtio_msg_pack_get_vqueue_resp(VirtIOMSG *msg,
                                                   uint32_t index,
                                                   uint32_t max_size)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_VQUEUE, 0, 0);

    pl->get_vqueue_resp.index = cpu_to_le32(index);
    pl->get_vqueue_resp.max_size = cpu_to_le32(max_size);
}

static inline void virtio_msg_pack_set_vqueue(VirtIOMSG *msg,
                                              uint32_t index,
                                              uint32_t size,
                                              uint64_t descriptor_addr,
                                              uint64_t driver_addr,
                                              uint64_t device_addr)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_VQUEUE, 0, 0);

    pl->set_vqueue.index = cpu_to_le32(index);
    pl->set_vqueue.size = cpu_to_le32(size);
    pl->set_vqueue.descriptor_addr = cpu_to_le64(descriptor_addr);
    pl->set_vqueue.driver_addr = cpu_to_le64(driver_addr);
    pl->set_vqueue.device_addr = cpu_to_le64(device_addr);
}

static inline void virtio_msg_pack_event_driver(VirtIOMSG *msg,
                                                uint32_t index,
                                                uint64_t next_offset,
                                                uint64_t next_wrap)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_DRIVER, 0, 0);

    pl->event_driver.index = cpu_to_le32(index);
    pl->event_driver.next_offset = cpu_to_le64(next_offset);
    pl->event_driver.next_wrap = cpu_to_le64(next_wrap);
}

static inline void virtio_msg_pack_event_device(VirtIOMSG *msg, uint32_t index)
{
    VirtIOMSGPayload *pl = &msg->payload;
    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_DEVICE, 0, 0);

    pl->event_device.index = cpu_to_le32(index);
}

static inline const char *virtio_msg_type_to_str(unsigned int type)
{
#define VIRTIO_MSG_TYPE2STR(x) [ VIRTIO_MSG_ ## x ] = stringify(x)
    static const char *type2str[VIRTIO_MSG_MAX] = {
        VIRTIO_MSG_TYPE2STR(CONNECT),
        VIRTIO_MSG_TYPE2STR(DISCONNECT),
        VIRTIO_MSG_TYPE2STR(DEVICE_INFO),
        VIRTIO_MSG_TYPE2STR(GET_DEVICE_FEAT),
        VIRTIO_MSG_TYPE2STR(SET_DEVICE_FEAT),
        VIRTIO_MSG_TYPE2STR(GET_DEVICE_CONF),
        VIRTIO_MSG_TYPE2STR(SET_DEVICE_CONF),
        VIRTIO_MSG_TYPE2STR(GET_CONF_GEN),
        VIRTIO_MSG_TYPE2STR(EVENT_CONF),
        VIRTIO_MSG_TYPE2STR(GET_DEVICE_STATUS),
        VIRTIO_MSG_TYPE2STR(SET_DEVICE_STATUS),
        VIRTIO_MSG_TYPE2STR(GET_VQUEUE),
        VIRTIO_MSG_TYPE2STR(SET_VQUEUE),
        VIRTIO_MSG_TYPE2STR(RESET_VQUEUE),
        VIRTIO_MSG_TYPE2STR(EVENT_DRIVER),
        VIRTIO_MSG_TYPE2STR(EVENT_DEVICE),
    };

    return type2str[type];
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

static inline void virtio_msg_print(VirtIOMSG *msg, bool resp)
{
    VirtIOMSGPayload *pl = &msg->payload;
    int i;

    assert(msg);
    printf("virtio-msg: type %s 0x%x msg_id 0x%x dev_id 0x%0x\n",
           virtio_msg_type_to_str(msg->type),
           msg->type, msg->msg_id, msg->dev_id);

    for (i = 0; i < 32; i++) {
        printf("%2.2x ", msg->payload.u8[i]);
        if (((i + 1) %  16) == 0) {
            printf("\n");
        }
    }

    switch (msg->type) {
    case VIRTIO_MSG_GET_DEVICE_STATUS:
        if (resp) {
            virtio_msg_print_status(pl->get_device_status_resp.status);
        }
        break;
    case VIRTIO_MSG_SET_DEVICE_STATUS:
        virtio_msg_print_status(pl->set_device_status.status);
        break;
    }
    printf("\n");
}
#endif
