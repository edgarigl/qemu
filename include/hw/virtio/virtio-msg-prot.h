/*
 * Virtio MSG - Message packing/unpacking functions.
 * TODO: Use either packed struct or memcpy (not both).
 * QEMU upstream OK with packed structs?
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
typedef struct VirtIOMSG {
    uint8_t type;
    uint8_t msg_id;
    uint16_t dev_id;
    uint32_t unused;
    uint8_t payload[32];
} QEMU_PACKED VirtIOMSG;

typedef struct VirtIOMSGPayload {
    union {
        uint8_t u8[32];

        struct {
            uint32_t device_version;
            uint32_t device_id;
            uint32_t vendor_id;
        } get_device_info_resp;
        struct {
            uint32_t index;
            uint64_t features;
        } get_device_feat;
        struct {
            uint32_t index;
            uint64_t features;
        } get_device_feat_resp;
        struct {
            uint32_t index;
            uint64_t features;
        } set_device_feat;
        struct {
            uint32_t status;
        } get_device_status_resp;
        struct {
            uint32_t status;
        } set_device_status;
        struct {
            uint32_t size;
            uint32_t offset;
        } get_device_conf;
        struct {
            uint32_t size;
            uint32_t offset;
            uint32_t data;
        } get_device_conf_resp;
        struct {
            uint32_t size;
            uint32_t offset;
            uint32_t data;
        } set_device_conf;
        struct {
            uint32_t generation;
        } get_conf_gen_resp;
        struct {
            uint32_t index;
        } get_vqueue;
        struct {
            uint32_t index;
            uint32_t max_size;
        } get_vqueue_resp;
        struct {
            uint32_t index;
            uint32_t size;
            uint64_t descriptor_addr;
            uint64_t driver_addr;
            uint64_t device_addr;
        } set_vqueue;
        struct {
            uint32_t index;
            uint64_t next_offset;
            uint64_t next_wrap;
        } event_driver;
        struct {
            uint32_t index;
        } event_device;
    };
} QEMU_PACKED VirtIOMSGPayload;

#define GEN_VIRTIO_MSG_UNPACK(W)                                            \
static inline uint ## W ## _t virtio_msg_unpack_u ## W(VirtIOMSG *msg,      \
                                                   unsigned int offset)     \
{                                                                           \
    uint ## W ## _t v;                                                      \
                                                                            \
    assert((offset + sizeof v) <= sizeof msg->payload);                      \
    memcpy(&v, &msg->payload[offset], sizeof v);                            \
    v = le ## W ## _to_cpu(v);                                              \
    return v;                                                               \
}

GEN_VIRTIO_MSG_UNPACK(16);
GEN_VIRTIO_MSG_UNPACK(32);
GEN_VIRTIO_MSG_UNPACK(64);

static inline void virtio_msg_unpack(VirtIOMSG *msg, VirtIOMSGPayload *mp)
{
    switch (msg->type) {
    case VIRTIO_MSG_GET_DEVICE_FEAT:
        mp->get_device_feat.index = virtio_msg_unpack_u32(msg, 0);
        mp->set_device_feat.features = virtio_msg_unpack_u64(msg, 4);
        break;
    case VIRTIO_MSG_SET_DEVICE_FEAT:
        mp->set_device_feat.index = virtio_msg_unpack_u32(msg, 0);
        mp->set_device_feat.features = virtio_msg_unpack_u64(msg, 4);
        break;
    case VIRTIO_MSG_SET_DEVICE_STATUS:
        mp->set_device_status.status = virtio_msg_unpack_u32(msg, 0);
        break;
    case VIRTIO_MSG_GET_DEVICE_CONF:
        mp->get_device_conf.size = virtio_msg_unpack_u32(msg, 0);
        mp->get_device_conf.offset = virtio_msg_unpack_u32(msg, 4);
        break;
    case VIRTIO_MSG_SET_DEVICE_CONF:
        mp->set_device_conf.size = virtio_msg_unpack_u32(msg, 0);
        mp->set_device_conf.offset = virtio_msg_unpack_u32(msg, 4);
        mp->set_device_conf.data = virtio_msg_unpack_u32(msg, 8);
        break;
    case VIRTIO_MSG_GET_VQUEUE:
        mp->get_vqueue.index = virtio_msg_unpack_u32(msg, 0);
        break;
    case VIRTIO_MSG_SET_VQUEUE:
        mp->set_vqueue.index = virtio_msg_unpack_u32(msg, 0);
        mp->set_vqueue.size = virtio_msg_unpack_u32(msg, 4);
        mp->set_vqueue.descriptor_addr = virtio_msg_unpack_u64(msg, 8);
        mp->set_vqueue.driver_addr = virtio_msg_unpack_u64(msg, 16);
        mp->set_vqueue.device_addr = virtio_msg_unpack_u64(msg, 24);
        break;
    case VIRTIO_MSG_EVENT_DRIVER:
        mp->event_driver.index = virtio_msg_unpack_u32(msg, 0);
        mp->event_driver.next_offset = virtio_msg_unpack_u64(msg, 4);
        mp->event_driver.next_wrap = virtio_msg_unpack_u64(msg, 12);
        break;
    case VIRTIO_MSG_EVENT_DEVICE:
        mp->event_device.index = virtio_msg_unpack_u32(msg, 0);
        break;
    default:
        break;
    }
}

static inline void virtio_msg_unpack_resp(VirtIOMSG *msg, VirtIOMSGPayload *mp)
{
    switch (msg->type) {
    case VIRTIO_MSG_DEVICE_INFO:
        mp->get_device_info_resp.device_version = virtio_msg_unpack_u32(msg, 0);
        mp->get_device_info_resp.device_id = virtio_msg_unpack_u32(msg, 4);
        mp->get_device_info_resp.vendor_id = virtio_msg_unpack_u32(msg, 8);
        break;
    case VIRTIO_MSG_GET_DEVICE_FEAT:
        mp->get_device_feat_resp.index = virtio_msg_unpack_u32(msg, 0);
        mp->get_device_feat_resp.features = virtio_msg_unpack_u64(msg, 4);
        break;
    case VIRTIO_MSG_GET_DEVICE_STATUS:
        mp->get_device_status_resp.status = virtio_msg_unpack_u32(msg, 0);
        break;
    case VIRTIO_MSG_GET_DEVICE_CONF:
        mp->get_device_conf_resp.size = virtio_msg_unpack_u32(msg, 0);
        mp->get_device_conf_resp.offset = virtio_msg_unpack_u32(msg, 4);
        mp->get_device_conf_resp.data = virtio_msg_unpack_u32(msg, 8);
        break;
    case VIRTIO_MSG_GET_VQUEUE:
        mp->get_vqueue_resp.index = virtio_msg_unpack_u32(msg, 0);
        mp->get_vqueue_resp.max_size = virtio_msg_unpack_u32(msg, 4);
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
    memset(msg->payload, 0, sizeof msg->payload);
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
    virtio_msg_pack_header(msg, VIRTIO_MSG_DEVICE_INFO, 0, 0);

    dev_version = cpu_to_le32(dev_version);
    dev_id = cpu_to_le32(dev_id);
    vendor_id = cpu_to_le32(vendor_id);
    memcpy(msg->payload, &dev_version, sizeof dev_version);
    memcpy(msg->payload + 4, &dev_id, sizeof dev_id);
    memcpy(msg->payload + 8, &vendor_id, sizeof vendor_id);
}

static inline void virtio_msg_pack_get_device_feat(VirtIOMSG *msg,
                                                   uint32_t index,
                                                   uint64_t f)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_FEAT, 0, 0);

    index = cpu_to_le32(index);
    f = cpu_to_le64(f);
    memcpy(msg->payload, &index, sizeof index);
    memcpy(msg->payload + 4, &f, sizeof f);
}

static inline void virtio_msg_pack_get_device_feat_resp(VirtIOMSG *msg,
                                                   uint32_t index,
                                                   uint64_t f)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_FEAT, 0, 0);

    index = cpu_to_le32(index);
    f = cpu_to_le64(f);
    memcpy(msg->payload, &index, sizeof index);
    memcpy(msg->payload + 4, &f, sizeof f);
}

static inline void virtio_msg_pack_set_device_feat(VirtIOMSG *msg,
                                                   uint32_t index,
                                                   uint64_t f)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_FEAT, 0, 0);

    index = cpu_to_le32(index);
    f = cpu_to_le64(f);
    memcpy(msg->payload, &index, sizeof index);
    memcpy(msg->payload + 4, &f, sizeof f);
}

static inline void virtio_msg_pack_set_device_status(VirtIOMSG *msg,
                                                     uint32_t status)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_STATUS, 0, 0);

    status = cpu_to_le32(status);
    memcpy(msg->payload, &status, sizeof status);
}

static inline void virtio_msg_pack_get_device_status(VirtIOMSG *msg)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_STATUS, 0, 0);
}

static inline void virtio_msg_pack_get_device_status_resp(VirtIOMSG *msg,
                                                          uint32_t status)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_STATUS, 0, 0);

    status = cpu_to_le32(status);
    memcpy(msg->payload, &status, sizeof status);
}

static inline void virtio_msg_pack_get_device_conf(VirtIOMSG *msg,
                                                   uint32_t size,
                                                   uint32_t offset)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_CONF, 0, 0);

    size = cpu_to_le32(size);
    offset = cpu_to_le32(offset);
    memcpy(msg->payload, &size, sizeof size);
    memcpy(msg->payload + 4, &offset, sizeof offset);
}

static inline void virtio_msg_pack_get_device_conf_resp(VirtIOMSG *msg,
                                                        uint32_t size,
                                                        uint32_t offset,
                                                        uint32_t data)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_CONF, 0, 0);

    size = cpu_to_le32(size);
    offset = cpu_to_le32(offset);
    data = cpu_to_le32(data);
    memcpy(msg->payload, &size, sizeof size);
    memcpy(msg->payload + 4, &offset, sizeof offset);
    memcpy(msg->payload + 8, &data, sizeof data);
}

static inline void virtio_msg_pack_set_device_conf(VirtIOMSG *msg,
                                                   uint32_t size,
                                                   uint32_t offset,
                                                   uint32_t data)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_CONF, 0, 0);

    size = cpu_to_le32(size);
    offset = cpu_to_le32(offset);
    data = cpu_to_le32(data);
    memcpy(msg->payload, &size, sizeof size);
    memcpy(msg->payload + 4, &offset, sizeof offset);
    memcpy(msg->payload + 8, &data, sizeof data);
}

static inline void virtio_msg_pack_get_vqueue(VirtIOMSG *msg,
                                              uint32_t index)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_VQUEUE, 0, 0);

    index = cpu_to_le32(index);
    memcpy(msg->payload, &index, sizeof index);
}

static inline void virtio_msg_pack_get_vqueue_resp(VirtIOMSG *msg,
                                                   uint32_t index,
                                                   uint32_t max_size)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_VQUEUE, 0, 0);

    index = cpu_to_le32(index);
    max_size = cpu_to_le32(max_size);
    memcpy(msg->payload, &index, sizeof index);
    memcpy(msg->payload + 4, &max_size, sizeof max_size);
}

static inline void virtio_msg_pack_set_vqueue(VirtIOMSG *msg,
                                              uint32_t index,
                                              uint32_t size,
                                              uint64_t descriptor_addr,
                                              uint64_t driver_addr,
                                              uint64_t device_addr)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_VQUEUE, 0, 0);

    index = cpu_to_le32(index);
    size = cpu_to_le32(size);
    descriptor_addr = cpu_to_le64(descriptor_addr);
    driver_addr = cpu_to_le64(driver_addr);
    device_addr = cpu_to_le64(device_addr);
    memcpy(msg->payload, &index, sizeof index);
    memcpy(msg->payload + 4, &size, sizeof size);
    memcpy(msg->payload + 8, &descriptor_addr, sizeof descriptor_addr);
    memcpy(msg->payload + 16, &driver_addr, sizeof driver_addr);
    memcpy(msg->payload + 24, &device_addr, sizeof device_addr);
}

static inline void virtio_msg_pack_event_driver(VirtIOMSG *msg,
                                                uint32_t index,
                                                uint64_t next_offset,
                                                uint64_t next_wrap)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_DRIVER, 0, 0);

    index = cpu_to_le32(index);
    next_offset = cpu_to_le64(next_offset);
    next_wrap = cpu_to_le64(next_wrap);
    memcpy(msg->payload, &index, sizeof index);
    memcpy(msg->payload + 4, &next_offset, sizeof next_offset);
    memcpy(msg->payload + 12, &next_wrap, sizeof next_wrap);
}

static inline void virtio_msg_pack_event_device(VirtIOMSG *msg, uint32_t index)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_DEVICE, 0, 0);

    index = cpu_to_le32(index);
    memcpy(msg->payload, &index, sizeof index);
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
    VirtIOMSGPayload mp = {0};
    int i;

    assert(msg);
    printf("virtio-msg: type %s 0x%x msg_id 0x%x dev_id 0x%0x\n",
           virtio_msg_type_to_str(msg->type),
           msg->type, msg->msg_id, msg->dev_id);

    for (i = 0; i < 32; i++) {
        printf("%2.2x ", msg->payload[i]);
        if (((i + 1) %  16) == 0) {
            printf("\n");
        }
    }

    if (resp) {
        virtio_msg_unpack(msg, &mp);
    } else {
        virtio_msg_unpack_resp(msg, &mp);
    }

    switch (msg->type) {
    case VIRTIO_MSG_GET_DEVICE_STATUS:
        if (resp) {
            virtio_msg_print_status(mp.get_device_status_resp.status);
        }
        break;
    case VIRTIO_MSG_SET_DEVICE_STATUS:
        virtio_msg_print_status(mp.set_device_status.status);
        break;
    }
    printf("\n");
}


#endif
