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

#ifdef __XEN__
/* Xen compat */
#include <xen/lib.h>
#include <xen/ctype.h>
#include <xen/stringify.h>
#include <xen/bug.h>
#include <xen/virtio/std/virtio_config.h>
#include <xen/byteorder.h>
#define assert ASSERT
#define QEMU_PACKED __packed
#define g_assert_not_reached ASSERT_UNREACHABLE
#define stringify __stringify
#define printf printk
#else
#include <stdint.h>
#include "standard-headers/linux/virtio_config.h"
#endif

/* v0.0.1.  */
#define VIRTIO_MSG_DEVICE_VERSION 0x000001
#define VIRTIO_MSG_VENDOR_ID 0x554D4551 /* 'QEMU' */

enum {
    VIRTIO_MSG_NO_ERROR = 0,
    VIRTIO_MSG_ERROR_UNSUPPORTED_MESSAGE_ID = 1,
    VIRTIO_MSG_ERROR_MEMORY = 2, /* General memory error. */
};

enum {
    VIRTIO_MSG_DEVICE_INFO       = 0x02,
    VIRTIO_MSG_GET_FEATURES      = 0x03,
    VIRTIO_MSG_SET_FEATURES      = 0x04,
    VIRTIO_MSG_GET_CONFIG        = 0x05,
    VIRTIO_MSG_SET_CONFIG        = 0x06,
    VIRTIO_MSG_GET_DEVICE_STATUS = 0x07,
    VIRTIO_MSG_SET_DEVICE_STATUS = 0x08,
    VIRTIO_MSG_GET_VQUEUE        = 0x09,
    VIRTIO_MSG_SET_VQUEUE        = 0x0a,
    VIRTIO_MSG_RESET_VQUEUE      = 0x0b,
    VIRTIO_MSG_EVENT_CONFIG      = 0x40,
    VIRTIO_MSG_EVENT_AVAIL       = 0x41,
    VIRTIO_MSG_EVENT_USED        = 0x42,

    /* Experimental. For setups without IOMMU's, e.g ivshmem */
    VIRTIO_MSG_IOMMU_ENABLE      = 0x80,
    VIRTIO_MSG_IOMMU_TRANSLATE   = 0x81,
    VIRTIO_MSG_IOMMU_INVALIDATE  = 0x82,

    VIRTIO_MSG_MAX = VIRTIO_MSG_IOMMU_INVALIDATE,
};

#define VIRTIO_MSG_MAX_SIZE 44

#define VIRTIO_MSG_TYPE_RESPONSE  (1 << 0)
#define VIRTIO_MSG_TYPE_BUS       (1 << 1)

typedef struct VirtIOMSG {
    uint8_t type;
    uint8_t msg_id;
    uint16_t dev_num;
    uint16_t msg_size;

    union {
        uint8_t payload_u8[38];

        struct {
            uint32_t device_id;
            uint32_t vendor_id;
            uint32_t num_feature_bits;
            uint32_t config_size;
            uint32_t max_vqs;
            uint16_t admin_vq_idx;
            uint16_t admin_vq_count;
        } QEMU_PACKED get_device_info_resp;
        struct {
            uint32_t index;
            uint32_t num;
        } QEMU_PACKED get_features;
        struct {
            uint32_t index;
            uint32_t num;
            uint64_t features;
        } QEMU_PACKED get_features_resp;
        struct {
            uint32_t index;
            uint32_t num;
            uint64_t features;
        } QEMU_PACKED set_features;
        struct {
            uint32_t index;
            uint32_t num;
            uint64_t features;
        } QEMU_PACKED set_features_resp;
        struct {
            uint32_t offset;
            uint32_t size;
        } QEMU_PACKED get_config;
        struct {
            uint32_t generation;
            uint32_t offset;
            uint32_t size;
            uint64_t data;
        } QEMU_PACKED get_config_resp;
        struct {
            uint32_t generation;
            uint32_t offset;
            uint32_t size;
            uint64_t data;
        } QEMU_PACKED set_config;
        struct {
            uint32_t generation;
            uint32_t offset;
            uint32_t size;
            uint64_t data;
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
            uint32_t size;
            uint64_t descriptor_addr;
            uint64_t driver_addr;
            uint64_t device_addr;
        } QEMU_PACKED get_vqueue_resp;
        struct {
            uint32_t index;
            uint32_t unused;
            uint32_t size;
            uint64_t descriptor_addr;
            uint64_t driver_addr;
            uint64_t device_addr;
        } QEMU_PACKED set_vqueue;
        struct {
            uint32_t index;
            uint32_t unused;
            uint32_t size;
            uint64_t descriptor_addr;
            uint64_t driver_addr;
            uint64_t device_addr;
        } QEMU_PACKED set_vqueue_resp;
        struct {
            uint32_t index;
        } QEMU_PACKED reset_vqueue;
        struct {
            uint32_t status;
            uint32_t generation;
            uint32_t offset;
            uint32_t size;
            uint8_t config_value[16];
        } QEMU_PACKED event_config;
        struct {
            uint32_t index;
            uint32_t next_offset_wrap;
        } QEMU_PACKED event_avail;
        struct {
            uint32_t index;
        } QEMU_PACKED event_used;

        /* Xen bus.  */
        struct {
            uint32_t event_channel_port;
        } QEMU_PACKED connect_bus_xen;

        /* Experimental Soft IOMMU.  */
        struct {
            uint8_t enable;
        } QEMU_PACKED iommu_enable;

        struct {
#define VIRTIO_MSG_IOMMU_PAGE_SIZE (4 * 1024)
#define VIRTIO_MSG_IOMMU_PAGE_MASK (VIRTIO_MSG_IOMMU_PAGE_SIZE - 1)
            uint64_t va;
#define VIRTIO_MSG_IOMMU_PROT_READ  (1U << 0)
#define VIRTIO_MSG_IOMMU_PROT_WRITE (1U << 1)
            uint8_t prot;
        } QEMU_PACKED iommu_translate;
        struct {
            uint64_t va;
            uint64_t pa;
            uint8_t prot;
        } QEMU_PACKED iommu_translate_resp;
    };
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
 * virtio_msg_unpack_resp: Unpacks a wire virtio message responses into
 *                         a host version
 * @msg: the virtio message to unpack
 *
 * See virtio_msg_unpack().
 */
static inline void virtio_msg_unpack_resp(VirtIOMSG *msg)
{
    LE_TO_CPU(msg->dev_num);

    switch (msg->msg_id) {
    case VIRTIO_MSG_DEVICE_INFO:
        LE_TO_CPU(msg->get_device_info_resp.device_id);
        LE_TO_CPU(msg->get_device_info_resp.vendor_id);
        LE_TO_CPU(msg->get_device_info_resp.num_feature_bits);
        LE_TO_CPU(msg->get_device_info_resp.config_size);
        LE_TO_CPU(msg->get_device_info_resp.max_vqs);
        LE_TO_CPU(msg->get_device_info_resp.admin_vq_idx);
        LE_TO_CPU(msg->get_device_info_resp.admin_vq_count);
        break;
    case VIRTIO_MSG_GET_FEATURES:
        LE_TO_CPU(msg->get_features_resp.index);
        LE_TO_CPU(msg->get_features_resp.num);
        LE_TO_CPU(msg->get_features_resp.features);
        break;
    case VIRTIO_MSG_SET_FEATURES:
        LE_TO_CPU(msg->set_features_resp.index);
        LE_TO_CPU(msg->set_features_resp.num);
        LE_TO_CPU(msg->set_features_resp.features);
        break;
    case VIRTIO_MSG_GET_DEVICE_STATUS:
        LE_TO_CPU(msg->get_device_status_resp.status);
        break;
    case VIRTIO_MSG_GET_CONFIG:
        LE_TO_CPU(msg->get_config_resp.offset);
        LE_TO_CPU(msg->get_config_resp.data);
        break;
    case VIRTIO_MSG_SET_CONFIG:
        LE_TO_CPU(msg->set_config_resp.offset);
        LE_TO_CPU(msg->set_config_resp.data);
        break;
    case VIRTIO_MSG_GET_VQUEUE:
        LE_TO_CPU(msg->get_vqueue_resp.index);
        LE_TO_CPU(msg->get_vqueue_resp.max_size);
        break;
    case VIRTIO_MSG_IOMMU_TRANSLATE:
        LE_TO_CPU(msg->iommu_translate_resp.va);
        LE_TO_CPU(msg->iommu_translate_resp.pa);
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
static inline void virtio_msg_unpack(VirtIOMSG *msg) {
    if (msg->type & VIRTIO_MSG_TYPE_RESPONSE) {
        virtio_msg_unpack_resp(msg);
        return;
    }

    LE_TO_CPU(msg->dev_num);

    switch (msg->msg_id) {
    case VIRTIO_MSG_GET_FEATURES:
        LE_TO_CPU(msg->get_features.index);
        break;
    case VIRTIO_MSG_SET_FEATURES:
        LE_TO_CPU(msg->set_features.index);
        LE_TO_CPU(msg->set_features.features);
        break;
    case VIRTIO_MSG_SET_DEVICE_STATUS:
        LE_TO_CPU(msg->set_device_status.status);
        break;
    case VIRTIO_MSG_GET_CONFIG:
        LE_TO_CPU(msg->get_config.offset);
        break;
    case VIRTIO_MSG_SET_CONFIG:
        LE_TO_CPU(msg->set_config.offset);
        LE_TO_CPU(msg->set_config.data);
        break;
    case VIRTIO_MSG_GET_VQUEUE:
        LE_TO_CPU(msg->get_vqueue.index);
        break;
    case VIRTIO_MSG_SET_VQUEUE:
        LE_TO_CPU(msg->set_vqueue.index);
        LE_TO_CPU(msg->set_vqueue.size);
        LE_TO_CPU(msg->set_vqueue.descriptor_addr);
        LE_TO_CPU(msg->set_vqueue.driver_addr);
        LE_TO_CPU(msg->set_vqueue.device_addr);
        break;
    case VIRTIO_MSG_RESET_VQUEUE:
        LE_TO_CPU(msg->reset_vqueue.index);
        break;
    case VIRTIO_MSG_EVENT_CONFIG:
        LE_TO_CPU(msg->event_config.status);
        LE_TO_CPU(msg->event_config.offset);
        break;
    case VIRTIO_MSG_EVENT_AVAIL:
        LE_TO_CPU(msg->event_avail.index);
        LE_TO_CPU(msg->event_avail.next_offset_wrap);
        break;
    case VIRTIO_MSG_EVENT_USED:
        LE_TO_CPU(msg->event_used.index);
        break;
    case VIRTIO_MSG_IOMMU_TRANSLATE:
        LE_TO_CPU(msg->iommu_translate.va);
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
                                          uint16_t payload_size)
{
    uint16_t msg_size = virtio_msg_header_size() + payload_size;

    msg->type = type;
    msg->msg_id = msg_id;
    msg->dev_num = cpu_to_le16(dev_num);
    msg->msg_size = cpu_to_le16(msg_size);

    /* Keep things predictable.  */
    memset(msg->payload_u8, 0, sizeof msg->payload_u8);
}

static inline void virtio_msg_pack_get_device_info(VirtIOMSG *msg)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_DEVICE_INFO, 0, 0, 0);
}

static inline void virtio_msg_pack_get_device_info_resp(VirtIOMSG *msg,
                                                   uint32_t dev_num,
                                                   uint32_t vendor_id,
                                                   uint32_t num_feature_bits,
                                                   uint32_t config_size,
                                                   uint32_t max_vqs,
                                                   uint16_t admin_vq_idx,
                                                   uint16_t admin_vq_count)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_DEVICE_INFO,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->get_device_info_resp);

    msg->get_device_info_resp.device_id = cpu_to_le32(dev_num);
    msg->get_device_info_resp.vendor_id = cpu_to_le32(vendor_id);
    msg->get_device_info_resp.num_feature_bits = cpu_to_le32(num_feature_bits);
    msg->get_device_info_resp.config_size = cpu_to_le32(config_size);
    msg->get_device_info_resp.max_vqs = cpu_to_le32(max_vqs);
    msg->get_device_info_resp.admin_vq_idx = cpu_to_le16(admin_vq_idx);
    msg->get_device_info_resp.admin_vq_count = cpu_to_le16(admin_vq_count);
}

static inline void virtio_msg_pack_get_features(VirtIOMSG *msg,
                                                uint32_t index,
                                                uint32_t num)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_FEATURES, 0, 0,
                           sizeof msg->get_features);

    msg->get_features.index = cpu_to_le32(index);
    msg->get_features.num = cpu_to_le32(num);
}

static inline void virtio_msg_pack_get_features_resp(VirtIOMSG *msg,
                                                     uint32_t index,
                                                     uint32_t num,
                                                     uint64_t f)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_FEATURES,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->get_features_resp);

    msg->get_features_resp.index = cpu_to_le32(index);
    msg->get_features_resp.num = cpu_to_le32(num);
    msg->get_features_resp.features = cpu_to_le64(f);
}

static inline void virtio_msg_pack_set_features(VirtIOMSG *msg,
                                                uint32_t index,
                                                uint32_t num,
                                                uint64_t f)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_FEATURES, 0, 0,
                           sizeof msg->set_features);

    msg->set_features.index = cpu_to_le32(index);
    msg->set_features.num = cpu_to_le32(num);
    msg->set_features.features = cpu_to_le64(f);
}

static inline void virtio_msg_pack_set_features_resp(VirtIOMSG *msg,
                                                     uint32_t index,
                                                     uint32_t num,
                                                     uint64_t f)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_FEATURES,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->set_features_resp);

    msg->set_features_resp.index = cpu_to_le32(index);
    msg->set_features_resp.num = cpu_to_le32(num);
    msg->set_features_resp.features = cpu_to_le64(f);
}

static inline void virtio_msg_pack_set_device_status(VirtIOMSG *msg,
                                                     uint32_t status)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_STATUS, 0, 0,
                           sizeof msg->set_device_status);

    msg->set_device_status.status = cpu_to_le32(status);
}

static inline void virtio_msg_pack_set_device_status_resp(VirtIOMSG *msg,
                                                          uint32_t status)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_DEVICE_STATUS,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->set_device_status_resp);

    msg->set_device_status_resp.status = cpu_to_le32(status);
}

static inline void virtio_msg_pack_get_device_status(VirtIOMSG *msg)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_STATUS, 0, 0, 0);
}

static inline void virtio_msg_pack_get_device_status_resp(VirtIOMSG *msg,
                                                          uint32_t status)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_DEVICE_STATUS,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->get_device_status_resp);

    msg->get_device_status_resp.status = cpu_to_le32(status);
}

static inline void virtio_msg_pack_get_config(VirtIOMSG *msg,
                                              uint32_t size,
                                              uint32_t offset)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_CONFIG, 0, 0,
                           sizeof msg->get_config);

    msg->get_config.offset = cpu_to_le32(offset);
    msg->get_config.size = cpu_to_le32(size);
}

static inline void virtio_msg_pack_get_config_resp(VirtIOMSG *msg,
                                                        uint32_t size,
                                                        uint32_t offset,
                                                        uint32_t generation,
                                                        uint64_t data)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_CONFIG,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->get_config_resp);

    msg->get_config_resp.offset = cpu_to_le32(offset);
    msg->get_config_resp.size = cpu_to_le32(size);
    msg->get_config_resp.generation = cpu_to_le32(generation);
    msg->get_config_resp.data = cpu_to_le64(data);
}

static inline void virtio_msg_pack_set_config(VirtIOMSG *msg,
                                              uint32_t size,
                                              uint32_t offset,
                                              uint32_t generation,
                                              uint64_t data)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_CONFIG, 0, 0,
                           sizeof msg->set_config);

    msg->set_config.offset = cpu_to_le32(offset);
    msg->set_config.size = cpu_to_le32(size);
    msg->set_config.generation = cpu_to_le32(generation);
    msg->set_config.data = cpu_to_le64(data);
}

static inline void virtio_msg_pack_set_config_resp(VirtIOMSG *msg,
                                                   uint32_t size,
                                                   uint32_t offset,
                                                   uint32_t generation,
                                                   uint64_t data)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_CONFIG,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->set_config_resp);

    msg->set_config_resp.offset = cpu_to_le32(offset);
    msg->set_config_resp.size = cpu_to_le32(size);
    msg->set_config_resp.generation = cpu_to_le32(generation);
    msg->set_config_resp.data = cpu_to_le64(data);
}

static inline void virtio_msg_pack_get_vqueue(VirtIOMSG *msg,
                                              uint32_t index)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_VQUEUE, 0, 0,
                           sizeof msg->get_vqueue);

    msg->get_vqueue.index = cpu_to_le32(index);
}

static inline void virtio_msg_pack_get_vqueue_resp(VirtIOMSG *msg,
                                                   uint32_t index,
                                                   uint32_t max_size,
                                                   uint32_t size,
                                                   uint64_t descriptor_addr,
                                                   uint64_t driver_addr,
                                                   uint64_t device_addr)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_GET_VQUEUE,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->get_vqueue_resp);

    msg->get_vqueue_resp.index = cpu_to_le32(index);
    msg->get_vqueue_resp.max_size = cpu_to_le32(max_size);
    msg->get_vqueue_resp.size = cpu_to_le32(size);
    msg->get_vqueue_resp.descriptor_addr = cpu_to_le64(descriptor_addr);
    msg->get_vqueue_resp.driver_addr = cpu_to_le64(driver_addr);
    msg->get_vqueue_resp.device_addr = cpu_to_le64(device_addr);
}

static inline void virtio_msg_pack_reset_vqueue(VirtIOMSG *msg, uint32_t index)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_RESET_VQUEUE, 0, 0,
                           sizeof msg->reset_vqueue);

    msg->reset_vqueue.index = cpu_to_le32(index);
}

static inline void virtio_msg_pack_reset_vqueue_resp(VirtIOMSG *msg)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_RESET_VQUEUE,
                           VIRTIO_MSG_TYPE_RESPONSE, 0, 0);
}

static inline void virtio_msg_pack_set_vqueue(VirtIOMSG *msg,
                                              uint32_t index,
                                              uint32_t size,
                                              uint64_t descriptor_addr,
                                              uint64_t driver_addr,
                                              uint64_t device_addr)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_VQUEUE, 0, 0,
                           sizeof msg->set_vqueue);

    msg->set_vqueue.index = cpu_to_le32(index);
    msg->set_vqueue.unused = 0;
    msg->set_vqueue.size = cpu_to_le32(size);
    msg->set_vqueue.descriptor_addr = cpu_to_le64(descriptor_addr);
    msg->set_vqueue.driver_addr = cpu_to_le64(driver_addr);
    msg->set_vqueue.device_addr = cpu_to_le64(device_addr);
}

static inline void virtio_msg_pack_set_vqueue_resp(VirtIOMSG *msg,
                                                   uint32_t index,
                                                   uint32_t size,
                                                   uint64_t descriptor_addr,
                                                   uint64_t driver_addr,
                                                   uint64_t device_addr)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_SET_VQUEUE,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->set_vqueue_resp);

    msg->set_vqueue_resp.index = cpu_to_le32(index);
    msg->set_vqueue_resp.unused = 0;
    msg->set_vqueue_resp.size = cpu_to_le32(size);
    msg->set_vqueue_resp.descriptor_addr = cpu_to_le64(descriptor_addr);
    msg->set_vqueue_resp.driver_addr = cpu_to_le64(driver_addr);
    msg->set_vqueue_resp.device_addr = cpu_to_le64(device_addr);
}

static inline void virtio_msg_pack_event_avail(VirtIOMSG *msg,
                                               uint32_t index,
                                               uint32_t next_offset,
                                               bool next_wrap)
{
    uint32_t next_ow;

    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_AVAIL, 0, 0,
                           sizeof msg->event_avail);

    /* next_offset is 31b wide.  */
    assert((next_offset & 0x80000000U) == 0);

    /* Pack the next_offset_wrap field. */
    next_ow = next_wrap << 31;
    next_ow |= next_offset;

    msg->event_avail.index = cpu_to_le32(index);
    msg->event_avail.next_offset_wrap = cpu_to_le32(next_ow);
}

static inline void virtio_msg_pack_event_used(VirtIOMSG *msg, uint32_t index)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_USED, 0, 0,
                           sizeof msg->event_used);

    msg->event_used.index = cpu_to_le32(index);
}

static inline void virtio_msg_pack_event_config(VirtIOMSG *msg,
                                                uint32_t status,
                                                uint32_t generation,
                                                uint32_t offset,
                                                uint32_t size,
                                                uint8_t *value)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_EVENT_CONFIG, 0, 0,
                           sizeof msg->event_config);

    msg->event_config.status = cpu_to_le32(status);
    msg->event_config.generation = cpu_to_le32(generation);
    msg->event_config.offset = cpu_to_le32(offset);
    msg->event_config.size = cpu_to_le32(size);

    assert(size <= ARRAY_SIZE(msg->event_config.config_value));
    if (size > 0) {
        memcpy(&msg->event_config.config_value[0], value, size);
    }
}

static inline void virtio_msg_pack_iommu_enable(VirtIOMSG *msg,
                                                bool enable)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_IOMMU_ENABLE, 0, 0,
                           sizeof msg->iommu_enable);

    msg->iommu_enable.enable = enable;
}

static inline void virtio_msg_pack_iommu_translate(VirtIOMSG *msg,
                                                   uint64_t va,
                                                   uint8_t prot)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_IOMMU_TRANSLATE, 0, 0,
                           sizeof msg->iommu_translate);

    msg->iommu_translate.va = cpu_to_le64(va);
    msg->iommu_translate.prot = prot;
}

static inline void virtio_msg_pack_iommu_translate_resp(VirtIOMSG *msg,
                                                        uint64_t va,
                                                        uint64_t pa,
                                                        uint8_t prot)
{
    virtio_msg_pack_header(msg, VIRTIO_MSG_IOMMU_TRANSLATE,
                           VIRTIO_MSG_TYPE_RESPONSE, 0,
                           sizeof msg->iommu_translate_resp);

    msg->iommu_translate_resp.va = cpu_to_le64(va);
    msg->iommu_translate_resp.pa = cpu_to_le64(pa);
    msg->iommu_translate_resp.prot = prot;
}

/*
 * Return true if msg_resp is a response for msg_req.
 */
static inline bool virtio_msg_is_resp(VirtIOMSG *msg_req, VirtIOMSG *msg_resp)
{
    if (msg_resp->msg_id == msg_req->msg_id &&
        msg_resp->type & VIRTIO_MSG_TYPE_RESPONSE) {
        return true;
    }
    return false;
}

static inline const char *virtio_msg_id_to_str(unsigned int type)
{
#define VIRTIO_MSG_TYPE2STR(x) [ VIRTIO_MSG_ ## x ] = stringify(x)
    static const char *type2str[VIRTIO_MSG_MAX + 1] = {
        VIRTIO_MSG_TYPE2STR(DEVICE_INFO),
        VIRTIO_MSG_TYPE2STR(GET_FEATURES),
        VIRTIO_MSG_TYPE2STR(SET_FEATURES),
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
        VIRTIO_MSG_TYPE2STR(IOMMU_TRANSLATE),
        VIRTIO_MSG_TYPE2STR(IOMMU_INVALIDATE),
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

static inline void virtio_msg_print(VirtIOMSG *msg)
{
    bool resp = msg->type & VIRTIO_MSG_TYPE_RESPONSE;
    size_t payload_size;
    int i;

    assert(msg);
    printf("virtio-msg: id %s 0x%x type 0x%x dev_num 0x%x msg_size 0x%x\n",
           virtio_msg_id_to_str(msg->msg_id), msg->msg_id,
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
        printf("set-vqueue: index=%d size=%d desc-addr=%lx driver-addr=%lx device-addr=%lx\n",
                msg->set_vqueue.index, msg->set_vqueue.size,
                msg->set_vqueue.descriptor_addr,
                msg->set_vqueue.driver_addr,
                msg->set_vqueue.device_addr);
        break;
    }
    printf("\n");
}

#ifdef __XEN__
#undef printf
#undef assert
#undef QEMU_PACKED
#undef g_assert_not_reached
#undef stringify
#endif

#endif
