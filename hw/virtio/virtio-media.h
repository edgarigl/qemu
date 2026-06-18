/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_VIRTIO_MEDIA_H
#define HW_VIRTIO_MEDIA_H

#include "hw/virtio/virtio.h"
#include "system/memory.h"
#include "qemu/queue.h"

typedef struct _GHashTable GHashTable;

#define TYPE_VIRTIO_MEDIA "virtio-media-device"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMedia, VIRTIO_MEDIA)

typedef struct VirtIOMediaConfig VirtIOMediaConfig;
struct VirtIOMediaConfig {
    uint32_t device_caps;
    uint32_t device_type;
    uint8_t card[32];
};

typedef struct VirtIOMedia VirtIOMedia;
typedef struct VirtIOMediaEvent VirtIOMediaEvent;
typedef struct VirtIOMediaSession VirtIOMediaSession;
struct VirtIOMedia {
    VirtIODevice parent_obj;

    VirtQueue *command_vq;
    VirtQueue *event_vq;

    VirtIOMediaConfig config;
    MemoryRegion hostmem;
    uint8_t *hostmem_buf;

    uint64_t hostmem_size;
    uint32_t max_buffers;
    bool use_hostmem;
    char *host_device;
    char *host_v4l2_mem;
    bool use_host_device;

    uint32_t session_next_id;
    GHashTable *sessions;
    /*
     * Session that currently owns the capture queue (holds buffers via REQBUFS
     * count>0). 0 = unowned. A second handle's REQBUFS while owned returns
     * EBUSY, matching V4L2 single-owner queue semantics.
     */
    uint32_t capture_owner_session_id;

    QTAILQ_HEAD(, VirtIOMediaEvent) pending_events;
    uint32_t pending_events_count;
};

#endif /* HW_VIRTIO_MEDIA_H */
