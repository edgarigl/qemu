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
struct VirtIOMedia {
    VirtIODevice parent_obj;

    VirtQueue *command_vq;
    VirtQueue *event_vq;

    VirtIOMediaConfig config;
    MemoryRegion hostmem;

    uint64_t hostmem_size;
    uint32_t max_buffers;
    bool use_hostmem;

    uint32_t session_next_id;
    GHashTable *sessions;

    QTAILQ_HEAD(, VirtIOMediaEvent) pending_events;
};

#endif /* HW_VIRTIO_MEDIA_H */
