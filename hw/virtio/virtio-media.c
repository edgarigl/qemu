/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Virtio media device (simple capture backend)
 *
 * This implements a minimal virtio-media backend that exposes a synthetic
 * V4L2 capture device using MMAP buffers and an event queue for DQBUF.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/host-utils.h"
#include "qemu/iov.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/memalign.h"
#include "qemu/module.h"
#include "qemu/queue.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-media.h"
#include "hw/xen/xen.h"
#include "standard-headers/linux/virtio_ids.h"
#include "system/xen.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <linux/ioctl.h>
#include <linux/videodev2.h>
#include "hw/virtio/virtio-dmabuf.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <xen/gntalloc.h>

/*
 * gntdev dma-buf import ABI (from xen/gntdev.h). Defined locally because the
 * system header pulls in Xen public types (grant_ref_t, domid_t) that are not
 * available in the QEMU build include path.
 */
struct vmedia_gntdev_dmabuf_imp_to_refs {
    uint32_t fd;
    uint32_t count;
    uint32_t domid;
    uint32_t reserved;
    uint32_t refs[1];
};
struct vmedia_gntdev_dmabuf_imp_release {
    uint32_t fd;
    uint32_t reserved;
};
#define VMEDIA_IOCTL_GNTDEV_DMABUF_IMP_TO_REFS \
    _IOC(_IOC_NONE, 'G', 11, sizeof(struct vmedia_gntdev_dmabuf_imp_to_refs))
#define VMEDIA_IOCTL_GNTDEV_DMABUF_IMP_RELEASE \
    _IOC(_IOC_NONE, 'G', 12, sizeof(struct vmedia_gntdev_dmabuf_imp_release))

/*
 * dma-heap ABI (from linux/dma-heap.h). Defined locally to match the
 * gntdev-struct convention above and avoid UAPI header dependencies.
 */
struct vmedia_dma_heap_allocation_data {
    uint64_t len;
    uint32_t fd;
    uint32_t fd_flags;
    uint64_t heap_flags;
};
#define VMEDIA_DMA_HEAP_IOCTL_ALLOC \
    _IOWR('H', 0x0, struct vmedia_dma_heap_allocation_data)

#define VIRTIO_MEDIA_COMMAND_VQ 0
#define VIRTIO_MEDIA_EVENT_VQ   1
#define VIRTIO_MEDIA_NUM_VQS    2
#define VIRTIO_MEDIA_VQ_SIZE    128

#define VIRTIO_MEDIA_CARD_NAME "virtio-media"

#define VIRTIO_MEDIA_CMD_OPEN   1
#define VIRTIO_MEDIA_CMD_CLOSE  2
#define VIRTIO_MEDIA_CMD_IOCTL  3
#define VIRTIO_MEDIA_CMD_MMAP   4
#define VIRTIO_MEDIA_CMD_MUNMAP 5
#define VIRTIO_MEDIA_CMD_EXPORT_BUFFER 6
#define VIRTIO_MEDIA_CMD_IMPORT_BUFFER 7
#define VIRTIO_MEDIA_CMD_RELEASE_HANDLE 8
#define VIRTIO_MEDIA_CMD_REGISTER_BUFFER 9

#define VIRTIO_MEDIA_EVT_ERROR  0
#define VIRTIO_MEDIA_EVT_DQBUF  1
#define VIRTIO_MEDIA_EVT_EVENT  2

#define VIRTIO_MEDIA_MMAP_FLAG_RW (1 << 0)

#define VIRTIO_MEDIA_MAX_PLANES VIDEO_MAX_PLANES

/* Caps on guest-supplied ext-control counts/sizes to bound host allocation. */
#define VIRTIO_MEDIA_MAX_EXT_CTRLS 1024
#define VIRTIO_MEDIA_MAX_EXT_CTRL_SIZE (1u << 20)

/* Bound the pending event backlog when the guest stops posting buffers. */
#define VIRTIO_MEDIA_MAX_PENDING_EVENTS 256

#define VIRTIO_MEDIA_F_GNTREF 63
#define VIRTIO_MEDIA_F_EXPORT_IMPORT 62
#define VIRTIO_MEDIA_F_SHARE_FENCE 61
#define VIRTIO_MEDIA_F_PEER_GREF_IMPORT 60
#define VIRTIO_MEDIA_F_IMPORT_BUFFER 59
#define VIRTIO_MEDIA_GREF_PAGE_SIZE 4096u

#define VIRTIO_MEDIA_IMPORT_F_TARGET_DOMID (1U << 1)
#define VIRTIO_MEDIA_IMPORT_DOMID_SHIFT 16
#define VIRTIO_MEDIA_IMPORT_DOMID_MASK 0xffffU

#define VIRTIO_MEDIA_WIDTH  640u
#define VIRTIO_MEDIA_HEIGHT 480u
#define VIRTIO_MEDIA_PIXFMT_MPLANE V4L2_PIX_FMT_YUV420
#define VIRTIO_MEDIA_PIXFMT_SINGLE V4L2_PIX_FMT_YUYV
#define VIRTIO_MEDIA_BUFFER_SIZE_MPLANE \
    (VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT * 3 / 2)
#define VIRTIO_MEDIA_BUFFER_SIZE_SINGLE \
    (VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT * 2)

typedef enum VirtIOMediaHostV4L2MemMode {
    VMEDIA_HOST_V4L2_MEM_AUTO = 0,
    VMEDIA_HOST_V4L2_MEM_MMAP,
    VMEDIA_HOST_V4L2_MEM_USERPTR,
    /* Mode A: host MMAP + EXPBUF + gntdev re-grant */
    VMEDIA_HOST_V4L2_MEM_REGRANT,
    /* Import: dma-heap host dmabuf + downstream DMABUF + gntdev re-grant */
    VMEDIA_HOST_V4L2_MEM_IMPORT,
    /* Import-UUID: guest virtio-gpu blob (UUID) resolved to a host dmabuf */
    VMEDIA_HOST_V4L2_MEM_IMPORT_UUID,
} VirtIOMediaHostV4L2MemMode;

static int vmedia_ioctl_nointr(int fd, unsigned long req, void *arg);

static uint8_t *vmedia_hostmem_base(VirtIOMedia *s)
{
    assert(s->host_v4l2_mem_mode != VMEDIA_HOST_V4L2_MEM_MMAP);
    assert(s->hostmem_buf);
    return s->hostmem_buf;
}

static uint64_t vmedia_format_sizeimage(const struct v4l2_format *fmt)
{
    uint64_t sizeimage;

    switch (fmt->type) {
    case V4L2_BUF_TYPE_VIDEO_CAPTURE:
        if (fmt->fmt.pix.sizeimage) {
            return fmt->fmt.pix.sizeimage;
        }
        return (uint64_t)fmt->fmt.pix.width * fmt->fmt.pix.height * 2;
    case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
        sizeimage = 0;
        for (uint32_t i = 0; i < fmt->fmt.pix_mp.num_planes; i++) {
            sizeimage += fmt->fmt.pix_mp.plane_fmt[i].sizeimage;
        }
        if (sizeimage) {
            return sizeimage;
        }
        return (uint64_t)fmt->fmt.pix_mp.width * fmt->fmt.pix_mp.height * 2;
    default:
        return 0;
    }
}

static void vmedia_gntalloc_cleanup(VirtIOMedia *s)
{
    if (s->hostmem_buf && s->hostmem_buf != MAP_FAILED) {
        munmap(s->hostmem_buf, s->hostmem_size);
        s->hostmem_buf = NULL;
    }

    if (s->gntalloc_fd >= 0 && s->gref_count) {
        struct ioctl_gntalloc_dealloc_gref dealloc = {
            .index = s->gntalloc_index,
            .count = s->gref_count,
        };

        ioctl(s->gntalloc_fd, IOCTL_GNTALLOC_DEALLOC_GREF, &dealloc);
    }

    if (s->gntalloc_fd >= 0) {
        close(s->gntalloc_fd);
        s->gntalloc_fd = -1;
    }

    g_free(s->grefs);
    s->grefs = NULL;
    s->gref_count = 0;
}

static bool vmedia_gntalloc_init(VirtIOMedia *s, Error **errp)
{
    struct ioctl_gntalloc_alloc_gref *alloc;
    size_t alloc_sz;
    uint32_t gref_count;
    int fd;
    int ret;

    gref_count = DIV_ROUND_UP(s->hostmem_size, VIRTIO_MEDIA_GREF_PAGE_SIZE);
    if (!gref_count) {
        error_setg(errp, "virtio-media: invalid gref count");
        return false;
    }

    fd = open("/dev/xen/gntalloc", O_RDWR);
    if (fd < 0) {
        error_setg_errno(errp, errno,
                         "virtio-media: failed to open /dev/xen/gntalloc");
        return false;
    }

    alloc_sz = sizeof(*alloc) + (gref_count - 1) * sizeof(uint32_t);
    alloc = g_malloc0(alloc_sz);
    alloc->domid = xen_domid;
    alloc->flags = GNTALLOC_FLAG_WRITABLE;
    alloc->count = gref_count;

    ret = ioctl(fd, IOCTL_GNTALLOC_ALLOC_GREF, alloc);
    if (ret < 0) {
        error_setg_errno(errp, errno,
                         "virtio-media: gntalloc alloc failed for %" PRIu64
                         " bytes (%u grant refs)",
                         s->hostmem_size, gref_count);
        g_free(alloc);
        close(fd);
        return false;
    }

    s->gref_count = gref_count;
    s->grefs = g_new(uint32_t, gref_count);
    memcpy(s->grefs, alloc->gref_ids, gref_count * sizeof(uint32_t));
    s->gntalloc_index = alloc->index;
    g_free(alloc);

    s->hostmem_buf = mmap(NULL, s->hostmem_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, s->gntalloc_index);
    if (s->hostmem_buf == MAP_FAILED) {
        error_setg_errno(errp, errno,
                         "virtio-media: gntalloc mmap failed");
        close(fd);
        s->gntalloc_fd = -1;
        return false;
    }

    s->gntalloc_fd = fd;
    return true;
}

struct virtio_media_cmd_header {
    uint32_t cmd;
    uint32_t reserved;
};

struct virtio_media_resp_header {
    uint32_t status;
    uint32_t reserved;
};

struct virtio_media_cmd_open {
    struct virtio_media_cmd_header hdr;
};

struct virtio_media_resp_open {
    struct virtio_media_resp_header hdr;
    uint32_t session_id;
    uint32_t reserved;
};

struct virtio_media_cmd_close {
    struct virtio_media_cmd_header hdr;
    uint32_t session_id;
    uint32_t reserved;
};

struct virtio_media_cmd_ioctl {
    struct virtio_media_cmd_header hdr;
    uint32_t session_id;
    uint32_t code;
};

struct virtio_media_resp_ioctl {
    struct virtio_media_resp_header hdr;
};

struct virtio_media_cmd_mmap {
    struct virtio_media_cmd_header hdr;
    uint32_t session_id;
    uint32_t flags;
    uint32_t offset;
};

/*
 * The spec response is {hdr, driver_addr, len}. The grant fields below are a
 * QEMU/Xen extension only emitted when the VIRTIO_MEDIA_F_GNTREF feature is
 * negotiated. A grant-unaware driver posts a response buffer of only
 * VIRTIO_MEDIA_RESP_MMAP_BASE_SIZE bytes, so the non-gref path MUST write
 * exactly that many bytes -- never sizeof(struct virtio_media_resp_mmap).
 */
struct virtio_media_resp_mmap {
    struct virtio_media_resp_header hdr;
    uint64_t driver_addr;
    uint64_t len;
    uint32_t gref_count;
    uint32_t gref_page_size;
    uint32_t gref_domid;
    uint32_t pad;
    uint32_t gref_ids[0];
};
#define VIRTIO_MEDIA_RESP_MMAP_BASE_SIZE \
    offsetof(struct virtio_media_resp_mmap, gref_count)

struct virtio_media_cmd_munmap {
    struct virtio_media_cmd_header hdr;
    uint64_t driver_addr;
};

struct virtio_media_resp_munmap {
    struct virtio_media_resp_header hdr;
};

struct virtio_media_cmd_export_buffer {
    struct virtio_media_cmd_header hdr;
    uint32_t session_id;
    uint32_t queue_type;
    uint32_t buffer_index;
    uint32_t plane_index;
    uint32_t flags;
    uint32_t reserved;
};

struct virtio_media_resp_export_buffer {
    struct virtio_media_resp_header hdr;
    uint64_t handle_id;
    uint64_t len;
    uint32_t plane_count;
    uint32_t reserved;
};

struct virtio_media_cmd_import_buffer {
    struct virtio_media_cmd_header hdr;
    uint32_t session_id;
    uint32_t flags;
    uint64_t handle_id;
};

struct virtio_media_cmd_register_buffer {
    struct virtio_media_cmd_header hdr;
    uint32_t session_id;
    uint32_t buffer_index;
    uint8_t uuid[16];
};
struct virtio_media_resp_register_buffer {
    struct virtio_media_resp_header hdr;
};

struct virtio_media_resp_import_buffer {
    struct virtio_media_resp_header hdr;
    uint64_t driver_addr;
    uint64_t len;
    uint32_t gref_count;
    uint32_t gref_page_size;
    uint32_t gref_domid;
    uint32_t pad;
    uint32_t gref_ids[0];
};

struct virtio_media_cmd_release_handle {
    struct virtio_media_cmd_header hdr;
    uint64_t handle_id;
};

struct virtio_media_resp_release_handle {
    struct virtio_media_resp_header hdr;
};

struct virtio_media_event_header {
    uint32_t event;
    uint32_t session_id;
};

struct virtio_media_event_dqbuf {
    struct virtio_media_event_header hdr;
    struct v4l2_buffer buffer;
    struct v4l2_plane planes[VIRTIO_MEDIA_MAX_PLANES];
};

struct virtio_media_event_event {
    struct virtio_media_event_header hdr;
    struct v4l2_event event;
};

typedef struct VirtIOMediaBuffer {
    QTAILQ_ENTRY(VirtIOMediaBuffer) next;
    uint32_t index;
    bool queued;
    uint32_t sequence;
    uint64_t base_offset;
    uint64_t plane_offsets[VIRTIO_MEDIA_MAX_PLANES];
    uint32_t plane_lengths[VIRTIO_MEDIA_MAX_PLANES];
    struct v4l2_buffer buffer;
    struct v4l2_plane planes[VIRTIO_MEDIA_MAX_PLANES];
} VirtIOMediaBuffer;

typedef struct VirtIOMediaSession {
    struct VirtIOMedia *dev;
    uint32_t id;
    bool streaming;
    uint32_t sequence;
    bool mplane;
    uint32_t buffer_size;
    uint32_t num_buffers;
    VirtIOMediaBuffer *buffers;
    int host_fd;
    uint32_t host_memory;
    bool host_streaming;
    void **host_maps;
    uint32_t *host_lengths;
    uint32_t *host_offsets;
    MemoryRegion *mr;
    uint32_t host_num_buffers;
    uint32_t host_num_planes;
    uint32_t host_plane_lengths[VIRTIO_MEDIA_MAX_PLANES];

    /*
     * Mode A (zero-copy re-grant): when true, host MMAP buffers are exported
     * via VIDIOC_EXPBUF and re-granted to the guest with gntdev IMP_TO_REFS,
     * so the guest maps the host driver's own capture pages (no per-frame
     * memcpy). Per (buffer,plane) we keep the EXPBUF fd, the gntdev import fd,
     * and the grant refs returned to the guest.
     */
    bool host_regrant;
    bool host_import_uuid;
    int *host_dmabuf_fds;     /* EXPBUF fd per (buffer*planes + plane) */
    int *host_import_fds;     /* gntdev import fd per (buffer*planes + plane) */
    uint32_t **host_gref_ids; /* gref array per (buffer*planes + plane) */
    uint32_t *host_gref_cnts; /* gref count per (buffer*planes + plane) */
    uint32_t host_event_subs; /* number of active host event subscriptions */
    QTAILQ_HEAD(, VirtIOMediaBuffer) queued_buffers;
} VirtIOMediaSession;

struct VirtIOMediaEvent {
    QTAILQ_ENTRY(VirtIOMediaEvent) next;
    size_t len;
    uint8_t data[sizeof(struct virtio_media_event_dqbuf)];
};

typedef struct VirtIOMediaShare {
    uint64_t handle_id;
    uint32_t owner_session_id;
    uint32_t queue_type;
    uint32_t buffer_index;
    uint32_t plane_index;
    uint64_t driver_addr;
    uint64_t len;
    uint32_t plane_count;
    GHashTable *peer_grants;
} VirtIOMediaShare;

typedef struct VirtIOMediaPeerGrant {
    uint32_t domid;
    uint32_t gref_count;
    uint64_t gntalloc_index;
    uint64_t map_len;
    uint64_t len;
    int gntalloc_fd;
    uint8_t *map;
    uint32_t *grefs;
} VirtIOMediaPeerGrant;

static void vmedia_peer_grant_free(gpointer opaque)
{
    VirtIOMediaPeerGrant *pg = opaque;

    if (!pg) {
        return;
    }

    if (pg->map && pg->map != MAP_FAILED) {
        munmap(pg->map, pg->map_len);
        pg->map = NULL;
    }

    if (pg->gntalloc_fd >= 0 && pg->gref_count) {
        struct ioctl_gntalloc_dealloc_gref dealloc = {
            .index = pg->gntalloc_index,
            .count = pg->gref_count,
        };

        ioctl(pg->gntalloc_fd, IOCTL_GNTALLOC_DEALLOC_GREF, &dealloc);
    }

    if (pg->gntalloc_fd >= 0) {
        close(pg->gntalloc_fd);
        pg->gntalloc_fd = -1;
    }

    g_free(pg->grefs);
    g_free(pg);
}

static VirtIOMediaPeerGrant *vmedia_peer_grant_new(uint32_t domid, uint64_t len,
                                                   int *status)
{
    struct ioctl_gntalloc_alloc_gref *alloc = NULL;
    VirtIOMediaPeerGrant *pg = NULL;
    size_t alloc_sz;
    int fd = -1;
    int ret;

    if (!len) {
        *status = -EINVAL;
        return NULL;
    }

    pg = g_new0(VirtIOMediaPeerGrant, 1);
    pg->domid = domid;
    pg->len = len;
    pg->gref_count = DIV_ROUND_UP(len, VIRTIO_MEDIA_GREF_PAGE_SIZE);
    pg->map_len = (uint64_t)pg->gref_count * VIRTIO_MEDIA_GREF_PAGE_SIZE;
    pg->gntalloc_fd = -1;

    fd = open("/dev/xen/gntalloc", O_RDWR);
    if (fd < 0) {
        *status = -errno;
        goto err;
    }

    alloc_sz = sizeof(*alloc) + (pg->gref_count - 1) * sizeof(uint32_t);
    alloc = g_malloc0(alloc_sz);
    alloc->domid = domid;
    alloc->flags = GNTALLOC_FLAG_WRITABLE;
    alloc->count = pg->gref_count;

    ret = ioctl(fd, IOCTL_GNTALLOC_ALLOC_GREF, alloc);
    if (ret < 0) {
        *status = -errno;
        goto err;
    }

    pg->grefs = g_new(uint32_t, pg->gref_count);
    memcpy(pg->grefs, alloc->gref_ids, pg->gref_count * sizeof(uint32_t));
    pg->gntalloc_index = alloc->index;
    pg->gntalloc_fd = fd;
    g_free(alloc);
    alloc = NULL;

    pg->map = mmap(NULL, pg->map_len, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, pg->gntalloc_index);
    if (pg->map == MAP_FAILED) {
        *status = -errno;
        pg->map = NULL;
        goto err;
    }

    pg->gntalloc_fd = fd;
    *status = 0;
    return pg;

err:
    g_free(alloc);
    if (fd >= 0 && pg && pg->gntalloc_fd < 0) {
        close(fd);
    }
    vmedia_peer_grant_free(pg);
    return NULL;
}

static void vmedia_share_free(gpointer opaque)
{
    VirtIOMediaShare *share = opaque;

    if (!share) {
        return;
    }

    if (share->peer_grants) {
        g_hash_table_destroy(share->peer_grants);
        share->peer_grants = NULL;
    }

    g_free(share);
}

static void vmedia_host_fd_handler(void *opaque);
static void vmedia_emit_dqbuf(VirtIOMedia *s, VirtIOMediaSession *session,
                              VirtIOMediaBuffer *buf);
static void vmedia_flush_events(VirtIOMedia *s);
static void vmedia_drain_host_events(VirtIOMedia *s,
                                     VirtIOMediaSession *session);
static void vmedia_proxy_stop(VirtIOMediaSession *session);
static void vmedia_share_remove_for_owner(VirtIOMedia *s, uint32_t owner_id);
static void vmedia_share_sync_for_buffer(VirtIOMedia *s,
                                         VirtIOMediaSession *session,
                                         uint32_t buffer_index);

static void vmedia_reset_buffers(VirtIOMediaSession *session)
{
    VirtIOMediaBuffer *buf;

    if (!session->buffers) {
        return;
    }

    QTAILQ_FOREACH(buf, &session->queued_buffers, next) {
        buf->queued = false;
    }
    QTAILQ_INIT(&session->queued_buffers);
    g_free(session->buffers);
    session->buffers = NULL;
    session->num_buffers = 0;
}

static void vmedia_regrant_teardown(VirtIOMediaSession *session)
{
    uint32_t planes = session->host_num_planes ? session->host_num_planes : 1;
    uint32_t n = session->host_num_buffers * planes;
    uint32_t idx;

    if (!session->host_regrant) {
        return;
    }

    for (idx = 0; idx < n; idx++) {
        if (session->host_import_fds && session->host_import_fds[idx] >= 0) {
            struct vmedia_gntdev_dmabuf_imp_release rel = {
                .fd = session->host_import_fds[idx],
            };
            int gfd = open("/dev/xen/gntdev", O_RDWR | O_CLOEXEC);
            if (gfd >= 0) {
                ioctl(gfd, VMEDIA_IOCTL_GNTDEV_DMABUF_IMP_RELEASE, &rel);
                close(gfd);
            }
            close(session->host_import_fds[idx]);
        }
        if (session->host_dmabuf_fds && session->host_dmabuf_fds[idx] >= 0) {
            close(session->host_dmabuf_fds[idx]);
        }
        if (session->host_gref_ids && session->host_gref_ids[idx]) {
            g_free(session->host_gref_ids[idx]);
        }
    }

    g_free(session->host_dmabuf_fds);
    g_free(session->host_import_fds);
    g_free(session->host_gref_ids);
    g_free(session->host_gref_cnts);
    session->host_dmabuf_fds = NULL;
    session->host_import_fds = NULL;
    session->host_gref_ids = NULL;
    session->host_gref_cnts = NULL;
    session->host_regrant = false;
}

static void vmedia_proxy_release_buffers(VirtIOMedia *s,
                                         VirtIOMediaSession *session)
{
    uint32_t i;
    uint32_t p;
    uint32_t planes;

    if (!s->use_host_device) {
        return;
    }

    vmedia_regrant_teardown(session);

    if (!session->host_maps) {
        session->host_num_buffers = 0;
        session->host_num_planes = 0;
        return;
    }

    planes = session->host_num_planes ? session->host_num_planes : 1;
    for (i = 0; i < session->host_num_buffers; i++) {
        for (p = 0; p < planes; p++) {
            uint32_t idx = i * planes + p;

            if (session->host_maps[idx]) {
                memory_region_del_subregion(&s->hostmem, &session->mr[idx]);
                object_unparent(OBJECT(&session->mr[idx]));
                munmap(session->host_maps[idx], session->host_lengths[idx]);
            }
        }
    }

    g_free(session->mr);
    g_free(session->host_maps);
    g_free(session->host_lengths);
    g_free(session->host_offsets);
    session->host_maps = NULL;
    session->host_lengths = NULL;
    session->host_offsets = NULL;
    session->host_num_buffers = 0;
    session->host_num_planes = 0;
}

static void vmedia_session_free(VirtIOMedia *s, VirtIOMediaSession *session)
{
    if (!session) {
        return;
    }

    vmedia_share_remove_for_owner(s, session->id);

    /* Closing the owner releases the capture queue. */
    if (s->capture_owner_session_id == session->id) {
        s->capture_owner_session_id = 0;
    }

    if (session->host_fd >= 0) {
        vmedia_proxy_stop(session);
        close(session->host_fd);
        session->host_fd = -1;
    }

    vmedia_proxy_release_buffers(s, session);
    vmedia_reset_buffers(session);
    g_free(session);
}

static VirtIOMediaSession *vmedia_session_new(VirtIOMedia *s, uint32_t id)
{
    VirtIOMediaSession *session = g_new0(VirtIOMediaSession, 1);

    session->dev = s;
    session->id = id;
    session->mplane = false;
    session->buffer_size = VIRTIO_MEDIA_BUFFER_SIZE_SINGLE;
    session->host_fd = -1;
    session->host_memory = V4L2_MEMORY_MMAP;
    session->host_streaming = false;
    session->host_maps = NULL;
    session->host_lengths = NULL;
    session->host_offsets = NULL;
    session->host_num_buffers = 0;
    session->host_num_planes = 0;
    memset(session->host_plane_lengths, 0, sizeof(session->host_plane_lengths));
    QTAILQ_INIT(&session->queued_buffers);
    return session;
}

/*
 * Open the backing host V4L2 device for this session on first use, rather than
 * eagerly at guest open() time. This keeps the number of concurrent guest
 * opens from being bounded by the host device's own open limit (e.g.
 * v4l2loopback's max_openers): a guest fd that only queries capabilities never
 * consumes a host open slot. Returns 0 on success or a negative errno.
 */
static int vmedia_session_ensure_host_fd(VirtIOMedia *s,
                                         VirtIOMediaSession *session)
{
    int fd;

    if (!s->use_host_device || session->host_fd >= 0) {
        return 0;
    }

    fd = open(s->host_device, O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        return -errno;
    }
    session->host_fd = fd;
    return 0;
}

static size_t vmedia_iov_read(const struct iovec *iov, int iov_cnt,
                              size_t offset, void *dst, size_t len)
{
    return iov_to_buf(iov, iov_cnt, offset, dst, len);
}

static size_t vmedia_iov_write(const struct iovec *iov, int iov_cnt,
                               size_t offset, const void *src, size_t len)
{
    return iov_from_buf(iov, iov_cnt, offset, src, len);
}

static void vmedia_write_resp_header(struct virtio_media_resp_header *resp,
                                     int status)
{
    resp->status = cpu_to_le32(status);
    resp->reserved = 0;
}

static void vmedia_queue_event(VirtIOMedia *s, const void *data, size_t len)
{
    VirtIOMediaEvent *evt;

    /*
     * Bound the backlog: if the guest is not posting event buffers we must not
     * grow pending_events without limit (host DoS). Drop the oldest event to
     * make room, matching the lossy nature of the V4L2 event/dqbuf path.
     */
    if (s->pending_events_count >= VIRTIO_MEDIA_MAX_PENDING_EVENTS) {
        VirtIOMediaEvent *old = QTAILQ_FIRST(&s->pending_events);

        if (old) {
            QTAILQ_REMOVE(&s->pending_events, old, next);
            g_free(old);
            s->pending_events_count--;
        }
    }

    evt = g_new0(VirtIOMediaEvent, 1);
    evt->len = MIN(len, sizeof(evt->data));
    memcpy(evt->data, data, evt->len);
    QTAILQ_INSERT_TAIL(&s->pending_events, evt, next);
    s->pending_events_count++;
}

static void vmedia_set_host_handler(VirtIOMediaSession *session, bool enable)
{
    if (session->host_fd < 0) {
        return;
    }

    if (enable) {
        qemu_set_fd_handler(session->host_fd, vmedia_host_fd_handler, NULL,
                            session);
    } else {
        qemu_set_fd_handler(session->host_fd, NULL, NULL, NULL);
    }
}

static void vmedia_host_fd_handler(void *opaque)
{
    VirtIOMediaSession *session = opaque;
    VirtIOMedia *s = session->dev;
    struct v4l2_buffer buf;
    struct v4l2_plane planes[VIRTIO_MEDIA_MAX_PLANES];

    /* Forward any pending V4L2 events (e.g. control changes) to the guest. */
    if (session->host_event_subs) {
        vmedia_drain_host_events(s, session);
    }

    /* Only dequeue buffers while streaming; an event-only wake has none. */
    if (!session->host_streaming) {
        vmedia_flush_events(s);
        return;
    }

    for (;;) {
        int ret;

        memset(&buf, 0, sizeof(buf));
        memset(planes, 0, sizeof(planes));
        buf.type = session->mplane ? V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE :
                                     V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = session->host_memory;
        if (session->mplane) {
            buf.length = session->host_num_planes;
            buf.m.planes = planes;
        }

        ret = vmedia_ioctl_nointr(session->host_fd, VIDIOC_DQBUF, &buf);
        if (ret < 0) {
            if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
                break;
            }
            return;
        }

        if (buf.index >= session->num_buffers ||
            buf.index >= session->host_num_buffers) {
            continue;
        }

        if (!session->buffers[buf.index].queued) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "virtio-media: host dqbuf for unqueued buffer idx=%u session=%u\n",
                          buf.index, session->id);
            continue;
        }

        if (session->mplane && session->host_num_planes) {
            uint32_t num_planes =
                MIN(session->host_num_planes,
                    session->buffers[buf.index].buffer.length);
            for (uint32_t p = 0; p < num_planes; p++) {
                uint32_t idx = buf.index * session->host_num_planes + p;
                uint32_t bytes;
                uint32_t fallback_len;
                uint32_t max_len = session->buffers[buf.index].plane_lengths[p];
                uint32_t copy_len;

                if (session->host_memory == V4L2_MEMORY_MMAP) {
                    fallback_len = session->host_lengths[idx];
                } else {
                    fallback_len = session->buffers[buf.index].plane_lengths[p];
                }
                bytes = planes[p].bytesused ? planes[p].bytesused :
                                              fallback_len;
                copy_len = MIN(bytes, max_len);

                session->buffers[buf.index].planes[p].bytesused = copy_len;
            }
        }

        session->buffers[buf.index].queued = false;
        session->buffers[buf.index].sequence = buf.sequence;
        if (!session->mplane) {
            session->buffers[buf.index].buffer.bytesused = buf.bytesused;
        }
        session->buffers[buf.index].buffer.timestamp = buf.timestamp;

        vmedia_share_sync_for_buffer(s, session, buf.index);
        vmedia_emit_dqbuf(s, session, &session->buffers[buf.index]);
    }

    vmedia_flush_events(s);
}

static void vmedia_proxy_stop(VirtIOMediaSession *session)
{
    VirtIOMedia *s = session->dev;
    int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

    if (!s->use_host_device || session->host_fd < 0) {
        return;
    }

    if (session->host_streaming) {
        vmedia_ioctl_nointr(session->host_fd, VIDIOC_STREAMOFF, &type);
        session->host_streaming = false;
    }

    vmedia_set_host_handler(session, false);
}

static void vmedia_flush_events(VirtIOMedia *s)
{
    VirtQueue *vq = s->event_vq;

    while (!QTAILQ_EMPTY(&s->pending_events)) {
        VirtIOMediaEvent *evt = QTAILQ_FIRST(&s->pending_events);
        g_autofree VirtQueueElement *elem;
        size_t in_len;
        size_t written;

        elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
        if (!elem) {
            return;
        }

        in_len = iov_size(elem->in_sg, elem->in_num);
        written = vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                                   evt->data, MIN(in_len, evt->len));
        virtqueue_push(vq, elem, written);
        virtio_notify(&s->parent_obj, vq);
        QTAILQ_REMOVE(&s->pending_events, evt, next);
        g_free(evt);
        s->pending_events_count--;
    }
}

static void vmedia_fill_fmtdesc(struct v4l2_fmtdesc *desc, uint32_t type)
{
    memset(desc, 0, sizeof(*desc));
    desc->index = 0;
    desc->type = type;
    if (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        desc->pixelformat = VIRTIO_MEDIA_PIXFMT_MPLANE;
        snprintf((char *)desc->description, sizeof(desc->description),
                 "YUV420");
    } else {
        desc->pixelformat = VIRTIO_MEDIA_PIXFMT_SINGLE;
        snprintf((char *)desc->description, sizeof(desc->description),
                 "YUYV");
    }
}

static void vmedia_fill_format(struct v4l2_format *fmt, uint32_t type)
{
    memset(fmt, 0, sizeof(*fmt));
    fmt->type = type;
    if (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        struct v4l2_pix_format_mplane *pix_mp = &fmt->fmt.pix_mp;
        uint32_t y_size = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT;
        uint32_t uv_size = y_size / 4;

        pix_mp->width = VIRTIO_MEDIA_WIDTH;
        pix_mp->height = VIRTIO_MEDIA_HEIGHT;
        pix_mp->pixelformat = VIRTIO_MEDIA_PIXFMT_MPLANE;
        pix_mp->field = V4L2_FIELD_NONE;
        pix_mp->colorspace = V4L2_COLORSPACE_SRGB;
        pix_mp->num_planes = 3;
        pix_mp->plane_fmt[0].sizeimage = y_size;
        pix_mp->plane_fmt[0].bytesperline = VIRTIO_MEDIA_WIDTH;
        pix_mp->plane_fmt[1].sizeimage = uv_size;
        pix_mp->plane_fmt[1].bytesperline = VIRTIO_MEDIA_WIDTH / 2;
        pix_mp->plane_fmt[2].sizeimage = uv_size;
        pix_mp->plane_fmt[2].bytesperline = VIRTIO_MEDIA_WIDTH / 2;
    } else {
        struct v4l2_pix_format *pix = &fmt->fmt.pix;

        pix->width = VIRTIO_MEDIA_WIDTH;
        pix->height = VIRTIO_MEDIA_HEIGHT;
        pix->pixelformat = VIRTIO_MEDIA_PIXFMT_SINGLE;
        pix->field = V4L2_FIELD_NONE;
        pix->colorspace = V4L2_COLORSPACE_SRGB;
        pix->bytesperline = VIRTIO_MEDIA_WIDTH * 2;
        pix->sizeimage = VIRTIO_MEDIA_BUFFER_SIZE_SINGLE;
    }
}

static void vmedia_generate_frame(VirtIOMedia *s, VirtIOMediaSession *session,
                                  VirtIOMediaBuffer *buf)
{
    uint8_t *base = vmedia_hostmem_base(s);
    uint8_t *ptr = base + buf->base_offset;
    static const uint8_t yuv_bars[8][3] = {
        { 235, 128, 128 }, /* white */
        { 210,  16, 146 }, /* yellow */
        { 170, 166,  16 }, /* cyan */
        { 145,  54,  34 }, /* green */
        { 107, 202, 222 }, /* magenta */
        {  81,  90, 240 }, /* red */
        {  41, 240, 110 }, /* blue */
        {  16, 128, 128 }, /* black */
    };
    const uint32_t width = VIRTIO_MEDIA_WIDTH;
    const uint32_t height = VIRTIO_MEDIA_HEIGHT;
    const uint32_t bar_width = width / 8;

    if (session->mplane) {
        uint32_t y_size = width * height;
        uint32_t uv_size = y_size / 4;
        uint8_t *y_plane = ptr;
        uint8_t *u_plane = ptr + y_size;
        uint8_t *v_plane = ptr + y_size + uv_size;
        uint32_t x;
        uint32_t y;

        for (y = 0; y < height; y++) {
            for (x = 0; x < width; x++) {
                uint32_t bar = MIN(x / bar_width, 7u);
                y_plane[y * width + x] = yuv_bars[bar][0];
            }
        }

        for (y = 0; y < height / 2; y++) {
            for (x = 0; x < width / 2; x++) {
                uint32_t bar = MIN((x * 2) / bar_width, 7u);
                u_plane[y * (width / 2) + x] = yuv_bars[bar][1];
                v_plane[y * (width / 2) + x] = yuv_bars[bar][2];
            }
        }
    } else {
        uint32_t x;
        uint32_t y;

        for (y = 0; y < height; y++) {
            for (x = 0; x < width; x += 2) {
                uint32_t bar = MIN(x / bar_width, 7u);
                uint8_t y0 = yuv_bars[bar][0];
                uint8_t u = yuv_bars[bar][1];
                uint8_t v = yuv_bars[bar][2];
                uint32_t offset = (y * width + x) * 2;

                ptr[offset] = y0;
                ptr[offset + 1] = u;
                ptr[offset + 2] = y0;
                ptr[offset + 3] = v;
            }
        }
    }

    buf->sequence = session->sequence++;
}

static void vmedia_emit_dqbuf(VirtIOMedia *s, VirtIOMediaSession *session,
                                    VirtIOMediaBuffer *buf)
{
    struct virtio_media_event_dqbuf evt;
    struct v4l2_buffer *buffer = &evt.buffer;

    memset(&evt, 0, sizeof(evt));
    evt.hdr.event = cpu_to_le32(VIRTIO_MEDIA_EVT_DQBUF);
    evt.hdr.session_id = cpu_to_le32(session->id);

    *buffer = buf->buffer;
    buffer->sequence = buf->sequence;
    buffer->flags |= V4L2_BUF_FLAG_DONE;
    if (!s->use_host_device) {
        /* Synthetic path: stamp a real monotonic capture time. */
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        buffer->timestamp.tv_sec = ts.tv_sec;
        buffer->timestamp.tv_usec = ts.tv_nsec / 1000;
    }
    /*
     * Advertise the timestamp source. The synthetic path stamps CLOCK_MONOTONIC
     * above; the host-proxy path forwards the host driver's timestamp, which is
     * CLOCK_MONOTONIC for in-kernel V4L2 drivers (uvc, vivid, v4l2loopback).
     * Setting the source flag is required for V4L2 compliance and lets the
     * guest/userspace compare it against CLOCK_MONOTONIC.
     */
    buffer->flags &= ~V4L2_BUF_FLAG_TIMESTAMP_MASK;
    buffer->flags |= V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
    /*
     * A dequeued capture buffer must report a concrete field, never
     * V4L2_FIELD_ANY. We only deal with progressive formats here, so report
     * V4L2_FIELD_NONE if the host left it unset.
     */
    if (buffer->field == V4L2_FIELD_ANY) {
        buffer->field = V4L2_FIELD_NONE;
    }
    buffer->m.planes = NULL;

    if (session->mplane) {
        if (!s->use_host_device) {
            buf->planes[0].bytesused = buf->plane_lengths[0];
            buf->planes[1].bytesused = buf->plane_lengths[1];
            buf->planes[2].bytesused = buf->plane_lengths[2];
        }
        memcpy(evt.planes, buf->planes, sizeof(buf->planes));
    } else if (!s->use_host_device) {
        buffer->bytesused = session->buffer_size;
    }
    vmedia_queue_event(s, &evt, sizeof(evt));
}

/*
 * Drain any pending V4L2 events from the host device and forward them to the
 * guest as VIRTIO_MEDIA_EVT_EVENT. Called after subscribing (to deliver the
 * initial event) and from the host fd handler when the device signals an event.
 */
static void vmedia_drain_host_events(VirtIOMedia *s,
                                     VirtIOMediaSession *session)
{
    if (!s->use_host_device || session->host_fd < 0) {
        return;
    }

    for (;;) {
        struct virtio_media_event_event evt;
        int ret;

        memset(&evt, 0, sizeof(evt));
        ret = vmedia_ioctl_nointr(session->host_fd, VIDIOC_DQEVENT,
                                  &evt.event);
        if (ret < 0) {
            break;
        }
        evt.hdr.event = cpu_to_le32(VIRTIO_MEDIA_EVT_EVENT);
        evt.hdr.session_id = cpu_to_le32(session->id);
        vmedia_queue_event(s, &evt, sizeof(evt));
    }
}

static int vmedia_alloc_buffers(VirtIOMedia *s, VirtIOMediaSession *session,
                                      uint32_t count)
{
    uint64_t offset = 0;
    uint32_t i;

    vmedia_reset_buffers(session);

    if (!count) {
        return 0;
    }

    if (count > s->max_buffers) {
        count = s->max_buffers;
    }

    session->buffers = g_new0(VirtIOMediaBuffer, count);
    session->num_buffers = count;

    for (i = 0; i < count; i++) {
        VirtIOMediaBuffer *buf = &session->buffers[i];
        struct v4l2_plane *planes = buf->planes;
        uint32_t num_planes = 0;
        uint32_t plane_lengths[VIRTIO_MEDIA_MAX_PLANES] = { 0 };
        uint64_t buf_size = 0;

        buf->index = i;
        buf->queued = false;
        buf->base_offset = offset;
        if (session->mplane) {
            bool use_host_planes = session->host_num_planes &&
                session->host_plane_lengths[0];

            if (use_host_planes) {
                num_planes = session->host_num_planes;
                for (uint32_t p = 0; p < num_planes; p++) {
                    plane_lengths[p] = session->host_plane_lengths[p];
                }
            } else {
                num_planes = 3;
                plane_lengths[0] = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT;
                plane_lengths[1] = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT / 4;
                plane_lengths[2] = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT / 4;
            }

            buf->plane_offsets[0] = offset;
            for (uint32_t p = 0; p < num_planes; p++) {
                uint32_t plen = plane_lengths[p];

                if (p > 0) {
                    buf->plane_offsets[p] =
                        buf->plane_offsets[p - 1] +
                        (session->host_regrant ?
                         ROUND_UP(plane_lengths[p - 1],
                                  VIRTIO_MEDIA_GREF_PAGE_SIZE) :
                         ROUND_UP(plane_lengths[p - 1],
                                  qemu_real_host_page_size()));
                }
                buf->plane_lengths[p] = plen;
                /*
                 * In regrant mode each plane is re-granted as a whole number of
                 * pages; advance the synthetic layout by the page-rounded size
                 * so plane/buffer offsets align with gref boundaries and never
                 * overlap. In mmap mode the guest maps each plane by its
                 * mem_offset, which mmap requires to be page-aligned, so round
                 * to the host page size there too.
                 */
                buf_size += session->host_regrant ?
                    ROUND_UP(plen, VIRTIO_MEDIA_GREF_PAGE_SIZE) :
                    ROUND_UP(plen, qemu_real_host_page_size());
            }
        } else {
            buf->plane_offsets[0] = offset;
            buf->plane_lengths[0] = session->buffer_size;
            buf_size = session->host_regrant ?
                ROUND_UP(session->buffer_size, VIRTIO_MEDIA_GREF_PAGE_SIZE) :
                ROUND_UP(session->buffer_size, qemu_real_host_page_size());
        }

        /*
         * The synthetic plane offsets only index into the device hostmem pool
         * in non-regrant modes. In regrant mode there is no pool (buffers are
         * re-granted from the host EXPBUF dma-bufs), so skip the bounds check.
         */
        if (!session->host_regrant && !session->host_import_uuid &&
            offset + buf_size > s->hostmem_size) {
            vmedia_reset_buffers(session);
            return -ENOMEM;
        }

        memset(&buf->buffer, 0, sizeof(buf->buffer));
        buf->buffer.index = i;
        buf->buffer.type = session->mplane ?
            V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE : V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf->buffer.memory = V4L2_MEMORY_MMAP;
        if (session->mplane) {
            buf->buffer.length = num_planes;
            buf->buffer.m.planes = planes;

            memset(planes, 0, sizeof(buf->planes));
            for (uint32_t p = 0; p < num_planes; p++) {
                planes[p].length = buf->plane_lengths[p];
                planes[p].m.mem_offset = buf->plane_offsets[p];
            }
        } else {
            buf->buffer.length = session->buffer_size;
            buf->buffer.m.offset = buf->plane_offsets[0];
        }

        offset += buf_size;
    }

    return 0;
}

static int vmedia_find_plane(VirtIOMediaSession *session, uint32_t offset,
                                   uint64_t *addr, uint64_t *len)
{
    uint32_t i;

    for (i = 0; i < session->num_buffers; i++) {
        VirtIOMediaBuffer *buf = &session->buffers[i];
        uint32_t p;

        if (!session->mplane) {
            if (buf->plane_offsets[0] == offset) {
                *addr = buf->plane_offsets[0];
                *len = buf->plane_lengths[0];
                return 0;
            }
            continue;
        }

        for (p = 0; p < buf->buffer.length &&
                    p < VIRTIO_MEDIA_MAX_PLANES; p++) {
            if (buf->plane_offsets[p] == offset) {
                *addr = buf->plane_offsets[p];
                *len = buf->plane_lengths[p];
                return 0;
            }
        }
    }

    return -EINVAL;
}

/*
 * Like vmedia_find_plane but also returns the (buffer, plane) indices, used by
 * Mode A to locate the per-buffer re-granted gref array for a guest offset.
 */
static int vmedia_find_plane_index(VirtIOMediaSession *session, uint32_t offset,
                                   uint32_t *buf_index, uint32_t *plane_index)
{
    uint32_t i;

    for (i = 0; i < session->num_buffers; i++) {
        VirtIOMediaBuffer *buf = &session->buffers[i];
        uint32_t p;

        if (!session->mplane) {
            if (buf->plane_offsets[0] == offset) {
                *buf_index = i;
                *plane_index = 0;
                return 0;
            }
            continue;
        }

        for (p = 0; p < buf->buffer.length &&
                    p < VIRTIO_MEDIA_MAX_PLANES; p++) {
            if (buf->plane_offsets[p] == offset) {
                *buf_index = i;
                *plane_index = p;
                return 0;
            }
        }
    }

    return -EINVAL;
}

static gboolean vmedia_share_remove_for_owner_cb(gpointer key, gpointer value,
                                                 gpointer user_data)
{
    VirtIOMediaShare *share = value;
    uint32_t owner_id = *(uint32_t *)user_data;

    return share->owner_session_id == owner_id;
}

static void vmedia_share_remove_for_owner(VirtIOMedia *s, uint32_t owner_id)
{
    if (!s->share_handles) {
        return;
    }

    g_hash_table_foreach_remove(s->share_handles,
                                vmedia_share_remove_for_owner_cb,
                                &owner_id);
}

static VirtIOMediaShare *vmedia_share_lookup(VirtIOMedia *s, uint64_t handle_id)
{
    return g_hash_table_lookup(s->share_handles, &handle_id);
}

static void vmedia_share_sync_peer_grants(VirtIOMedia *s,
                                          VirtIOMediaShare *share)
{
    GHashTableIter iter;
    gpointer key;
    gpointer value;
    uint8_t *src;

    if (!share->peer_grants || g_hash_table_size(share->peer_grants) == 0) {
        return;
    }

    src = vmedia_hostmem_base(s) + share->driver_addr;
    g_hash_table_iter_init(&iter, share->peer_grants);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        VirtIOMediaPeerGrant *pg = value;

        memcpy(pg->map, src, share->len);
    }
}

typedef struct VirtIOMediaShareSyncCtx {
    VirtIOMedia *s;
    uint32_t owner_session_id;
    uint32_t buffer_index;
} VirtIOMediaShareSyncCtx;

static void vmedia_share_sync_cb(gpointer key, gpointer value,
                                 gpointer user_data)
{
    VirtIOMediaShare *share = value;
    VirtIOMediaShareSyncCtx *ctx = user_data;

    if (share->owner_session_id != ctx->owner_session_id ||
        share->buffer_index != ctx->buffer_index) {
        return;
    }

    vmedia_share_sync_peer_grants(ctx->s, share);
}

static void vmedia_share_sync_for_buffer(VirtIOMedia *s,
                                         VirtIOMediaSession *session,
                                         uint32_t buffer_index)
{
    VirtIOMediaShareSyncCtx ctx = {
        .s = s,
        .owner_session_id = session->id,
        .buffer_index = buffer_index,
    };

    if (!s->share_handles || g_hash_table_size(s->share_handles) == 0) {
        return;
    }

    g_hash_table_foreach(s->share_handles, vmedia_share_sync_cb, &ctx);
}

static VirtIOMediaPeerGrant *
vmedia_share_get_peer_grant(VirtIOMedia *s, VirtIOMediaShare *share,
                            uint32_t domid, int *status)
{
    VirtIOMediaPeerGrant *pg;

    pg = g_hash_table_lookup(share->peer_grants, GUINT_TO_POINTER(domid));
    if (pg) {
        *status = 0;
        return pg;
    }

    pg = vmedia_peer_grant_new(domid, share->len, status);
    if (!pg) {
        return NULL;
    }

    memcpy(pg->map, vmedia_hostmem_base(s) + share->driver_addr, share->len);
    g_hash_table_insert(share->peer_grants, GUINT_TO_POINTER(domid), pg);
    *status = 0;
    return pg;
}

static uint64_t vmedia_share_next_handle(VirtIOMedia *s)
{
    if (s->next_share_handle == 0) {
        s->next_share_handle = 1;
    }

    return s->next_share_handle++;
}

static int vmedia_share_from_buffer(VirtIOMedia *s, VirtIOMediaSession *session,
                                    uint32_t queue_type, uint32_t buffer_index,
                                    uint32_t plane_index,
                                    VirtIOMediaShare **out_share)
{
    VirtIOMediaBuffer *buf;
    VirtIOMediaShare *share;
    uint32_t num_planes;

    if (queue_type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        queue_type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }
    if (session->mplane != (queue_type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)) {
        return -EINVAL;
    }
    if (buffer_index >= session->num_buffers) {
        return -EINVAL;
    }

    buf = &session->buffers[buffer_index];
    num_planes = session->mplane ? buf->buffer.length : 1;
    if (plane_index >= num_planes) {
        return -EINVAL;
    }

    share = g_new0(VirtIOMediaShare, 1);
    share->handle_id = vmedia_share_next_handle(s);
    share->owner_session_id = session->id;
    share->queue_type = queue_type;
    share->buffer_index = buffer_index;
    share->plane_index = plane_index;
    share->driver_addr = buf->plane_offsets[plane_index];
    share->len = buf->plane_lengths[plane_index];
    share->plane_count = num_planes;
    share->peer_grants = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                NULL, vmedia_peer_grant_free);
    *out_share = share;

    return 0;
}

static int vmedia_read_planes(const struct iovec *iov, int iov_cnt,
                              size_t offset, struct v4l2_plane *planes,
                              uint32_t num_planes)
{
    size_t len = sizeof(struct v4l2_plane) * num_planes;
    size_t read = vmedia_iov_read(iov, iov_cnt, offset, planes, len);

    return (read == len) ? 0 : -EINVAL;
}

static int vmedia_write_planes(const struct iovec *iov, int iov_cnt,
                               size_t offset,
                               const struct v4l2_plane *planes,
                               uint32_t num_planes)
{
    size_t len = sizeof(struct v4l2_plane) * num_planes;
    size_t written = vmedia_iov_write(iov, iov_cnt, offset, planes, len);

    return (written == len) ? 0 : -EINVAL;
}

static int vmedia_ioctl_nointr(int fd, unsigned long req, void *arg)
{
    int ret;

    do {
        ret = ioctl(fd, req, arg);
    } while (ret < 0 && errno == EINTR);

    return ret < 0 ? -errno : 0;
}

static int vmedia_proxy_ioctl(int fd, unsigned long req, void *arg)
{
    return vmedia_ioctl_nointr(fd, req, arg);
}

/*
 * Grant a host dma-buf's pages to the guest with gntdev IMP_TO_REFS. Takes
 * ownership of @dmabuf_fd: stores it, the gntdev import fd, and the grant-ref
 * array on the session at slot @idx. On error closes @dmabuf_fd. Used by
 * import mode (dma-heap dmabuf source).
 */
static int vmedia_grant_dmabuf(VirtIOMediaSession *session, uint32_t idx,
                               int dmabuf_fd, uint32_t len)
{
    uint32_t page_count = DIV_ROUND_UP(len, VIRTIO_MEDIA_GREF_PAGE_SIZE);
    struct vmedia_gntdev_dmabuf_imp_to_refs *imp;
    size_t imp_sz;
    int gntdev_fd;
    int ret;

    gntdev_fd = open("/dev/xen/gntdev", O_RDWR | O_CLOEXEC);
    if (gntdev_fd < 0) {
        ret = -errno;
        close(dmabuf_fd);
        return ret;
    }

    imp_sz = sizeof(*imp) + (size_t)(page_count - 1) * sizeof(uint32_t);
    imp = g_malloc0(imp_sz);
    imp->fd = dmabuf_fd;
    imp->count = page_count;
    imp->domid = xen_domid;

    ret = ioctl(gntdev_fd, VMEDIA_IOCTL_GNTDEV_DMABUF_IMP_TO_REFS, imp);
    if (ret < 0) {
        ret = -errno;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: import IMP_TO_REFS failed idx=%u pages=%u "
                      "domid=%u: %d\n", idx, page_count, xen_domid, ret);
        g_free(imp);
        close(gntdev_fd);
        close(dmabuf_fd);
        return ret;
    }

    session->host_gref_cnts[idx] = page_count;
    session->host_gref_ids[idx] = g_new(uint32_t, page_count);
    memcpy(session->host_gref_ids[idx], imp->refs,
           page_count * sizeof(uint32_t));
    session->host_dmabuf_fds[idx] = dmabuf_fd;
    session->host_import_fds[idx] = gntdev_fd;
    session->host_lengths[idx] = len;
    g_free(imp);
    return 0;
}

/*
 * Import mode helper: allocate a system-RAM dma-buf from dma-heap @heap_fd.
 * Returns a dma-buf fd (>=0) or negative errno.
 */
static int vmedia_dmaheap_alloc(int heap_fd, uint32_t len)
{
    struct vmedia_dma_heap_allocation_data data;
    int ret;

    memset(&data, 0, sizeof(data));
    data.len = len;
    data.fd_flags = O_RDWR | O_CLOEXEC;
    ret = ioctl(heap_fd, VMEDIA_DMA_HEAP_IOCTL_ALLOC, &data);
    if (ret < 0) {
        return -errno;
    }
    return data.fd;
}

/*
 * Mode A helper: export host MMAP buffer (index, plane) as a dma-buf via
 * VIDIOC_EXPBUF, then re-grant its pages to the guest domain with gntdev
 * IMP_TO_REFS. On success stores the EXPBUF fd, the gntdev import fd, and the
 * grant-ref array on the session at slot @idx. Returns 0, or negative errno.
 */
static int vmedia_regrant_buffer_plane(VirtIOMediaSession *session,
                                       uint32_t buf_index, uint32_t plane,
                                       uint32_t idx, uint32_t len)
{
    struct v4l2_exportbuffer expbuf;
    uint32_t page_count = DIV_ROUND_UP(len, VIRTIO_MEDIA_GREF_PAGE_SIZE);
    struct vmedia_gntdev_dmabuf_imp_to_refs *imp;
    size_t imp_sz;
    int gntdev_fd = -1;
    int dmabuf_fd = -1;
    int ret;

    memset(&expbuf, 0, sizeof(expbuf));
    expbuf.type = session->mplane ? V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE :
                                    V4L2_BUF_TYPE_VIDEO_CAPTURE;
    expbuf.index = buf_index;
    expbuf.plane = plane;
    expbuf.flags = O_RDWR | O_CLOEXEC;

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_EXPBUF, &expbuf);
    if (ret < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: regrant EXPBUF failed buf=%u plane=%u: %d\n",
                      buf_index, plane, ret);
        return ret;
    }
    dmabuf_fd = expbuf.fd;

    gntdev_fd = open("/dev/xen/gntdev", O_RDWR | O_CLOEXEC);
    if (gntdev_fd < 0) {
        ret = -errno;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: regrant open gntdev failed: %d\n", ret);
        goto err_dmabuf;
    }

    imp_sz = sizeof(*imp) + (size_t)(page_count - 1) * sizeof(uint32_t);
    imp = g_malloc0(imp_sz);
    imp->fd = dmabuf_fd;
    imp->count = page_count;
    imp->domid = xen_domid;

    ret = ioctl(gntdev_fd, VMEDIA_IOCTL_GNTDEV_DMABUF_IMP_TO_REFS, imp);
    if (ret < 0) {
        ret = -errno;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: regrant IMP_TO_REFS failed buf=%u plane=%u "
                      "pages=%u domid=%u: %d\n",
                      buf_index, plane, page_count, xen_domid, ret);
        g_free(imp);
        goto err_gntdev;
    }

    session->host_gref_cnts[idx] = page_count;
    session->host_gref_ids[idx] = g_new(uint32_t, page_count);
    memcpy(session->host_gref_ids[idx], imp->refs,
           page_count * sizeof(uint32_t));
    session->host_dmabuf_fds[idx] = dmabuf_fd;
    session->host_import_fds[idx] = gntdev_fd;
    session->host_lengths[idx] = len;
    g_free(imp);
    return 0;

err_gntdev:
    close(gntdev_fd);
err_dmabuf:
    close(dmabuf_fd);
    return ret;
}

static bool vmedia_type_supports_userptr(int fd, uint32_t type)
{
    struct v4l2_requestbuffers reqbufs = { 0 };
    int ret;

    reqbufs.type = type;
    reqbufs.memory = V4L2_MEMORY_MMAP;
    ret = vmedia_proxy_ioctl(fd, VIDIOC_REQBUFS, &reqbufs);
    if (ret < 0) {
        return false;
    }

    if (reqbufs.capabilities &&
        !(reqbufs.capabilities & V4L2_BUF_CAP_SUPPORTS_USERPTR)) {
        return false;
    }

    memset(&reqbufs, 0, sizeof(reqbufs));
    reqbufs.type = type;
    reqbufs.memory = V4L2_MEMORY_USERPTR;
    return vmedia_proxy_ioctl(fd, VIDIOC_REQBUFS, &reqbufs) == 0;
}

static bool vmedia_userptr_supported_for_type(VirtIOMedia *s, uint32_t type)
{
    if (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return s->host_userptr_mplane;
    }

    return s->host_userptr_capture;
}

static int vmedia_get_host_memory_mode(VirtIOMedia *s, uint32_t type,
                                       uint32_t *memory)
{
    bool supports_userptr = vmedia_userptr_supported_for_type(s, type);

    switch (s->host_v4l2_mem_mode) {
    case VMEDIA_HOST_V4L2_MEM_MMAP:
        *memory = V4L2_MEMORY_MMAP;
        return 0;
    case VMEDIA_HOST_V4L2_MEM_REGRANT:
        /* Mode A uses host MMAP buffers, then re-grants them. */
        *memory = V4L2_MEMORY_MMAP;
        return 0;
    case VMEDIA_HOST_V4L2_MEM_IMPORT:
        /* Import uses dma-heap dmabufs driven downstream as DMABUF. */
        *memory = V4L2_MEMORY_DMABUF;
        return 0;
    case VMEDIA_HOST_V4L2_MEM_IMPORT_UUID:
        /* Import-UUID: guest-supplied blob resolved to a host dmabuf. */
        *memory = V4L2_MEMORY_DMABUF;
        return 0;
    case VMEDIA_HOST_V4L2_MEM_USERPTR:
        if (!supports_userptr) {
            return -EINVAL;
        }
        *memory = V4L2_MEMORY_USERPTR;
        return 0;
    case VMEDIA_HOST_V4L2_MEM_AUTO:
        *memory = supports_userptr ? V4L2_MEMORY_USERPTR : V4L2_MEMORY_MMAP;
        return 0;
    default:
        return -EINVAL;
    }
}

static int vmedia_parse_host_v4l2_mem_mode(VirtIOMedia *s, Error **errp)
{
    const char *mode = s->host_v4l2_mem ? s->host_v4l2_mem : "auto";

    if (!strcmp(mode, "auto")) {
        s->host_v4l2_mem_mode = VMEDIA_HOST_V4L2_MEM_AUTO;
        return 0;
    }
    if (!strcmp(mode, "mmap")) {
        s->host_v4l2_mem_mode = VMEDIA_HOST_V4L2_MEM_MMAP;
        return 0;
    }
    if (!strcmp(mode, "userptr")) {
        s->host_v4l2_mem_mode = VMEDIA_HOST_V4L2_MEM_USERPTR;
        return 0;
    }
    if (!strcmp(mode, "regrant")) {
        s->host_v4l2_mem_mode = VMEDIA_HOST_V4L2_MEM_REGRANT;
        return 0;
    }
    if (!strcmp(mode, "import")) {
        s->host_v4l2_mem_mode = VMEDIA_HOST_V4L2_MEM_IMPORT;
        return 0;
    }
    if (!strcmp(mode, "import-uuid")) {
        s->host_v4l2_mem_mode = VMEDIA_HOST_V4L2_MEM_IMPORT_UUID;
        return 0;
    }

    error_setg(errp,
               "virtio-media: invalid host-v4l2-memory '%s' "
               "(use auto|mmap|userptr|regrant|import)",
               mode);
    return -EINVAL;
}

static uint64_t vmedia_proxy_max_sizeimage_for_format(int fd,
                                                      uint32_t pixelformat)
{
    struct v4l2_frmsizeenum frmsize;
    struct v4l2_format fmt;
    uint32_t max_width = 0;
    uint32_t max_height = 0;
    int ret;

    memset(&frmsize, 0, sizeof(frmsize));
    frmsize.pixel_format = pixelformat;
    for (frmsize.index = 0;; frmsize.index++) {
        ret = vmedia_proxy_ioctl(fd, VIDIOC_ENUM_FRAMESIZES, &frmsize);
        if (ret < 0) {
            break;
        }

        switch (frmsize.type) {
        case V4L2_FRMSIZE_TYPE_DISCRETE:
            if (frmsize.discrete.width > max_width) {
                max_width = frmsize.discrete.width;
            }
            if (frmsize.discrete.height > max_height) {
                max_height = frmsize.discrete.height;
            }
            break;
        case V4L2_FRMSIZE_TYPE_CONTINUOUS:
        case V4L2_FRMSIZE_TYPE_STEPWISE:
            max_width = frmsize.stepwise.max_width;
            max_height = frmsize.stepwise.max_height;
            frmsize.index = UINT32_MAX;
            break;
        default:
            frmsize.index = UINT32_MAX;
            break;
        }
    }

    if (!max_width || !max_height) {
        return 0;
    }

    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = max_width;
    fmt.fmt.pix.height = max_height;
    fmt.fmt.pix.pixelformat = pixelformat;

    ret = vmedia_proxy_ioctl(fd, VIDIOC_TRY_FMT, &fmt);
    if (ret < 0) {
        return 0;
    }

    if (fmt.fmt.pix.sizeimage) {
        return fmt.fmt.pix.sizeimage;
    }

    return (uint64_t)fmt.fmt.pix.width * fmt.fmt.pix.height * 2;
}

static uint64_t vmedia_proxy_max_sizeimage(int fd)
{
    struct v4l2_fmtdesc desc;
    uint64_t max_sizeimage = 0;
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    for (desc.index = 0;; desc.index++) {
        uint64_t sizeimage;

        ret = vmedia_proxy_ioctl(fd, VIDIOC_ENUM_FMT, &desc);
        if (ret < 0) {
            break;
        }

        sizeimage = vmedia_proxy_max_sizeimage_for_format(fd,
                                                          desc.pixelformat);
        max_sizeimage = MAX(max_sizeimage, sizeimage);
    }

    return max_sizeimage;
}

static int vmedia_proxy_enuminput(VirtIOMediaSession *session,
                                  const struct iovec *out_sg, int out_num,
                                  const struct iovec *in_sg, int in_num,
                                  size_t out_off, size_t in_off)
{
    struct v4l2_input input;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &input,
                              sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_ENUMINPUT, &input);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &input,
                               sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_g_input(VirtIOMediaSession *session,
                                const struct iovec *in_sg, int in_num,
                                size_t in_off)
{
    uint32_t input = 0;
    int ret;

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_G_INPUT, &input);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &input,
                               sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_s_input(VirtIOMediaSession *session,
                                const struct iovec *out_sg, int out_num,
                                const struct iovec *in_sg, int in_num,
                                size_t out_off, size_t in_off)
{
    uint32_t input;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &input,
                              sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_S_INPUT, &input);
    if (ret < 0) {
        return ret;
    }

    /* Echo back the resulting input index so the guest sees the value. */
    if (vmedia_iov_write(in_sg, in_num, in_off, &input,
                               sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_enum_fmt(VirtIOMediaSession *session,
                                 const struct iovec *out_sg, int out_num,
                                 const struct iovec *in_sg, int in_num,
                                 size_t out_off, size_t in_off)
{
    struct v4l2_fmtdesc desc;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &desc,
                              sizeof(desc)) != sizeof(desc)) {
        return -EINVAL;
    }

    if (desc.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        desc.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_ENUM_FMT, &desc);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &desc,
                               sizeof(desc)) != sizeof(desc)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_g_fmt(VirtIOMediaSession *session,
                              const struct iovec *out_sg, int out_num,
                              const struct iovec *in_sg, int in_num,
                              size_t out_off, size_t in_off)
{
    struct v4l2_format fmt;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &fmt,
                              sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    if (fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_G_FMT, &fmt);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &fmt,
                               sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_s_fmt(VirtIOMediaSession *session,
                              const struct iovec *out_sg, int out_num,
                              const struct iovec *in_sg, int in_num,
                              size_t out_off, size_t in_off,
                              bool is_try)
{
    struct v4l2_format fmt;
    unsigned long req = is_try ? VIDIOC_TRY_FMT : VIDIOC_S_FMT;
    struct v4l2_requestbuffers reqbufs;
    uint32_t type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    uint64_t sizeimage;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &fmt,
                              sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    if (fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, req, &fmt);
    if (ret == -EBUSY && !is_try) {
        int stop_ret;

        stop_ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_STREAMOFF,
                                      &type);
        if (stop_ret < 0 && stop_ret != -EINVAL) {
            return stop_ret;
        }
        session->host_streaming = false;
        vmedia_set_host_handler(session, false);

        memset(&reqbufs, 0, sizeof(reqbufs));
        reqbufs.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        reqbufs.memory = V4L2_MEMORY_MMAP;
        reqbufs.count = 0;
        ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS, &reqbufs);
        if (ret < 0) {
            return ret;
        }

        ret = vmedia_proxy_ioctl(session->host_fd, req, &fmt);
    }
    if (ret < 0) {
        return ret;
    }

    sizeimage = vmedia_format_sizeimage(&fmt);
    /*
     * Reject formats whose buffers won't fit our bounce pool. Only applies
     * when we back buffers from the pool: not in regrant-only mode (buffers
     * are re-granted from the host's dma-bufs, hostmem_size == 0) and never
     * for TRY_FMT, which must not allocate or fail with ENOMEM.
     */
    if (!is_try && !session->dev->regrant_only &&
        session->dev->host_v4l2_mem_mode != VMEDIA_HOST_V4L2_MEM_IMPORT &&
        session->dev->host_v4l2_mem_mode != VMEDIA_HOST_V4L2_MEM_IMPORT_UUID &&
        sizeimage &&
        (uint64_t)session->dev->max_buffers * sizeimage >
        session->dev->hostmem_size) {
        return -ENOMEM;
    }

    if (!is_try && session) {
        vmedia_proxy_release_buffers(session->dev, session);
        vmedia_reset_buffers(session);
        QTAILQ_INIT(&session->queued_buffers);
        session->streaming = false;
        session->mplane = (fmt.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
        session->buffer_size = sizeimage ? (uint32_t)sizeimage :
            VIRTIO_MEDIA_BUFFER_SIZE_SINGLE;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &fmt,
                               sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_reqbufs(VirtIOMedia *s, VirtIOMediaSession *session,
                                      const struct iovec *out_sg, int out_num,
                                      const struct iovec *in_sg, int in_num,
                                      size_t out_off, size_t in_off)
{
    struct v4l2_requestbuffers reqbufs;
    struct v4l2_requestbuffers host_reqbufs;
    struct v4l2_buffer buf;
    uint32_t host_memory;
    uint32_t i;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &reqbufs,
                              sizeof(reqbufs)) != sizeof(reqbufs)) {
        return -EINVAL;
    }

    if ((reqbufs.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
         reqbufs.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
        (reqbufs.memory != V4L2_MEMORY_MMAP &&
         !(reqbufs.memory == V4L2_MEMORY_DMABUF &&
           s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_IMPORT_UUID))) {
        return -EINVAL;
    }

    ret = vmedia_get_host_memory_mode(s, reqbufs.type, &host_memory);
    if (ret < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: host USERPTR not supported for queue type %u\n",
                      reqbufs.type);
        return ret;
    }

    reqbufs.count = MIN(reqbufs.count, s->max_buffers);

    /*
     * V4L2 single-owner queue semantics: once one handle owns the capture queue
     * (REQBUFS count>0), another handle's REQBUFS must fail with EBUSY until the
     * owner frees it (REQBUFS count=0 or close). v4l2-compliance buffers.cpp.
     */
    if (s->capture_owner_session_id != 0 &&
        s->capture_owner_session_id != session->id) {
        return -EBUSY;
    }

    /*
     * Report the queue's real capabilities and clear any client-supplied
     * flags. We back capture buffers with MMAP only (DMABUF export via EXPBUF
     * is separate from import support) and do not support cache hints, so
     * V4L2_MEMORY_FLAG_NON_COHERENT must never be reported back.
     *
     * The wire protocol's v4l2_requestbuffers always carries a flags word
     * (kernel >= 5.16). QEMU may be built against older UAPI headers where that
     * word is still named reserved[0]; clear it either way so the guest never
     * sees NON_COHERENT echoed back (v4l2-compliance buffers.cpp coherent test).
     */
    reqbufs.capabilities = V4L2_BUF_CAP_SUPPORTS_MMAP;
#ifdef CONFIG_V4L2_REQBUFS_FLAGS
    reqbufs.flags = 0;
#else
    reqbufs.reserved[0] = 0;
#endif

    vmedia_proxy_release_buffers(s, session);

    host_reqbufs = reqbufs;
    host_reqbufs.memory = host_memory;
    if (host_memory == V4L2_MEMORY_USERPTR) {
        host_reqbufs.count = 0;
    }
    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS, &host_reqbufs);
    if (ret < 0 && host_memory == V4L2_MEMORY_USERPTR &&
        s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_AUTO) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: USERPTR reqbufs failed (%d), falling back to MMAP\n",
                      ret);
        host_memory = V4L2_MEMORY_MMAP;
        host_reqbufs = reqbufs;
        host_reqbufs.memory = host_memory;
        ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS,
                                 &host_reqbufs);
    }
    if (ret < 0) {
        return ret;
    }

    session->host_memory = host_memory;
    session->mplane = (reqbufs.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
    session->buffer_size = VIRTIO_MEDIA_BUFFER_SIZE_SINGLE;
    session->host_num_planes = session->mplane ? 0 : 1;
    /*
     * Mode A: re-grant the host driver's own MMAP buffers to the guest instead
     * of mmap+memcpy. Requires Xen grant refs and host MMAP buffers.
     */
    session->host_regrant = s->use_grefs &&
        (((s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_REGRANT) &&
          host_memory == V4L2_MEMORY_MMAP) ||
         ((s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_IMPORT) &&
          host_memory == V4L2_MEMORY_DMABUF));
    session->host_import_uuid =
        (s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_IMPORT_UUID) &&
        host_memory == V4L2_MEMORY_DMABUF;
    if (host_memory == V4L2_MEMORY_MMAP || host_memory == V4L2_MEMORY_DMABUF) {
        session->host_num_buffers = host_reqbufs.count;
        reqbufs.count = host_reqbufs.count;
    } else {
        session->host_num_buffers = reqbufs.count;
    }

    if (reqbufs.count == 0) {
        vmedia_reset_buffers(session);
        /* Freeing the queue releases ownership if this session held it. */
        if (s->capture_owner_session_id == session->id) {
            s->capture_owner_session_id = 0;
        }
        if (vmedia_iov_write(in_sg, in_num, in_off, &reqbufs,
                                   sizeof(reqbufs)) != sizeof(reqbufs)) {
            return -EINVAL;
        }
        return 0;
    }

    /* count>0 succeeded: this session now owns the capture queue. */
    s->capture_owner_session_id = session->id;

    if (session->mplane) {
        struct v4l2_format fmt;

        memset(&fmt, 0, sizeof(fmt));
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
        if (vmedia_proxy_ioctl(session->host_fd, VIDIOC_G_FMT, &fmt) == 0 &&
            fmt.fmt.pix_mp.num_planes > 0) {
            session->host_num_planes = MIN(fmt.fmt.pix_mp.num_planes,
                                           (uint32_t)VIRTIO_MEDIA_MAX_PLANES);
            for (i = 0; i < session->host_num_planes; i++) {
                session->host_plane_lengths[i] =
                    fmt.fmt.pix_mp.plane_fmt[i].sizeimage;
            }
        } else {
            session->host_num_planes = 1;
        }
    } else {
        struct v4l2_format fmt;

        session->host_num_planes = 1;
        /*
         * Size the buffer from the host's actual capture format, not the
         * hardcoded default. Otherwise the mmap response advertises a stale
         * length and the guest's mmap() of a larger (e.g. 720p) buffer fails.
         */
        memset(&fmt, 0, sizeof(fmt));
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (vmedia_proxy_ioctl(session->host_fd, VIDIOC_G_FMT, &fmt) == 0) {
            uint64_t sz = vmedia_format_sizeimage(&fmt);

            if (sz) {
                session->buffer_size = (uint32_t)sz;
            }
        }
    }

    if (host_memory == V4L2_MEMORY_MMAP) {
        uint32_t nslots = reqbufs.count * session->host_num_planes;

        session->host_maps = g_new0(void *, nslots);
        session->host_lengths = g_new0(uint32_t, nslots);
        session->host_offsets = g_new0(uint32_t, nslots);

        if (session->host_regrant) {
            uint32_t k;

            session->host_dmabuf_fds = g_new0(int, nslots);
            session->host_import_fds = g_new0(int, nslots);
            session->host_gref_ids = g_new0(uint32_t *, nslots);
            session->host_gref_cnts = g_new0(uint32_t, nslots);
            for (k = 0; k < nslots; k++) {
                session->host_dmabuf_fds[k] = -1;
                session->host_import_fds[k] = -1;
            }
        } else {
            session->mr = g_new0(MemoryRegion, nslots);
        }

        for (i = 0; i < reqbufs.count; i++) {
            struct v4l2_plane planes[VIRTIO_MEDIA_MAX_PLANES];

            memset(&buf, 0, sizeof(buf));
            memset(planes, 0, sizeof(planes));
            buf.type = session->mplane ? V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE :
                                         V4L2_BUF_TYPE_VIDEO_CAPTURE;
            buf.memory = V4L2_MEMORY_MMAP;
            buf.index = i;
            if (session->mplane) {
                buf.length = session->host_num_planes;
                buf.m.planes = planes;
            }

            ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_QUERYBUF, &buf);
            if (ret < 0) {
                vmedia_proxy_release_buffers(s, session);
                memset(&host_reqbufs, 0, sizeof(host_reqbufs));
                host_reqbufs.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
                host_reqbufs.memory = V4L2_MEMORY_MMAP;
                vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS,
                                   &host_reqbufs);
                return ret;
            }

            if (session->mplane) {
                uint32_t p;

                for (p = 0; p < session->host_num_planes; p++) {
                    uint32_t idx = i * session->host_num_planes + p;

                    session->host_offsets[idx] = planes[p].m.mem_offset;
                    session->host_lengths[idx] = planes[p].length;

                    if (session->host_regrant) {
                        ret = vmedia_regrant_buffer_plane(session, i, p, idx,
                                                          planes[p].length);
                    } else {
                        session->host_maps[idx] = mmap(NULL, planes[p].length,
                                                       PROT_READ | PROT_WRITE,
                                                       MAP_SHARED,
                                                       session->host_fd,
                                                       planes[p].m.mem_offset);
                        ret = (session->host_maps[idx] == MAP_FAILED) ?
                            -errno : 0;
                        if (ret) {
                            session->host_maps[idx] = NULL;
                        }
                    }
                    if (ret) {
                        vmedia_proxy_release_buffers(s, session);
                        memset(&host_reqbufs, 0, sizeof(host_reqbufs));
                        host_reqbufs.type = session->mplane ?
                            V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE :
                            V4L2_BUF_TYPE_VIDEO_CAPTURE;
                        host_reqbufs.memory = V4L2_MEMORY_MMAP;
                        vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS,
                                           &host_reqbufs);
                        return ret;
                    }
                }
                if (i == 0) {
                    uint64_t total = 0;

                    for (p = 0; p < session->host_num_planes; p++) {
                        total += session->host_lengths[p];
                    }
                    session->buffer_size = total ? (uint32_t)total :
                        VIRTIO_MEDIA_BUFFER_SIZE_MPLANE;
                }
            } else {
                session->host_offsets[i] = buf.m.offset;
                session->host_lengths[i] = buf.length;

                if (session->host_regrant) {
                    ret = vmedia_regrant_buffer_plane(session, i, 0, i,
                                                      buf.length);
                } else {
                    session->host_maps[i] = mmap(NULL, buf.length,
                                                 PROT_READ | PROT_WRITE,
                                                 MAP_SHARED, session->host_fd,
                                                 buf.m.offset);
                    ret = (session->host_maps[i] == MAP_FAILED) ? -errno : 0;
                    if (ret) {
                        session->host_maps[i] = NULL;
                    }
                }
                if (ret) {
                    vmedia_proxy_release_buffers(s, session);
                    memset(&host_reqbufs, 0, sizeof(host_reqbufs));
                    host_reqbufs.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
                    host_reqbufs.memory = V4L2_MEMORY_MMAP;
                    vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS,
                                       &host_reqbufs);
                    return ret;
                }
                if (i == 0) {
                    session->buffer_size = buf.length;
                }
            }
        }

        if (session->mplane && session->host_num_planes) {
            uint32_t p;

            for (p = 0; p < session->host_num_planes; p++) {
                session->host_plane_lengths[p] = session->host_lengths[p];
            }
        }
    } else if (host_memory == V4L2_MEMORY_DMABUF && session->host_regrant) {
        /*
         * Import mode: back each capture buffer with a system-RAM dma-buf from
         * the dma-heap, grant its pages to the guest (zero-copy readback), and
         * drive the host device with V4L2_MEMORY_DMABUF.
         */
        uint32_t nslots = reqbufs.count * session->host_num_planes;
        uint32_t k;
        int heap_fd;

        session->host_maps = g_new0(void *, nslots);
        session->host_lengths = g_new0(uint32_t, nslots);
        session->host_offsets = g_new0(uint32_t, nslots);
        session->host_dmabuf_fds = g_new0(int, nslots);
        session->host_import_fds = g_new0(int, nslots);
        session->host_gref_ids = g_new0(uint32_t *, nslots);
        session->host_gref_cnts = g_new0(uint32_t, nslots);
        for (k = 0; k < nslots; k++) {
            session->host_dmabuf_fds[k] = -1;
            session->host_import_fds[k] = -1;
        }

        /*
         * Prefer the CMA dma-heap: its buffers are physically (and, on a
         * 1:1-mapped PVH dom0, machine-) contiguous, so a host capture device
         * driven via vb2-dma-contig/dma-sg can DMA into them directly
         * (nents==1).  The system heap is scattered and only works with a
         * vb2-vmalloc (CPU-copy) host import.  Fall back to system if there is
         * no CMA heap.
         */
        heap_fd = open("/dev/dma_heap/default_cma_region", O_RDWR | O_CLOEXEC);
        if (heap_fd < 0)
            heap_fd = open("/dev/dma_heap/system", O_RDWR | O_CLOEXEC);
        if (heap_fd < 0) {
            ret = -errno;
            qemu_log_mask(LOG_GUEST_ERROR,
                          "virtio-media: import open dma_heap failed: %d\n",
                          ret);
            vmedia_proxy_release_buffers(s, session);
            memset(&host_reqbufs, 0, sizeof(host_reqbufs));
            host_reqbufs.type = reqbufs.type;
            host_reqbufs.memory = V4L2_MEMORY_DMABUF;
            vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS, &host_reqbufs);
            return ret;
        }

        for (i = 0; i < reqbufs.count; i++) {
            uint32_t p;

            for (p = 0; p < session->host_num_planes; p++) {
                uint32_t idx = i * session->host_num_planes + p;
                uint32_t plen = session->mplane ?
                    session->host_plane_lengths[p] : session->buffer_size;
                int dfd = vmedia_dmaheap_alloc(heap_fd, plen);

                ret = (dfd < 0) ? dfd :
                    vmedia_grant_dmabuf(session, idx, dfd, plen);
                if (ret) {
                    close(heap_fd);
                    vmedia_proxy_release_buffers(s, session);
                    memset(&host_reqbufs, 0, sizeof(host_reqbufs));
                    host_reqbufs.type = reqbufs.type;
                    host_reqbufs.memory = V4L2_MEMORY_DMABUF;
                    vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS,
                                       &host_reqbufs);
                    return ret;
                }
            }
        }
        close(heap_fd);
    } else if (host_memory == V4L2_MEMORY_DMABUF && session->host_import_uuid) {
        /*
         * Import-UUID: the guest owns the buffers (its virtio-gpu blobs).
         * Allocate the host-fd table; each slot is filled by REGISTER_BUFFER
         * resolving the guest UUID -> host dmabuf via virtio_lookup_dmabuf.
         */
        uint32_t nslots = reqbufs.count * session->host_num_planes;
        uint32_t k;

        session->host_dmabuf_fds = g_new0(int, nslots);
        /*
         * host_lengths must be allocated here too: the QBUF path reads
         * session->host_lengths[index] for DMABUF buffers.  Without it that
         * deref is NULL[0] -> segfault.  The guest owns the buffers (venus
         * blobs); size them from the negotiated capture format.
         */
        session->host_lengths = g_new0(uint32_t, nslots);
        for (k = 0; k < nslots; k++) {
            session->host_dmabuf_fds[k] = -1;
            session->host_lengths[k] = session->buffer_size;
        }
    }

    ret = vmedia_alloc_buffers(s, session, reqbufs.count);
    if (ret < 0) {
        vmedia_proxy_release_buffers(s, session);
        memset(&host_reqbufs, 0, sizeof(host_reqbufs));
        host_reqbufs.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        host_reqbufs.memory = session->host_memory;
        vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS, &host_reqbufs);
        return ret;
    }

    reqbufs.count = session->num_buffers;
    if (vmedia_iov_write(in_sg, in_num, in_off, &reqbufs,
                               sizeof(reqbufs)) != sizeof(reqbufs)) {
        return -EINVAL;
    }

    if (s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_MMAP) {
        for (i = 0; i < reqbufs.count; i++) {
            memory_region_init_ram_ptr(&session->mr[i], OBJECT(&s->hostmem),
                                       "mmap-mr",
                                       session->host_lengths[i],
                                       session->host_maps[i]);
            memory_region_add_subregion_overlap(&s->hostmem,
                                                session->buffers[i].base_offset,
                                                &session->mr[i], 1);
        }
    }

    return 0;
}

static int vmedia_proxy_querybuf(VirtIOMediaSession *session,
                                 const struct iovec *out_sg, int out_num,
                                 const struct iovec *in_sg, int in_num,
                                 size_t out_off, size_t in_off,
                                 size_t *payload_len)
{
    struct v4l2_buffer buf;
    struct v4l2_plane planes[VIRTIO_MEDIA_MAX_PLANES];
    uint32_t index;
    uint32_t length;
    uint32_t i;

    if (vmedia_iov_read(out_sg, out_num, out_off, &buf,
                        sizeof(buf)) != sizeof(buf)) {
        return -EINVAL;
    }

    index = buf.index;
    length = buf.length;
    /*
     * QUERYBUF must not validate the memory field: callers (e.g.
     * v4l2-compliance) may pass 0. We always back buffers with MMAP, so
     * report that in the reply regardless of what was requested.
     */
    if ((buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
         buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
        index >= session->num_buffers) {
        return -EINVAL;
    }
    buf.memory = V4L2_MEMORY_MMAP;

    if (session->mplane != (buf.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)) {
        return -EINVAL;
    }

    if (buf.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        if (length < session->buffers[index].buffer.length) {
            return -EINVAL;
        }
        if (vmedia_read_planes(out_sg, out_num,
                               out_off + sizeof(buf),
                               planes, session->buffers[index].buffer.length)) {
            return -EINVAL;
        }

        uint32_t buf_planes = session->buffers[index].buffer.length;

        for (i = 0; i < buf_planes; i++) {
            planes[i].length = session->buffers[index].plane_lengths[i];
            planes[i].bytesused = 0;
            planes[i].m.mem_offset = session->buffers[index].plane_offsets[i];
        }

        buf.length = buf_planes;
        buf.bytesused = 0;
        buf.flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;

        if (vmedia_iov_write(in_sg, in_num, in_off, &buf,
                             sizeof(buf)) != sizeof(buf)) {
            return -EINVAL;
        }
        if (vmedia_write_planes(in_sg, in_num,
                                in_off + sizeof(buf),
                                planes, buf_planes)) {
            return -EINVAL;
        }
        *payload_len = sizeof(struct v4l2_buffer) +
            sizeof(struct v4l2_plane) * buf_planes;
    } else {
        buf.length = session->buffers[index].plane_lengths[0];
        buf.bytesused = 0;
        buf.flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
        buf.m.offset = session->buffers[index].plane_offsets[0];

        if (vmedia_iov_write(in_sg, in_num, in_off, &buf,
                             sizeof(buf)) != sizeof(buf)) {
            return -EINVAL;
        }
        *payload_len = sizeof(struct v4l2_buffer);
    }

    return 0;
}

static int vmedia_proxy_qbuf(VirtIOMedia *s, VirtIOMediaSession *session,
                                   const struct iovec *out_sg, int out_num,
                                   const struct iovec *in_sg, int in_num,
                                   size_t out_off, size_t in_off,
                                   size_t *payload_len)
{
    struct v4l2_buffer buf;
    struct v4l2_buffer host_buf;
    struct v4l2_plane planes[VIRTIO_MEDIA_MAX_PLANES];
    uint32_t index;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &buf,
                              sizeof(buf)) != sizeof(buf)) {
        qemu_log_mask(LOG_GUEST_ERROR, "virtio-media: qbuf iov_read failed\n");
        return -EINVAL;
    }

    if ((buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
         buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
        (buf.memory != V4L2_MEMORY_MMAP &&
         !(buf.memory == V4L2_MEMORY_DMABUF &&
           s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_IMPORT_UUID))) {
        return -EINVAL;
    }

    if (session->mplane != (buf.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)) {
        return -EINVAL;
    }

    index = buf.index;
    if (index >= session->num_buffers || index >= session->host_num_buffers) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: qbuf bad index %u (num=%u host=%u)\n",
                      index, session->num_buffers, session->host_num_buffers);
        return -EINVAL;
    }

    if (session->buffers[index].queued) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: qbuf idx=%u already queued (session=%u)\n",
                      index, session->id);
        return -EINVAL;
    }

    memset(&host_buf, 0, sizeof(host_buf));
    host_buf.type = session->mplane ? V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE :
                                      V4L2_BUF_TYPE_VIDEO_CAPTURE;
    host_buf.memory = session->host_memory;
    host_buf.index = index;
    if (session->mplane) {
        if (!session->host_num_planes ||
            buf.length < session->host_num_planes) {
            return -EINVAL;
        }
        if (vmedia_read_planes(out_sg, out_num,
                               out_off + sizeof(buf),
                               planes, session->host_num_planes)) {
            return -EINVAL;
        }
        host_buf.length = session->host_num_planes;
        host_buf.m.planes = planes;
        for (uint32_t p = 0; p < session->host_num_planes; p++) {
            uint32_t idx = index * session->host_num_planes + p;

            if (session->host_memory == V4L2_MEMORY_MMAP) {
                planes[p].length = session->host_lengths[idx];
                planes[p].m.mem_offset = session->host_offsets[idx];
            } else if (session->host_memory == V4L2_MEMORY_DMABUF) {
                planes[p].length = session->host_lengths[idx];
                planes[p].m.fd = session->host_dmabuf_fds[idx];
            } else {
                planes[p].length = session->buffers[index].plane_lengths[p];
                planes[p].m.userptr =
                    (unsigned long)(uintptr_t)
                    (vmedia_hostmem_base(s) +
                     session->buffers[index].plane_offsets[p]);
            }
        }
    } else if (session->host_memory == V4L2_MEMORY_USERPTR) {
        host_buf.length = session->buffers[index].plane_lengths[0];
        host_buf.m.userptr =
            (unsigned long)(uintptr_t)
            (vmedia_hostmem_base(s) +
             session->buffers[index].plane_offsets[0]);
    } else if (session->host_memory == V4L2_MEMORY_DMABUF) {
        host_buf.length = session->host_lengths[index];
        host_buf.m.fd = session->host_dmabuf_fds[index];
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_QBUF, &host_buf);
    if (ret < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: host qbuf failed ret=%d session=%u idx=%u type=%u mplane=%d len=%u flags=0x%x bytesused=%u\n",
                      ret, session->id, index, host_buf.type, session->mplane,
                      host_buf.length, host_buf.flags, host_buf.bytesused);
        if (session->mplane && session->host_num_planes) {
            for (uint32_t p = 0; p < session->host_num_planes; p++) {
                if (session->host_memory == V4L2_MEMORY_MMAP) {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                  "virtio-media: host qbuf plane[%u] mem_offset=0x%x length=%u bytesused=%u data_offset=%u\n",
                                  p, planes[p].m.mem_offset, planes[p].length,
                                  planes[p].bytesused, planes[p].data_offset);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                  "virtio-media: host qbuf plane[%u] userptr=0x%lx length=%u bytesused=%u data_offset=%u\n",
                                  p, planes[p].m.userptr, planes[p].length,
                                  planes[p].bytesused, planes[p].data_offset);
                }
            }
        } else {
            if (session->host_memory == V4L2_MEMORY_MMAP) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "virtio-media: host qbuf single mem_offset=0x%x\n",
                              host_buf.m.offset);
            } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "virtio-media: host qbuf single userptr=0x%lx len=%u\n",
                              host_buf.m.userptr, host_buf.length);
            }
        }
        return ret;
    }

    session->buffers[index].queued = true;

    /*
     * Report the buffer back as QUEUED with our timestamp source. Strip any
     * client-supplied flags (e.g. cache hints) we do not support, otherwise
     * v4l2-compliance sees them echoed back and fails.
     */
    buf.flags = V4L2_BUF_FLAG_QUEUED | V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;

    if (vmedia_iov_write(in_sg, in_num, in_off, &buf,
                               sizeof(buf)) != sizeof(buf)) {
        return -EINVAL;
    }
    if (session->mplane) {
        if (vmedia_write_planes(in_sg, in_num,
                                in_off + sizeof(buf),
                                planes, session->host_num_planes)) {
            return -EINVAL;
        }
        *payload_len = sizeof(struct v4l2_buffer) +
            sizeof(struct v4l2_plane) * session->host_num_planes;
    } else {
        *payload_len = sizeof(struct v4l2_buffer);
    }
    return 0;
}

static int vmedia_proxy_streamon(VirtIOMedia *s, VirtIOMediaSession *session,
                                       const struct iovec *out_sg, int out_num,
                                       size_t out_off)
{
    uint32_t type;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &type,
                              sizeof(type)) != sizeof(type)) {
        return -EINVAL;
    }

    if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }
    if (session->mplane != (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)) {
        return -EINVAL;
    }

    /*
     * V4L2 requires STREAMON to fail with EINVAL when no buffers have been
     * allocated (REQBUFS count==0). Buffers that are allocated but not yet
     * queued are fine: STREAMON must still succeed (v4l2-compliance
     * buffers.cpp testBlockingDQBuf reqbufs(2)+streamon, vs the empty-queue
     * EINVAL check after reqbufs(0)).
     */
    if (session->num_buffers == 0) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_STREAMON, &type);
    if (ret < 0) {
        return ret;
    }

    session->host_streaming = true;
    session->streaming = true;
    vmedia_set_host_handler(session, true);
    return 0;
}

static int vmedia_proxy_streamoff(VirtIOMedia *s, VirtIOMediaSession *session,
                                        const struct iovec *out_sg, int out_num,
                                        size_t out_off)
{
    uint32_t type;
    int ret;
    uint32_t i;

    if (vmedia_iov_read(out_sg, out_num, out_off, &type,
                              sizeof(type)) != sizeof(type)) {
        return -EINVAL;
    }

    if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }
    if (session->mplane != (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_STREAMOFF, &type);
    if (ret < 0) {
        return ret;
    }

    session->host_streaming = false;
    session->streaming = false;
    vmedia_set_host_handler(session, false);
    QTAILQ_INIT(&session->queued_buffers);
    for (i = 0; i < session->num_buffers; i++) {
        session->buffers[i].queued = false;
    }
    return 0;
}

static int vmedia_proxy_queryctrl(VirtIOMediaSession *session,
                                        const struct iovec *out_sg, int out_num,
                                        const struct iovec *in_sg, int in_num,
                                        size_t out_off, size_t in_off)
{
    struct v4l2_queryctrl ctrl;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &ctrl,
                              sizeof(ctrl)) != sizeof(ctrl)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_QUERYCTRL, &ctrl);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &ctrl,
                               sizeof(ctrl)) != sizeof(ctrl)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_g_ctrl(VirtIOMediaSession *session,
                                     const struct iovec *out_sg, int out_num,
                                     const struct iovec *in_sg, int in_num,
                                     size_t out_off, size_t in_off)
{
    struct v4l2_control ctrl;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &ctrl,
                              sizeof(ctrl)) != sizeof(ctrl)) {
        return -EINVAL;
    }

    /*
     * The V4L2 API requires G_CTRL on a write-only control to fail with
     * EACCES. Some host drivers return EINVAL instead, so enforce it here by
     * querying the control's flags first.
     */
    {
        struct v4l2_queryctrl qc;

        memset(&qc, 0, sizeof(qc));
        qc.id = ctrl.id;
        if (vmedia_proxy_ioctl(session->host_fd, VIDIOC_QUERYCTRL, &qc) == 0 &&
            (qc.flags & V4L2_CTRL_FLAG_WRITE_ONLY)) {
            return -EACCES;
        }
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_G_CTRL, &ctrl);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &ctrl,
                               sizeof(ctrl)) != sizeof(ctrl)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_s_ctrl(VirtIOMediaSession *session,
                                     const struct iovec *out_sg, int out_num,
                                     const struct iovec *in_sg, int in_num,
                                     size_t out_off, size_t in_off)
{
    struct v4l2_control ctrl;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &ctrl,
                              sizeof(ctrl)) != sizeof(ctrl)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_S_CTRL, &ctrl);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &ctrl,
                               sizeof(ctrl)) != sizeof(ctrl)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_querymenu(VirtIOMediaSession *session,
                                        const struct iovec *out_sg, int out_num,
                                        const struct iovec *in_sg, int in_num,
                                        size_t out_off, size_t in_off)
{
    struct v4l2_querymenu menu;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &menu,
                              sizeof(menu)) != sizeof(menu)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_QUERYMENU, &menu);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &menu,
                               sizeof(menu)) != sizeof(menu)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_cropcap(VirtIOMediaSession *session,
                                      const struct iovec *out_sg, int out_num,
                                      const struct iovec *in_sg, int in_num,
                                      size_t out_off, size_t in_off)
{
    struct v4l2_cropcap cap;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &cap,
                              sizeof(cap)) != sizeof(cap)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_CROPCAP, &cap);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &cap,
                               sizeof(cap)) != sizeof(cap)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_crop(VirtIOMediaSession *session, bool is_set,
                                   const struct iovec *out_sg, int out_num,
                                   const struct iovec *in_sg, int in_num,
                                   size_t out_off, size_t in_off)
{
    struct v4l2_crop crop;
    unsigned long req = is_set ? VIDIOC_S_CROP : VIDIOC_G_CROP;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &crop,
                              sizeof(crop)) != sizeof(crop)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, req, &crop);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &crop,
                               sizeof(crop)) != sizeof(crop)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_selection(VirtIOMediaSession *session, bool is_set,
                                        const struct iovec *out_sg, int out_num,
                                        const struct iovec *in_sg, int in_num,
                                        size_t out_off, size_t in_off)
{
    struct v4l2_selection sel;
    unsigned long req = is_set ? VIDIOC_S_SELECTION : VIDIOC_G_SELECTION;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &sel,
                              sizeof(sel)) != sizeof(sel)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, req, &sel);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &sel,
                               sizeof(sel)) != sizeof(sel)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_parm(VirtIOMediaSession *session,
                             bool is_set,
                             const struct iovec *out_sg, int out_num,
                             const struct iovec *in_sg, int in_num,
                             size_t out_off, size_t in_off)
{
    struct v4l2_streamparm parm;
    unsigned long req = is_set ? VIDIOC_S_PARM : VIDIOC_G_PARM;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &parm,
                              sizeof(parm)) != sizeof(parm)) {
        return -EINVAL;
    }

    /*
     * Clear reserved fields before forwarding S_PARM: we implement no reserved
     * semantics, and a client may pass garbage there (v4l2-compliance sets them
     * to 0xff). The host driver could reject nonzero reserved bytes, which must
     * not make a valid S_PARM fail.
     */
    if (is_set) {
        if (parm.type == V4L2_BUF_TYPE_VIDEO_CAPTURE ||
            parm.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
            memset(parm.parm.capture.reserved, 0,
                   sizeof(parm.parm.capture.reserved));
        } else if (parm.type == V4L2_BUF_TYPE_VIDEO_OUTPUT ||
                   parm.type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
            memset(parm.parm.output.reserved, 0,
                   sizeof(parm.parm.output.reserved));
        }
    }

    ret = vmedia_proxy_ioctl(session->host_fd, req, &parm);
    if (ret < 0) {
        return ret;
    }

    /*
     * We do not advertise V4L2_CAP_READWRITE, so readbuffers (the number of
     * buffers used for read()) must be reported as 0. The host driver may set
     * a non-zero value; clear it to match our advertised capabilities.
     */
    if (parm.type == V4L2_BUF_TYPE_VIDEO_CAPTURE ||
        parm.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        parm.parm.capture.readbuffers = 0;
    } else if (parm.type == V4L2_BUF_TYPE_VIDEO_OUTPUT ||
               parm.type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
        parm.parm.output.writebuffers = 0;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &parm,
                               sizeof(parm)) != sizeof(parm)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_enum_framesizes(VirtIOMediaSession *session,
                                        const struct iovec *out_sg, int out_num,
                                        const struct iovec *in_sg, int in_num,
                                        size_t out_off, size_t in_off)
{
    struct v4l2_frmsizeenum frmsize;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &frmsize,
                              sizeof(frmsize)) != sizeof(frmsize)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_ENUM_FRAMESIZES,
                             &frmsize);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &frmsize,
                               sizeof(frmsize)) != sizeof(frmsize)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_enum_frameintervals(VirtIOMediaSession *session,
                                            const struct iovec *out_sg,
                                            int out_num,
                                            const struct iovec *in_sg,
                                            int in_num,
                                            size_t out_off,
                                            size_t in_off)
{
    struct v4l2_frmivalenum frmival;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &frmival,
                              sizeof(frmival)) != sizeof(frmival)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_ENUM_FRAMEINTERVALS,
                             &frmival);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &frmival,
                               sizeof(frmival)) != sizeof(frmival)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_query_ext_ctrl(VirtIOMediaSession *session,
                                       const struct iovec *out_sg, int out_num,
                                       const struct iovec *in_sg, int in_num,
                                       size_t out_off, size_t in_off)
{
    struct v4l2_query_ext_ctrl ctrl;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &ctrl,
                              sizeof(ctrl)) != sizeof(ctrl)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_QUERY_EXT_CTRL, &ctrl);
    if (ret < 0) {
        return ret;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &ctrl,
                               sizeof(ctrl)) != sizeof(ctrl)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_proxy_ext_ctrls(VirtIOMediaSession *session,
                                  unsigned long req,
                                  const struct iovec *out_sg,
                                  int out_num,
                                  const struct iovec *in_sg,
                                  int in_num,
                                  size_t out_off,
                                  size_t in_off,
                                  size_t *payload_len)
{
    struct v4l2_ext_controls ctrls;
    struct v4l2_ext_control *controls;
    uint64_t orig_controls_ptr;
    uint64_t *orig_ptrs = NULL;
    uint8_t *buf = NULL;
    uint8_t *data_ptr;
    size_t total;
    size_t data_size = 0;
    size_t i;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &ctrls,
                              sizeof(ctrls)) != sizeof(ctrls)) {
        return -EINVAL;
    }

    if (ctrls.count == 0) {
        total = sizeof(ctrls);
        buf = g_malloc0(total);
        memcpy(buf, &ctrls, sizeof(ctrls));
    } else {
        size_t controls_size;
        size_t base;
        size_t out_len = iov_size(out_sg, out_num);

        if (ctrls.count > VIRTIO_MEDIA_MAX_EXT_CTRLS) {
            return -EINVAL;
        }

        controls_size = ctrls.count * sizeof(*controls);
        base = sizeof(ctrls) + controls_size;

        if (out_len < out_off + base) {
            return -EINVAL;
        }

        controls = g_malloc0(controls_size);
        if (vmedia_iov_read(out_sg, out_num, out_off + sizeof(ctrls),
                                  controls, controls_size) != controls_size) {
            g_free(controls);
            return -EINVAL;
        }

        for (i = 0; i < ctrls.count; i++) {
            if (controls[i].size > VIRTIO_MEDIA_MAX_EXT_CTRL_SIZE) {
                g_free(controls);
                return -EINVAL;
            }
            data_size += controls[i].size;
        }
        g_free(controls);

        total = base + data_size;
        buf = g_malloc0(total);
        if (vmedia_iov_read(out_sg, out_num, out_off,
                                  buf, total) != total) {
            g_free(buf);
            return -EINVAL;
        }
    }

    ctrls = *(struct v4l2_ext_controls *)buf;
    controls = (struct v4l2_ext_control *)(buf + sizeof(ctrls));
    orig_controls_ptr = (uint64_t)(uintptr_t)ctrls.controls;
    ctrls.controls = controls;
    *(struct v4l2_ext_controls *)buf = ctrls;

    if (ctrls.count) {
        orig_ptrs = g_new0(uint64_t, ctrls.count);
        data_ptr = buf + sizeof(ctrls) + ctrls.count * sizeof(*controls);
        for (i = 0; i < ctrls.count; i++) {
            if (controls[i].size) {
                orig_ptrs[i] = (uint64_t)controls[i].ptr;
                controls[i].ptr = data_ptr;
                data_ptr += controls[i].size;
            }
        }
    }

    /*
     * The V4L2 API requires access-flag checks the host driver may not enforce:
     *   - G_EXT_CTRLS on a write-only control fails with EACCES
     *   - TRY/S_EXT_CTRLS on a read-only control fails with EACCES
     * The error_idx convention differs: TRY_EXT_CTRLS reports the offending
     * index, while G/S_EXT_CTRLS report count. Some host drivers return EINVAL
     * instead, so enforce it here by checking each control's flags first.
     */
    if (ctrls.count) {
        bool is_get = (req == VIDIOC_G_EXT_CTRLS);
        bool is_try = (req == VIDIOC_TRY_EXT_CTRLS);
        uint32_t bad_flag = is_get ? V4L2_CTRL_FLAG_WRITE_ONLY :
                                     V4L2_CTRL_FLAG_READ_ONLY;

        for (i = 0; i < ctrls.count; i++) {
            struct v4l2_queryctrl qc;

            memset(&qc, 0, sizeof(qc));
            qc.id = controls[i].id;
            if (vmedia_proxy_ioctl(session->host_fd, VIDIOC_QUERYCTRL,
                                   &qc) == 0 &&
                (qc.flags & bad_flag)) {
                ctrls = *(struct v4l2_ext_controls *)buf;
                ctrls.error_idx = is_try ? (uint32_t)i : ctrls.count;
                ctrls.controls =
                    (struct v4l2_ext_control *)(uintptr_t)orig_controls_ptr;
                if (vmedia_iov_write(in_sg, in_num, in_off, &ctrls,
                                     sizeof(ctrls)) != sizeof(ctrls)) {
                    g_free(orig_ptrs);
                    g_free(buf);
                    return -EINVAL;
                }
                *payload_len = sizeof(ctrls);
                g_free(orig_ptrs);
                g_free(buf);
                return -EACCES;
            }
        }
    }

    ret = vmedia_proxy_ioctl(session->host_fd, req, buf);
    if (ret < 0) {
        /*
         * TRY_EXT_CTRLS must report error_idx as the offending control's index
         * (0 for the first), but the host typically sets it to count. Rewrite
         * it and return the payload so the guest sees the right index.
         */
        if (req == VIDIOC_TRY_EXT_CTRLS && ret == -EINVAL) {
            ctrls = *(struct v4l2_ext_controls *)buf;
            ctrls.error_idx = 0;
            ctrls.controls =
                (struct v4l2_ext_control *)(uintptr_t)orig_controls_ptr;
            if (vmedia_iov_write(in_sg, in_num, in_off, &ctrls,
                                 sizeof(ctrls)) == sizeof(ctrls)) {
                *payload_len = sizeof(ctrls);
            }
        }
        g_free(orig_ptrs);
        g_free(buf);
        return ret;
    }

    ctrls = *(struct v4l2_ext_controls *)buf;
    controls = (struct v4l2_ext_control *)(buf + sizeof(ctrls));
    ctrls.controls = (struct v4l2_ext_control *)(uintptr_t)orig_controls_ptr;
    *(struct v4l2_ext_controls *)buf = ctrls;

    if (ctrls.count && orig_ptrs) {
        for (i = 0; i < ctrls.count; i++) {
            if (controls[i].size) {
                controls[i].ptr = (void *)(uintptr_t)orig_ptrs[i];
            }
        }
    }

    if (vmedia_iov_write(in_sg, in_num, in_off,
                               buf, total) != total) {
        g_free(orig_ptrs);
        g_free(buf);
        return -EINVAL;
    }

    *payload_len = total;
    g_free(orig_ptrs);
    g_free(buf);
    return 0;
}

static int vmedia_ioctl_enum_fmt(VirtIOMediaSession *session,
                                       const struct iovec *out_sg, int out_num,
                                       const struct iovec *in_sg, int in_num,
                                       size_t out_off, size_t in_off)
{
    struct v4l2_fmtdesc desc;

    (void)session;

    if (vmedia_iov_read(out_sg, out_num, out_off, &desc,
                              sizeof(desc)) != sizeof(desc)) {
        return -EINVAL;
    }

    if (desc.index != 0 ||
        (desc.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
         desc.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)) {
        return -EINVAL;
    }

    vmedia_fill_fmtdesc(&desc, desc.type);

    if (vmedia_iov_write(in_sg, in_num, in_off, &desc,
                               sizeof(desc)) != sizeof(desc)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_ioctl_g_fmt(const struct iovec *out_sg, int out_num,
                                    const struct iovec *in_sg, int in_num,
                                    size_t out_off, size_t in_off)
{
    struct v4l2_format fmt;

    if (vmedia_iov_read(out_sg, out_num, out_off, &fmt,
                              sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    if (fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    vmedia_fill_format(&fmt, fmt.type);
    if (vmedia_iov_write(in_sg, in_num, in_off, &fmt,
                               sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_ioctl_s_fmt(const struct iovec *out_sg, int out_num,
                                    const struct iovec *in_sg, int in_num,
                                    size_t out_off, size_t in_off)
{
    struct v4l2_format fmt;

    if (vmedia_iov_read(out_sg, out_num, out_off, &fmt,
                              sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    if (fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    if (fmt.type == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
        if (fmt.fmt.pix.pixelformat != VIRTIO_MEDIA_PIXFMT_SINGLE) {
            return -EINVAL;
        }
    } else {
        if (fmt.fmt.pix_mp.pixelformat != VIRTIO_MEDIA_PIXFMT_MPLANE) {
            return -EINVAL;
        }
    }

    vmedia_fill_format(&fmt, fmt.type);
    if (vmedia_iov_write(in_sg, in_num, in_off, &fmt,
                               sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_ioctl_reqbufs(VirtIOMedia *s, VirtIOMediaSession *session,
                                      const struct iovec *out_sg, int out_num,
                                      const struct iovec *in_sg, int in_num,
                                      size_t out_off, size_t in_off)
{
    struct v4l2_requestbuffers reqbufs;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &reqbufs,
                              sizeof(reqbufs)) != sizeof(reqbufs)) {
        return -EINVAL;
    }

    if ((reqbufs.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
         reqbufs.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
        reqbufs.memory != V4L2_MEMORY_MMAP) {
        return -EINVAL;
    }

    session->mplane = (reqbufs.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
    session->buffer_size = session->mplane ?
        VIRTIO_MEDIA_BUFFER_SIZE_MPLANE : VIRTIO_MEDIA_BUFFER_SIZE_SINGLE;

    ret = vmedia_alloc_buffers(s, session, reqbufs.count);
    if (ret < 0) {
        return ret;
    }

    reqbufs.count = session->num_buffers;
    if (vmedia_iov_write(in_sg, in_num, in_off, &reqbufs,
                               sizeof(reqbufs)) != sizeof(reqbufs)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_ioctl_querybuf(VirtIOMediaSession *session,
                                       const struct iovec *out_sg, int out_num,
                                       const struct iovec *in_sg, int in_num,
                                       size_t out_off, size_t in_off,
                                       size_t *payload_len)
{
    struct v4l2_buffer buf;
    struct v4l2_plane planes[3];
    uint32_t index;
    uint32_t length;
    uint32_t i;

    if (vmedia_iov_read(out_sg, out_num, out_off, &buf,
                              sizeof(buf)) != sizeof(buf)) {
        return -EINVAL;
    }

    index = buf.index;
    length = buf.length;
    /* QUERYBUF must not validate the memory field; report MMAP in the reply. */
    if ((buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
         buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
        index >= session->num_buffers) {
        return -EINVAL;
    }
    buf.memory = V4L2_MEMORY_MMAP;

    if (buf.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        if (!session->mplane || length < 3) {
            return -EINVAL;
        }
        if (vmedia_read_planes(out_sg, out_num,
                                     out_off + sizeof(buf),
                                     planes, 3)) {
            return -EINVAL;
        }

        for (i = 0; i < 3; i++) {
            planes[i].length = session->buffers[index].plane_lengths[i];
            planes[i].bytesused = 0;
            planes[i].m.mem_offset = session->buffers[index].plane_offsets[i];
        }

        buf.length = 3;
        buf.bytesused = 0;
        buf.flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;

        if (vmedia_iov_write(in_sg, in_num, in_off, &buf,
                                   sizeof(buf)) != sizeof(buf)) {
            return -EINVAL;
        }
        if (vmedia_write_planes(in_sg, in_num,
                                      in_off + sizeof(buf),
                                      planes, 3)) {
            return -EINVAL;
        }
        *payload_len = sizeof(struct v4l2_buffer) +
                       sizeof(struct v4l2_plane) * 3;
    } else {
        if (session->mplane) {
            return -EINVAL;
        }
        buf.length = session->buffer_size;
        buf.bytesused = 0;
        buf.flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
        buf.m.offset = session->buffers[index].plane_offsets[0];

        if (vmedia_iov_write(in_sg, in_num, in_off, &buf,
                                   sizeof(buf)) != sizeof(buf)) {
            return -EINVAL;
        }
        *payload_len = sizeof(struct v4l2_buffer);
    }

    return 0;
}

static int vmedia_ioctl_qbuf(VirtIOMedia *s, VirtIOMediaSession *session,
                                   const struct iovec *out_sg, int out_num,
                                   const struct iovec *in_sg, int in_num,
                                   size_t out_off, size_t in_off,
                                   size_t *payload_len)
{
    struct v4l2_buffer buf;
    struct v4l2_plane planes[3];
    uint32_t index;
    uint32_t length;

    if (vmedia_iov_read(out_sg, out_num, out_off, &buf,
                              sizeof(buf)) != sizeof(buf)) {
        return -EINVAL;
    }

    index = buf.index;
    length = buf.length;
    if ((buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
         buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
        buf.memory != V4L2_MEMORY_MMAP ||
        index >= session->num_buffers) {
        return -EINVAL;
    }

    if (buf.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        if (!session->mplane || length < 3) {
            return -EINVAL;
        }
        if (vmedia_read_planes(out_sg, out_num,
                                     out_off + sizeof(buf),
                                     planes, 3)) {
            return -EINVAL;
        }
    }

    if (session->buffers[index].queued) {
        return -EINVAL;
    }

    if (buf.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        memcpy(session->buffers[index].planes, planes, sizeof(planes));
        session->buffers[index].planes[0].m.mem_offset =
            session->buffers[index].plane_offsets[0];
        session->buffers[index].planes[1].m.mem_offset =
            session->buffers[index].plane_offsets[1];
        session->buffers[index].planes[2].m.mem_offset =
            session->buffers[index].plane_offsets[2];
        session->buffers[index].planes[0].length =
            session->buffers[index].plane_lengths[0];
        session->buffers[index].planes[1].length =
            session->buffers[index].plane_lengths[1];
        session->buffers[index].planes[2].length =
            session->buffers[index].plane_lengths[2];
    }
    session->buffers[index].queued = true;

    QTAILQ_INSERT_TAIL(&session->queued_buffers,
                       &session->buffers[index], next);

    if (session->streaming) {
        VirtIOMediaBuffer *qbuf = QTAILQ_FIRST(&session->queued_buffers);
        QTAILQ_REMOVE(&session->queued_buffers, qbuf, next);
        qbuf->queued = false;
        vmedia_generate_frame(s, session, qbuf);
        vmedia_share_sync_for_buffer(s, session, qbuf->index);
        vmedia_emit_dqbuf(s, session, qbuf);
        vmedia_flush_events(s);
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &buf,
                               sizeof(buf)) != sizeof(buf)) {
        return -EINVAL;
    }
    if (buf.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        if (vmedia_write_planes(in_sg, in_num,
                                      in_off + sizeof(buf),
                                      planes, 3)) {
            return -EINVAL;
        }
        *payload_len = sizeof(struct v4l2_buffer) +
                       sizeof(struct v4l2_plane) * 3;
    } else {
        *payload_len = sizeof(struct v4l2_buffer);
    }

    return 0;
}

static int vmedia_ioctl_streamon(VirtIOMedia *s, VirtIOMediaSession *session,
                                       const struct iovec *out_sg, int out_num,
                                       size_t out_off)
{
    uint32_t type;

    if (vmedia_iov_read(out_sg, out_num, out_off, &type,
                              sizeof(type)) != sizeof(type)) {
        return -EINVAL;
    }

    if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    if (session->mplane != (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)) {
        return -EINVAL;
    }

    session->streaming = true;
    while (!QTAILQ_EMPTY(&session->queued_buffers)) {
        VirtIOMediaBuffer *qbuf = QTAILQ_FIRST(&session->queued_buffers);
        QTAILQ_REMOVE(&session->queued_buffers, qbuf, next);
        qbuf->queued = false;
        vmedia_generate_frame(s, session, qbuf);
        vmedia_share_sync_for_buffer(s, session, qbuf->index);
        vmedia_emit_dqbuf(s, session, qbuf);
    }
    vmedia_flush_events(s);
    return 0;
}

static int vmedia_ioctl_streamoff(VirtIOMediaSession *session,
                                        const struct iovec *out_sg, int out_num,
                                        size_t out_off)
{
    uint32_t type;
    uint32_t i;

    if (vmedia_iov_read(out_sg, out_num, out_off, &type,
                              sizeof(type)) != sizeof(type)) {
        return -EINVAL;
    }

    if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
        type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    if (session->mplane != (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)) {
        return -EINVAL;
    }

    session->streaming = false;
    QTAILQ_INIT(&session->queued_buffers);
    for (i = 0; i < session->num_buffers; i++) {
        session->buffers[i].queued = false;
    }
    return 0;
}

static int vmedia_ioctl_enuminput(const struct iovec *out_sg, int out_num,
                                        const struct iovec *in_sg, int in_num,
                                        size_t out_off, size_t in_off)
{
    struct v4l2_input input;

    if (vmedia_iov_read(out_sg, out_num, out_off, &input,
                              sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    if (input.index != 0) {
        return -EINVAL;
    }

    memset(&input, 0, sizeof(input));
    input.index = 0;
    input.type = V4L2_INPUT_TYPE_CAMERA;
    snprintf((char *)input.name, sizeof(input.name), "Default");

    if (vmedia_iov_write(in_sg, in_num, in_off, &input,
                               sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_ioctl_g_input(const struct iovec *in_sg, int in_num,
                                      size_t in_off)
{
    uint32_t input = 0;

    if (vmedia_iov_write(in_sg, in_num, in_off, &input,
                               sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_ioctl_s_input(const struct iovec *out_sg, int out_num,
                                      const struct iovec *in_sg, int in_num,
                                      size_t out_off, size_t in_off)
{
    uint32_t input;

    if (vmedia_iov_read(out_sg, out_num, out_off, &input,
                              sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    if (input != 0) {
        return -EINVAL;
    }

    if (vmedia_iov_write(in_sg, in_num, in_off, &input,
                               sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return 0;
}

static int vmedia_ioctl_subscribe_event(VirtIOMedia *s,
                                        VirtIOMediaSession *session,
                                        bool subscribe,
                                        const struct iovec *out_sg,
                                        int out_num,
                                              size_t out_off)
{
    struct v4l2_event_subscription sub;

    if (vmedia_iov_read(out_sg, out_num, out_off, &sub,
                              sizeof(sub)) != sizeof(sub)) {
        return -EINVAL;
    }

    if (!s->use_host_device) {
        /* No host device: nothing to forward, accept the (un)subscribe. */
        return 0;
    }

    if (vmedia_proxy_ioctl(session->host_fd,
                           subscribe ? VIDIOC_SUBSCRIBE_EVENT :
                                       VIDIOC_UNSUBSCRIBE_EVENT,
                           &sub) < 0) {
        return -EINVAL;
    }

    if (subscribe) {
        session->host_event_subs++;
        /*
         * Drain any event delivered immediately by the subscribe (e.g. due to
         * V4L2_EVENT_SUB_FL_SEND_INITIAL). We deliberately do not arm a
         * dedicated fd handler for events here: QEMU's fd handler watches
         * POLLIN, but V4L2 events signal POLLPRI, so watching a non-streaming
         * fd would busy-loop. While streaming, the buffer fd handler also
         * drains events (see vmedia_host_fd_handler).
         */
        vmedia_drain_host_events(s, session);
    } else if (session->host_event_subs > 0) {
        session->host_event_subs--;
    }

    return 0;
}

static int vmedia_handle_ioctl(VirtIOMedia *s,
                                     VirtIOMediaSession *session,
                                     uint32_t code, VirtQueueElement *elem,
                                     size_t *payload_len)
{
    size_t out_off = sizeof(struct virtio_media_cmd_ioctl);
    size_t in_off = sizeof(struct virtio_media_resp_ioctl);

    if (s->use_host_device) {
        int ret = vmedia_session_ensure_host_fd(s, session);
        if (ret < 0) {
            return ret;
        }
    }

    switch (code) {
    case _IOC_NR(VIDIOC_ENUM_FMT):
        *payload_len = sizeof(struct v4l2_fmtdesc);
        if (s->use_host_device) {
            return vmedia_proxy_enum_fmt(session, elem->out_sg, elem->out_num,
                                               elem->in_sg, elem->in_num,
                                               out_off, in_off);
        }
        return vmedia_ioctl_enum_fmt(session, elem->out_sg, elem->out_num,
                                           elem->in_sg, elem->in_num,
                                           out_off, in_off);
    case _IOC_NR(VIDIOC_G_FMT):
        *payload_len = sizeof(struct v4l2_format);
        if (s->use_host_device) {
            return vmedia_proxy_g_fmt(session, elem->out_sg, elem->out_num,
                                            elem->in_sg, elem->in_num,
                                            out_off, in_off);
        }
        return vmedia_ioctl_g_fmt(elem->out_sg, elem->out_num,
                                        elem->in_sg, elem->in_num,
                                        out_off, in_off);
    case _IOC_NR(VIDIOC_S_FMT):
        *payload_len = sizeof(struct v4l2_format);
        if (s->use_host_device) {
            return vmedia_proxy_s_fmt(session, elem->out_sg, elem->out_num,
                                            elem->in_sg, elem->in_num,
                                            out_off, in_off, false);
        }
        return vmedia_ioctl_s_fmt(elem->out_sg, elem->out_num,
                                        elem->in_sg, elem->in_num,
                                        out_off, in_off);
    case _IOC_NR(VIDIOC_TRY_FMT):
        *payload_len = sizeof(struct v4l2_format);
        if (s->use_host_device) {
            return vmedia_proxy_s_fmt(session, elem->out_sg, elem->out_num,
                                            elem->in_sg, elem->in_num,
                                            out_off, in_off, true);
        }
        return vmedia_ioctl_s_fmt(elem->out_sg, elem->out_num,
                                        elem->in_sg, elem->in_num,
                                        out_off, in_off);
    case _IOC_NR(VIDIOC_REQBUFS):
        *payload_len = sizeof(struct v4l2_requestbuffers);
        if (s->use_host_device) {
            return vmedia_proxy_reqbufs(s, session, elem->out_sg, elem->out_num,
                                              elem->in_sg, elem->in_num,
                                              out_off, in_off);
        }
        return vmedia_ioctl_reqbufs(s, session, elem->out_sg, elem->out_num,
                                          elem->in_sg, elem->in_num,
                                          out_off, in_off);
    case _IOC_NR(VIDIOC_QUERYBUF):
        *payload_len = 0;
        if (s->use_host_device) {
            return vmedia_proxy_querybuf(session, elem->out_sg, elem->out_num,
                                          elem->in_sg, elem->in_num,
                                          out_off, in_off, payload_len);
        }
        return vmedia_ioctl_querybuf(session, elem->out_sg, elem->out_num,
                                           elem->in_sg, elem->in_num,
                                           out_off, in_off, payload_len);
    case _IOC_NR(VIDIOC_QBUF):
        *payload_len = 0;
        if (s->use_host_device) {
            return vmedia_proxy_qbuf(s, session, elem->out_sg, elem->out_num,
                                           elem->in_sg, elem->in_num,
                                           out_off, in_off, payload_len);
        }
        return vmedia_ioctl_qbuf(s, session, elem->out_sg, elem->out_num,
                                       elem->in_sg, elem->in_num,
                                       out_off, in_off, payload_len);
    case _IOC_NR(VIDIOC_STREAMON):
        *payload_len = 0;
        if (s->use_host_device) {
            return vmedia_proxy_streamon(s, session, elem->out_sg,
                                               elem->out_num, out_off);
        }
        return vmedia_ioctl_streamon(s, session, elem->out_sg,
                                           elem->out_num, out_off);
    case _IOC_NR(VIDIOC_STREAMOFF):
        *payload_len = 0;
        if (s->use_host_device) {
            return vmedia_proxy_streamoff(s, session, elem->out_sg,
                                                elem->out_num, out_off);
        }
        return vmedia_ioctl_streamoff(session, elem->out_sg,
                                            elem->out_num, out_off);
    case _IOC_NR(VIDIOC_ENUMINPUT):
        *payload_len = sizeof(struct v4l2_input);
        if (s->use_host_device) {
            return vmedia_proxy_enuminput(session, elem->out_sg, elem->out_num,
                                          elem->in_sg, elem->in_num,
                                          out_off, in_off);
        }
        return vmedia_ioctl_enuminput(elem->out_sg, elem->out_num,
                                      elem->in_sg, elem->in_num,
                                      out_off, in_off);
    case _IOC_NR(VIDIOC_G_INPUT):
        *payload_len = sizeof(uint32_t);
        if (s->use_host_device) {
            return vmedia_proxy_g_input(session, elem->in_sg, elem->in_num,
                                        in_off);
        }
        return vmedia_ioctl_g_input(elem->in_sg, elem->in_num, in_off);
    case _IOC_NR(VIDIOC_S_INPUT):
        *payload_len = sizeof(uint32_t);
        if (s->use_host_device) {
            return vmedia_proxy_s_input(session, elem->out_sg, elem->out_num,
                                        elem->in_sg, elem->in_num,
                                        out_off, in_off);
        }
        return vmedia_ioctl_s_input(elem->out_sg, elem->out_num,
                                    elem->in_sg, elem->in_num,
                                    out_off, in_off);
    case _IOC_NR(VIDIOC_QUERYCTRL):
        *payload_len = sizeof(struct v4l2_queryctrl);
        if (s->use_host_device) {
            return vmedia_proxy_queryctrl(session, elem->out_sg, elem->out_num,
                                                elem->in_sg, elem->in_num,
                                                out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_G_CTRL):
        *payload_len = sizeof(struct v4l2_control);
        if (s->use_host_device) {
            return vmedia_proxy_g_ctrl(session, elem->out_sg, elem->out_num,
                                             elem->in_sg, elem->in_num,
                                             out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_S_CTRL):
        *payload_len = sizeof(struct v4l2_control);
        if (s->use_host_device) {
            return vmedia_proxy_s_ctrl(session, elem->out_sg, elem->out_num,
                                             elem->in_sg, elem->in_num,
                                             out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_QUERYMENU):
        *payload_len = sizeof(struct v4l2_querymenu);
        if (s->use_host_device) {
            return vmedia_proxy_querymenu(session, elem->out_sg, elem->out_num,
                                                elem->in_sg, elem->in_num,
                                                out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_CROPCAP):
        *payload_len = sizeof(struct v4l2_cropcap);
        if (s->use_host_device) {
            return vmedia_proxy_cropcap(session, elem->out_sg, elem->out_num,
                                              elem->in_sg, elem->in_num,
                                              out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_G_CROP):
        *payload_len = sizeof(struct v4l2_crop);
        if (s->use_host_device) {
            return vmedia_proxy_crop(session, false, elem->out_sg,
                                     elem->out_num, elem->in_sg,
                                     elem->in_num, out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_S_CROP):
        *payload_len = sizeof(struct v4l2_crop);
        if (s->use_host_device) {
            return vmedia_proxy_crop(session, true, elem->out_sg,
                                     elem->out_num, elem->in_sg,
                                     elem->in_num, out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_G_SELECTION):
        *payload_len = sizeof(struct v4l2_selection);
        if (s->use_host_device) {
            return vmedia_proxy_selection(session, false, elem->out_sg,
                                          elem->out_num, elem->in_sg,
                                          elem->in_num, out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_S_SELECTION):
        *payload_len = sizeof(struct v4l2_selection);
        if (s->use_host_device) {
            return vmedia_proxy_selection(session, true, elem->out_sg,
                                          elem->out_num, elem->in_sg,
                                          elem->in_num, out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_QUERY_EXT_CTRL):
        *payload_len = sizeof(struct v4l2_query_ext_ctrl);
        if (s->use_host_device) {
            return vmedia_proxy_query_ext_ctrl(session, elem->out_sg,
                                               elem->out_num, elem->in_sg,
                                               elem->in_num, out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_G_EXT_CTRLS):
        *payload_len = 0;
        if (s->use_host_device) {
            return vmedia_proxy_ext_ctrls(session, VIDIOC_G_EXT_CTRLS,
                                                elem->out_sg, elem->out_num,
                                                elem->in_sg, elem->in_num,
                                                out_off, in_off, payload_len);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_S_EXT_CTRLS):
        *payload_len = 0;
        if (s->use_host_device) {
            return vmedia_proxy_ext_ctrls(session, VIDIOC_S_EXT_CTRLS,
                                                elem->out_sg, elem->out_num,
                                                elem->in_sg, elem->in_num,
                                                out_off, in_off, payload_len);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_TRY_EXT_CTRLS):
        *payload_len = 0;
        if (s->use_host_device) {
            return vmedia_proxy_ext_ctrls(session, VIDIOC_TRY_EXT_CTRLS,
                                                elem->out_sg, elem->out_num,
                                                elem->in_sg, elem->in_num,
                                                out_off, in_off, payload_len);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_ENUM_FRAMESIZES):
        *payload_len = sizeof(struct v4l2_frmsizeenum);
        if (s->use_host_device) {
            return vmedia_proxy_enum_framesizes(session, elem->out_sg,
                                                elem->out_num,
                                                elem->in_sg, elem->in_num,
                                                out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_ENUM_FRAMEINTERVALS):
        *payload_len = sizeof(struct v4l2_frmivalenum);
        if (s->use_host_device) {
            return vmedia_proxy_enum_frameintervals(session, elem->out_sg,
                                                    elem->out_num,
                                                    elem->in_sg, elem->in_num,
                                                    out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_G_PARM):
        *payload_len = sizeof(struct v4l2_streamparm);
        if (s->use_host_device) {
            return vmedia_proxy_parm(session, false, elem->out_sg,
                                     elem->out_num, elem->in_sg, elem->in_num,
                                     out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_S_PARM):
        *payload_len = sizeof(struct v4l2_streamparm);
        if (s->use_host_device) {
            return vmedia_proxy_parm(session, true, elem->out_sg,
                                     elem->out_num, elem->in_sg, elem->in_num,
                                     out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_SUBSCRIBE_EVENT):
        *payload_len = 0;
        return vmedia_ioctl_subscribe_event(s, session, true,
                                            elem->out_sg, elem->out_num,
                                            out_off);
    case _IOC_NR(VIDIOC_UNSUBSCRIBE_EVENT):
        *payload_len = 0;
        return vmedia_ioctl_subscribe_event(s, session, false,
                                            elem->out_sg, elem->out_num,
                                            out_off);
    default:
        *payload_len = 0;
        return -ENOTTY;
    }
}

static void vmedia_handle_command(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOMedia *s = VIRTIO_MEDIA(vdev);
    struct virtio_media_cmd_header hdr;
    VirtQueueElement *elem;

    while ((elem = virtqueue_pop(vq, sizeof(VirtQueueElement)))) {
        size_t out_len = iov_size(elem->out_sg, elem->out_num);
        size_t in_len = iov_size(elem->in_sg, elem->in_num);
        uint32_t cmd;

        if (out_len < sizeof(hdr)) {
            virtio_error(vdev, "virtio-media: short command buffers");
            virtqueue_push(vq, elem, 0);
            g_free(elem);
            continue;
        }

        if (vmedia_iov_read(elem->out_sg, elem->out_num, 0,
                                  &hdr, sizeof(hdr)) != sizeof(hdr)) {
            virtio_error(vdev, "virtio-media: failed to read command header");
            virtqueue_push(vq, elem, 0);
            g_free(elem);
            continue;
        }

        cmd = le32_to_cpu(hdr.cmd);

    switch (cmd) {
    case VIRTIO_MEDIA_CMD_OPEN: {
        struct virtio_media_resp_open resp;
        VirtIOMediaSession *session = NULL;

        if (in_len < sizeof(resp)) {
            virtio_error(vdev, "virtio-media: short OPEN response buffer");
            virtqueue_push(vq, elem, 0);
            break;
        }

        /*
         * Do not open the host device here. It is opened lazily on the first
         * ioctl (see vmedia_session_ensure_host_fd), so a guest that merely
         * opens the node without streaming does not consume a host open slot.
         */
        session = vmedia_session_new(s, s->session_next_id++);
        g_hash_table_insert(s->sessions, GUINT_TO_POINTER(session->id),
                            session);

        vmedia_write_resp_header(&resp.hdr, 0);
        resp.session_id = cpu_to_le32(session->id);
        resp.reserved = 0;
        vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                               &resp, sizeof(resp));
        virtqueue_push(vq, elem, sizeof(resp));
        break;
    }
    case VIRTIO_MEDIA_CMD_CLOSE: {
        struct virtio_media_cmd_close close_cmd;
        uint32_t id;
        VirtIOMediaSession *session;

        if (vmedia_iov_read(elem->out_sg, elem->out_num, 0,
                            &close_cmd,
                            sizeof(close_cmd)) != sizeof(close_cmd)) {
            virtqueue_push(vq, elem, 0);
            break;
        }

        id = le32_to_cpu(close_cmd.session_id);
        session = g_hash_table_lookup(s->sessions, GUINT_TO_POINTER(id));
        if (session) {
            g_hash_table_remove(s->sessions, GUINT_TO_POINTER(id));
            vmedia_session_free(s, session);
        }
        virtqueue_push(vq, elem, 0);
        break;
    }
    case VIRTIO_MEDIA_CMD_IOCTL: {
        struct virtio_media_cmd_ioctl ioctl_cmd;
        struct virtio_media_resp_ioctl resp;
        VirtIOMediaSession *session;
        uint32_t id;
        uint32_t code;
        int status;
        size_t payload_len = 0;
        size_t used;

        if (in_len < sizeof(resp)) {
            virtio_error(vdev, "virtio-media: short IOCTL response buffer");
            virtqueue_push(vq, elem, 0);
            break;
        }

        if (vmedia_iov_read(elem->out_sg, elem->out_num, 0,
                            &ioctl_cmd,
                            sizeof(ioctl_cmd)) != sizeof(ioctl_cmd)) {
            virtqueue_push(vq, elem, 0);
            break;
        }

        id = le32_to_cpu(ioctl_cmd.session_id);
        code = le32_to_cpu(ioctl_cmd.code);
        session = g_hash_table_lookup(s->sessions, GUINT_TO_POINTER(id));
        if (!session) {
            status = -EINVAL;
        } else {
            status = vmedia_handle_ioctl(s, session, code, elem, &payload_len);
        }
        /*
         * On error, drop the payload. The exception is the EXT_CTRLS family:
         * the spec requires returning the v4l2_ext_controls payload (with
         * error_idx set) even on EACCES/EINVAL, and the guest driver reads it
         * back. Those handlers set payload_len on their error paths; all other
         * dispatch arms may have pre-set payload_len, so we must still zero it.
         */
        if (status < 0) {
            switch (_IOC_NR(code)) {
            case _IOC_NR(VIDIOC_G_EXT_CTRLS):
            case _IOC_NR(VIDIOC_S_EXT_CTRLS):
            case _IOC_NR(VIDIOC_TRY_EXT_CTRLS):
                break;
            default:
                payload_len = 0;
                break;
            }
        }

        vmedia_write_resp_header(&resp.hdr, status < 0 ? -status : 0);
        vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                               &resp, sizeof(resp));
        used = sizeof(resp) + payload_len;
        if (used > in_len) {
            used = in_len;
        }
        virtqueue_push(vq, elem, used);
        /*
         * An ioctl may have queued events (e.g. SUBSCRIBE_EVENT with
         * SEND_INITIAL drains the host's initial event); deliver them now.
         */
        vmedia_flush_events(s);
        break;
    }
    case VIRTIO_MEDIA_CMD_EXPORT_BUFFER: {
        struct virtio_media_cmd_export_buffer export_cmd;
        struct virtio_media_resp_export_buffer resp = { 0 };
        VirtIOMediaSession *session;
        VirtIOMediaShare *share = NULL;
        uint32_t id;
        int status = 0;

        if (in_len < sizeof(resp)) {
            virtio_error(vdev, "virtio-media: short EXPORT response buffer");
            virtqueue_push(vq, elem, 0);
            break;
        }
        if (!virtio_vdev_has_feature(vdev, VIRTIO_MEDIA_F_EXPORT_IMPORT)) {
            status = -EOPNOTSUPP;
            goto export_respond;
        }
        if (vmedia_iov_read(elem->out_sg, elem->out_num, 0,
                            &export_cmd,
                            sizeof(export_cmd)) != sizeof(export_cmd)) {
            virtqueue_push(vq, elem, 0);
            break;
        }

        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: EXPORT cmd session=%u qtype=%u idx=%u plane=%u\n",
                      le32_to_cpu(export_cmd.session_id),
                      le32_to_cpu(export_cmd.queue_type),
                      le32_to_cpu(export_cmd.buffer_index),
                      le32_to_cpu(export_cmd.plane_index));

        id = le32_to_cpu(export_cmd.session_id);
        session = g_hash_table_lookup(s->sessions, GUINT_TO_POINTER(id));
        if (!session) {
            status = -EINVAL;
            goto export_respond;
        }

        status = vmedia_share_from_buffer(s, session,
                                          le32_to_cpu(export_cmd.queue_type),
                                          le32_to_cpu(export_cmd.buffer_index),
                                          le32_to_cpu(export_cmd.plane_index),
                                          &share);
        if (status < 0) {
            goto export_respond;
        }

        {
            guint64 *key = g_new(guint64, 1);
            *key = share->handle_id;
            g_hash_table_insert(s->share_handles, key, share);
        }

        resp.handle_id = cpu_to_le64(share->handle_id);
        resp.len = cpu_to_le64(share->len);
        resp.plane_count = cpu_to_le32(share->plane_count);

export_respond:
        if (status < 0 && share) {
            g_free(share);
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: EXPORT resp status=%d handle=%" PRIu64
                      " len=%" PRIu64 "\n",
                      status, (uint64_t)le64_to_cpu(resp.handle_id),
                      (uint64_t)le64_to_cpu(resp.len));
        vmedia_write_resp_header(&resp.hdr, status < 0 ? -status : 0);
        vmedia_iov_write(elem->in_sg, elem->in_num, 0, &resp, sizeof(resp));
        virtqueue_push(vq, elem, sizeof(resp));
        break;
    }
    case VIRTIO_MEDIA_CMD_IMPORT_BUFFER: {
        struct virtio_media_cmd_import_buffer import_cmd;
        struct virtio_media_resp_import_buffer resp = { 0 };
        VirtIOMediaSession *session;
        VirtIOMediaShare *share;
        VirtIOMediaPeerGrant *peer_grant = NULL;
        size_t resp_len;
        uint32_t id;
        uint32_t flags = 0;
        uint32_t import_domid = 0;
        uint64_t addr = 0;
        uint64_t len = 0;
        int status = 0;

        if (!virtio_vdev_has_feature(vdev, VIRTIO_MEDIA_F_EXPORT_IMPORT)) {
            status = -EOPNOTSUPP;
            goto import_respond;
        }
        if (vmedia_iov_read(elem->out_sg, elem->out_num, 0,
                            &import_cmd,
                            sizeof(import_cmd)) != sizeof(import_cmd)) {
            virtqueue_push(vq, elem, 0);
            break;
        }

        flags = le32_to_cpu(import_cmd.flags);
        if (flags & VIRTIO_MEDIA_IMPORT_F_TARGET_DOMID) {
            import_domid = (flags >> VIRTIO_MEDIA_IMPORT_DOMID_SHIFT) &
                           VIRTIO_MEDIA_IMPORT_DOMID_MASK;
            if (!import_domid) {
                status = -EINVAL;
                goto import_respond;
            }
            if (!virtio_vdev_has_feature(vdev,
                                         VIRTIO_MEDIA_F_PEER_GREF_IMPORT)) {
                status = -EOPNOTSUPP;
                goto import_respond;
            }
        }

        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: IMPORT cmd session=%u handle=%" PRIu64
                      " flags=0x%x domid=%u\n",
                      le32_to_cpu(import_cmd.session_id),
                      (uint64_t)le64_to_cpu(import_cmd.handle_id),
                      flags, import_domid);

        id = le32_to_cpu(import_cmd.session_id);
        session = g_hash_table_lookup(s->sessions, GUINT_TO_POINTER(id));
        if (!session) {
            status = -EINVAL;
            goto import_respond;
        }

        share = vmedia_share_lookup(s, le64_to_cpu(import_cmd.handle_id));
        if (!share) {
            status = -ENOENT;
            goto import_respond;
        }
        addr = share->driver_addr;
        len = share->len;

        if (import_domid) {
            peer_grant = vmedia_share_get_peer_grant(s, share, import_domid,
                                                     &status);
            if (!peer_grant) {
                goto import_respond;
            }
        }

import_respond:
        vmedia_write_resp_header(&resp.hdr, status < 0 ? -status : 0);
        resp.driver_addr = cpu_to_le64(addr);
        resp.len = cpu_to_le64(len);
        resp.gref_count = 0;
        resp.gref_page_size = 0;
        resp.gref_domid = 0;
        resp.pad = 0;

        if (s->use_grefs && status == 0) {
            uint32_t gref_start;
            uint32_t gref_count;
            size_t needed;

            if (peer_grant) {
                gref_start = 0;
                gref_count = peer_grant->gref_count;
            } else {
                gref_start = addr / VIRTIO_MEDIA_GREF_PAGE_SIZE;
                gref_count = DIV_ROUND_UP(len, VIRTIO_MEDIA_GREF_PAGE_SIZE);
            }
            needed = sizeof(resp) + (size_t)gref_count * sizeof(uint32_t);
            if (in_len < needed ||
                (!peer_grant &&
                 (uint64_t)gref_start + gref_count > s->gref_count)) {
                vmedia_write_resp_header(&resp.hdr, ENOSPC);
                vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                                 &resp, sizeof(resp));
                virtqueue_push(vq, elem, sizeof(resp));
                break;
            }

            resp.gref_count = cpu_to_le32(gref_count);
            resp.gref_page_size = cpu_to_le32(VIRTIO_MEDIA_GREF_PAGE_SIZE);
            resp.gref_domid = cpu_to_le32(peer_grant ? import_domid : 0);

            vmedia_iov_write(elem->in_sg, elem->in_num, 0, &resp, sizeof(resp));
            {
                uint32_t i;
                g_autofree uint32_t *grefs = g_new(uint32_t, gref_count);

                for (i = 0; i < gref_count; i++) {
                    grefs[i] = cpu_to_le32(peer_grant ?
                                           peer_grant->grefs[i] :
                                           s->grefs[gref_start + i]);
                }
                vmedia_iov_write(elem->in_sg, elem->in_num, sizeof(resp),
                                 grefs, gref_count * sizeof(uint32_t));
            }
            resp_len = needed;
        } else {
            if (in_len < sizeof(resp)) {
                virtio_error(vdev,
                             "virtio-media: short IMPORT response buffer");
                virtqueue_push(vq, elem, 0);
                break;
            }
            vmedia_iov_write(elem->in_sg, elem->in_num, 0, &resp, sizeof(resp));
            resp_len = sizeof(resp);
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: IMPORT resp status=%d addr=0x%" PRIx64
                      " len=0x%" PRIx64 " grefs=%u\n",
                      status, (uint64_t)addr, (uint64_t)len,
                      (uint32_t)le32_to_cpu(resp.gref_count));
        virtqueue_push(vq, elem, resp_len);
        break;
    }
    case VIRTIO_MEDIA_CMD_RELEASE_HANDLE: {
        struct virtio_media_cmd_release_handle release_cmd;
        struct virtio_media_resp_release_handle resp = { 0 };
        int status = 0;

        if (in_len < sizeof(resp)) {
            virtio_error(vdev, "virtio-media: short RELEASE response buffer");
            virtqueue_push(vq, elem, 0);
            break;
        }
        if (!virtio_vdev_has_feature(vdev, VIRTIO_MEDIA_F_EXPORT_IMPORT)) {
            status = -EOPNOTSUPP;
            goto release_respond;
        }
        if (vmedia_iov_read(elem->out_sg, elem->out_num, 0,
                            &release_cmd,
                            sizeof(release_cmd)) != sizeof(release_cmd)) {
            virtqueue_push(vq, elem, 0);
            break;
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: RELEASE cmd handle=%" PRIu64 "\n",
                      (uint64_t)le64_to_cpu(release_cmd.handle_id));
        {
            uint64_t handle_id = le64_to_cpu(release_cmd.handle_id);
            if (!g_hash_table_remove(s->share_handles, &handle_id)) {
                status = -ENOENT;
            }
        }

release_respond:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: RELEASE resp status=%d\n", status);
        vmedia_write_resp_header(&resp.hdr, status < 0 ? -status : 0);
        vmedia_iov_write(elem->in_sg, elem->in_num, 0, &resp, sizeof(resp));
        virtqueue_push(vq, elem, sizeof(resp));
        break;
    }
    case VIRTIO_MEDIA_CMD_REGISTER_BUFFER: {
        struct virtio_media_cmd_register_buffer reg;
        struct virtio_media_resp_register_buffer reg_resp = { 0 };
        VirtIOMediaSession *session;
        QemuUUID uuid;
        int hostfd = -1;
        int status = 0;
        uint32_t idx;

        if (!virtio_vdev_has_feature(vdev, VIRTIO_MEDIA_F_IMPORT_BUFFER)) {
            status = -EOPNOTSUPP;
            goto reg_respond;
        }
        if (vmedia_iov_read(elem->out_sg, elem->out_num, 0,
                            &reg, sizeof(reg)) != sizeof(reg)) {
            virtqueue_push(vq, elem, 0);
            break;
        }
        session = g_hash_table_lookup(s->sessions,
                      GUINT_TO_POINTER(le32_to_cpu(reg.session_id)));
        if (!session) {
            status = -EINVAL;
            goto reg_respond;
        }
        idx = le32_to_cpu(reg.buffer_index);
        if (!session->host_dmabuf_fds || idx >= session->host_num_buffers) {
            status = -EINVAL;
            goto reg_respond;
        }
        memcpy(uuid.data, reg.uuid, sizeof(uuid.data));
        hostfd = virtio_lookup_dmabuf(&uuid);
        if (hostfd < 0) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "virtio-media: REGISTER_BUFFER idx=%u uuid not found\n",
                          idx);
            status = -ENOENT;
            goto reg_respond;
        }
        if (session->host_dmabuf_fds[idx] >= 0) {
            close(session->host_dmabuf_fds[idx]);
        }
        session->host_dmabuf_fds[idx] = dup(hostfd);
        if (session->host_dmabuf_fds[idx] < 0) {
            status = -errno;
            goto reg_respond;
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-media: REGISTER_BUFFER idx=%u -> host fd %d\n",
                      idx, session->host_dmabuf_fds[idx]);
reg_respond:
        vmedia_write_resp_header(&reg_resp.hdr, status);
        vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                         &reg_resp, sizeof(reg_resp));
        virtqueue_push(vq, elem, sizeof(reg_resp));
        break;
    }
    case VIRTIO_MEDIA_CMD_MMAP: {
        struct virtio_media_cmd_mmap mmap_cmd;
        struct virtio_media_resp_mmap resp;
        size_t resp_len;
        VirtIOMediaSession *session;
        uint64_t addr = 0;
        uint64_t len = 0;
        uint32_t id;
        int status;
        /*
         * Only emit the grant-ref extension when the guest negotiated GNTREF.
         * A grant-unaware driver (e.g. upstream) posts a base-sized response
         * buffer; gating on the device capability alone would overrun it.
         */
        bool grefs_acked = s->use_grefs &&
            virtio_vdev_has_feature(vdev, VIRTIO_MEDIA_F_GNTREF);

        if (vmedia_iov_read(elem->out_sg, elem->out_num, 0,
                            &mmap_cmd,
                            sizeof(mmap_cmd)) != sizeof(mmap_cmd)) {
            virtqueue_push(vq, elem, 0);
            break;
        }

        id = le32_to_cpu(mmap_cmd.session_id);
        session = g_hash_table_lookup(s->sessions, GUINT_TO_POINTER(id));
        if (!session) {
            status = -EINVAL;
        } else {
            status = vmedia_find_plane(session,
                                       le32_to_cpu(mmap_cmd.offset),
                                       &addr, &len);
        }

        vmedia_write_resp_header(&resp.hdr, status < 0 ? -status : 0);
        resp.driver_addr = cpu_to_le64(addr);
        resp.len = cpu_to_le64(len);
        resp.gref_count = 0;
        resp.gref_page_size = 0;
        resp.gref_domid = 0;
        resp.pad = 0;

        if (grefs_acked && status == 0 && session->host_regrant) {
            /*
             * Mode A: return the grant refs for the host driver's own
             * EXPBUF'd buffer pages (set up at REQBUFS), so the guest maps
             * the actual capture buffer with no per-frame copy.
             */
            uint32_t bi = 0, pi = 0;
            uint32_t planes = session->host_num_planes ?
                              session->host_num_planes : 1;
            uint32_t slot;
            uint32_t gref_count;
            const uint32_t *src;
            size_t needed;

            if (vmedia_find_plane_index(session, le32_to_cpu(mmap_cmd.offset),
                                        &bi, &pi) < 0) {
                vmedia_write_resp_header(&resp.hdr, EINVAL);
                vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                                 &resp, sizeof(resp));
                virtqueue_push(vq, elem, sizeof(resp));
                break;
            }
            slot = bi * planes + pi;
            gref_count = session->host_gref_cnts[slot];
            src = session->host_gref_ids[slot];
            needed = sizeof(resp) + (size_t)gref_count * sizeof(uint32_t);
            if (!src || !gref_count || in_len < needed) {
                vmedia_write_resp_header(&resp.hdr, ENOSPC);
                vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                                 &resp, sizeof(resp));
                virtqueue_push(vq, elem, sizeof(resp));
                break;
            }

            resp.gref_count = cpu_to_le32(gref_count);
            resp.gref_page_size = cpu_to_le32(VIRTIO_MEDIA_GREF_PAGE_SIZE);
            resp.gref_domid = cpu_to_le32(0); /* dom0-granted */
            vmedia_iov_write(elem->in_sg, elem->in_num, 0, &resp, sizeof(resp));
            {
                uint32_t i;
                g_autofree uint32_t *grefs = g_new(uint32_t, gref_count);

                for (i = 0; i < gref_count; i++) {
                    grefs[i] = cpu_to_le32(src[i]);
                }
                vmedia_iov_write(elem->in_sg, elem->in_num, sizeof(resp),
                                 grefs, gref_count * sizeof(uint32_t));
            }
            resp_len = needed;
        } else if (grefs_acked && status == 0) {
            uint32_t gref_start;
            uint32_t gref_count;
            size_t needed;

            gref_start = addr / VIRTIO_MEDIA_GREF_PAGE_SIZE;
            gref_count = DIV_ROUND_UP(len, VIRTIO_MEDIA_GREF_PAGE_SIZE);
            needed = sizeof(resp) + (size_t)gref_count * sizeof(uint32_t);
            if (in_len < needed ||
                (uint64_t)gref_start + gref_count > s->gref_count) {
                vmedia_write_resp_header(&resp.hdr, ENOSPC);
                vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                                 &resp, sizeof(resp));
                virtqueue_push(vq, elem, sizeof(resp));
                break;
            }

            resp.gref_count = cpu_to_le32(gref_count);
            resp.gref_page_size = cpu_to_le32(VIRTIO_MEDIA_GREF_PAGE_SIZE);
            /* gntalloc grants pages from dom0. */
            resp.gref_domid = cpu_to_le32(0);

            vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                             &resp, sizeof(resp));
            {
                uint32_t i;
                g_autofree uint32_t *grefs = g_new(uint32_t, gref_count);

                for (i = 0; i < gref_count; i++) {
                    grefs[i] = cpu_to_le32(s->grefs[gref_start + i]);
                }
                vmedia_iov_write(elem->in_sg, elem->in_num, sizeof(resp),
                                 grefs,
                                 gref_count * sizeof(uint32_t));
            }
            resp_len = needed;
        } else {
            /*
             * No grant extension: respond with the spec-sized struct only
             * (hdr, driver_addr, len). Writing sizeof(resp) would include the
             * grant fields and overrun a grant-unaware driver's buffer.
             */
            if (in_len < VIRTIO_MEDIA_RESP_MMAP_BASE_SIZE) {
                virtio_error(vdev, "virtio-media: short MMAP response buffer");
                virtqueue_push(vq, elem, 0);
                break;
            }
            vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                             &resp, VIRTIO_MEDIA_RESP_MMAP_BASE_SIZE);
            resp_len = VIRTIO_MEDIA_RESP_MMAP_BASE_SIZE;
        }
        virtqueue_push(vq, elem, resp_len);
        break;
    }
    case VIRTIO_MEDIA_CMD_MUNMAP: {
        struct virtio_media_resp_munmap resp;

        if (in_len < sizeof(resp)) {
            virtio_error(vdev, "virtio-media: short MUNMAP response buffer");
            virtqueue_push(vq, elem, 0);
            break;
        }

        vmedia_write_resp_header(&resp.hdr, 0);
        vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                               &resp, sizeof(resp));
        virtqueue_push(vq, elem, sizeof(resp));
        break;
    }
    default: {
        struct virtio_media_resp_header resp;

        if (in_len < sizeof(resp)) {
            virtio_error(vdev, "virtio-media: short response buffer");
            virtqueue_push(vq, elem, 0);
            break;
        }

        vmedia_write_resp_header(&resp, ENOTTY);
        vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                               &resp, sizeof(resp));
        virtqueue_push(vq, elem, sizeof(resp));
        break;
    }
        }

        virtio_notify(vdev, vq);
        g_free(elem);
    }
}

static void vmedia_handle_event(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOMedia *s = VIRTIO_MEDIA(vdev);

    vmedia_flush_events(s);
}

static void vmedia_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    VirtIOMedia *s = VIRTIO_MEDIA(vdev);

    memcpy(config_data, &s->config, sizeof(s->config));
}

static uint64_t vmedia_get_features(VirtIODevice *vdev, uint64_t f,
                                          Error **errp)
{
    VirtIOMedia *s = VIRTIO_MEDIA(vdev);

    if (s->use_grefs) {
        f |= (1ULL << VIRTIO_MEDIA_F_GNTREF);
        f |= (1ULL << VIRTIO_MEDIA_F_PEER_GREF_IMPORT);
    }
    f |= (1ULL << VIRTIO_MEDIA_F_EXPORT_IMPORT);
    f |= (1ULL << VIRTIO_MEDIA_F_SHARE_FENCE);
    if (s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_IMPORT_UUID) {
        f |= (1ULL << VIRTIO_MEDIA_F_IMPORT_BUFFER);
    }
    return f;
}

static int vmedia_pre_load(void *opaque)
{
    return 0;
}

static int vmedia_post_load(void *opaque, int version_id)
{
    return 0;
}

static const VMStateDescription vmstate_virtio_media = {
    .name = "virtio-media",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_load = vmedia_pre_load,
    .post_load = vmedia_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    }
};

static void vmedia_realize(DeviceState *dev, Error **errp)
{
    VirtIOMedia *s = VIRTIO_MEDIA(dev);
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    struct v4l2_capability cap;
    struct v4l2_format fmt;
    uint64_t buffer_size = VIRTIO_MEDIA_BUFFER_SIZE_MPLANE;
    bool use_grefs = xen_enabled() && s->xen_grants;
    int caps;

    if (s->max_buffers == 0) {
        s->max_buffers = 8;
    }

    if (vmedia_parse_host_v4l2_mem_mode(s, errp) < 0) {
        return;
    }

    if (s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_REGRANT && !use_grefs) {
        error_setg(errp,
                   "virtio-media: host-v4l2-memory=regrant requires Xen grant "
                   "references; not available (xen-grants disabled or not "
                   "running under Xen)");
        return;
    }

    s->use_host_device = false;
    s->host_userptr_capture = false;
    s->host_userptr_mplane = false;

    if (s->host_device) {
        uint64_t max_sizeimage;
        int host_caps;
        int host_fd;

        host_fd = open(s->host_device, O_RDWR | O_NONBLOCK);
        if (host_fd < 0) {
            error_setg(errp, "virtio-media: failed to open host device %s: %s",
                       s->host_device, strerror(errno));
            return;
        }

        if (vmedia_ioctl_nointr(host_fd, VIDIOC_QUERYCAP, &cap) < 0) {
            error_setg(errp, "virtio-media: VIDIOC_QUERYCAP failed on %s: %s",
                       s->host_device, strerror(errno));
            close(host_fd);
            return;
        }

        memset(&fmt, 0, sizeof(fmt));
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (vmedia_ioctl_nointr(host_fd, VIDIOC_G_FMT, &fmt) == 0) {
            buffer_size = MAX(buffer_size, vmedia_format_sizeimage(&fmt));
        }

        memset(&fmt, 0, sizeof(fmt));
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
        if (vmedia_ioctl_nointr(host_fd, VIDIOC_G_FMT, &fmt) == 0) {
            buffer_size = MAX(buffer_size, vmedia_format_sizeimage(&fmt));
        }

        max_sizeimage = use_grefs ? 0 : vmedia_proxy_max_sizeimage(host_fd);
        if (!use_grefs && max_sizeimage > buffer_size) {
            buffer_size = max_sizeimage;
        }

        host_caps = cap.device_caps ? cap.device_caps : cap.capabilities;
        if (host_caps & V4L2_CAP_STREAMING) {
            if (host_caps & V4L2_CAP_VIDEO_CAPTURE) {
                s->host_userptr_capture =
                    vmedia_type_supports_userptr(host_fd,
                                                 V4L2_BUF_TYPE_VIDEO_CAPTURE);
            }
            if (host_caps & V4L2_CAP_VIDEO_CAPTURE_MPLANE) {
                s->host_userptr_mplane =
                    vmedia_type_supports_userptr(
                        host_fd, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
            }
        }

        if (s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_USERPTR &&
            !s->host_userptr_capture && !s->host_userptr_mplane) {
            error_setg(errp,
                       "virtio-media: host-v4l2-memory=userptr requested but host device does not support USERPTR");
            close(host_fd);
            return;
        }

        caps = host_caps;
        /*
         * Do not advertise V4L2_CAP_READWRITE: the proxy only implements the
         * streaming (QBUF/DQBUF) API, not read()/write(), so claiming it would
         * be a conformance lie.
         */
        caps &= V4L2_CAP_VIDEO_CAPTURE |
            V4L2_CAP_VIDEO_CAPTURE_MPLANE |
            V4L2_CAP_STREAMING |
            V4L2_CAP_EXT_PIX_FORMAT;
        s->config.device_caps = cpu_to_le32(caps);
        memset(s->config.card, 0, sizeof(s->config.card));
        snprintf((char *)s->config.card, sizeof(s->config.card),
                 "%s", (char *)cap.card);
        s->use_host_device = true;
        close(host_fd);
    } else {
        s->config.device_caps = cpu_to_le32(V4L2_CAP_VIDEO_CAPTURE |
                                            V4L2_CAP_VIDEO_CAPTURE_MPLANE |
                                            V4L2_CAP_STREAMING);
        memset(s->config.card, 0, sizeof(s->config.card));
        snprintf((char *)s->config.card, sizeof(s->config.card),
                 "%s", VIRTIO_MEDIA_CARD_NAME);
    }
    s->config.device_type = cpu_to_le32(0);

    s->hostmem_size = pow2ceil((uint64_t)s->max_buffers * buffer_size);
    s->hostmem_buf = NULL;
    s->use_grefs = use_grefs;
    s->gntalloc_fd = -1;
    s->gntalloc_index = 0;
    s->gref_count = 0;
    s->grefs = NULL;

    /*
     * In regrant-only mode the per-buffer pages are re-granted from the host
     * device's EXPBUF'd dma-bufs (per session, at REQBUFS time), so the
     * device-wide gntalloc pool / hostmem RAM region is never read or written.
     * Skip allocating it entirely: this avoids exhausting the dom0 gntalloc
     * limit when scaling guests, and lets buffer size grow at runtime (e.g.
     * higher resolution) without being capped by a pool fixed at realize.
     */
    s->regrant_only = s->use_host_device && use_grefs &&
                      s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_REGRANT;

    if (s->regrant_only) {
        s->hostmem_size = 0;
    } else if (s->use_grefs) {
        if (!vmedia_gntalloc_init(s, errp)) {
            return;
        }
    }

    if (!use_grefs) {
        if (s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_MMAP) {
            memory_region_init(&s->hostmem, OBJECT(s),
                               "virtio-media-hostmem",
                               s->hostmem_size);
        } else if (s->host_v4l2_mem_mode == VMEDIA_HOST_V4L2_MEM_USERPTR) {
            s->hostmem_buf = qemu_memalign(qemu_real_host_page_size(), s->hostmem_size);
            memory_region_init_ram_ptr(&s->hostmem, OBJECT(s),
                                       "virtio-media-hostmem",
                                       s->hostmem_size, s->hostmem_buf);
        }
    }

    s->use_hostmem = true;
    s->session_next_id = 1;
    s->next_share_handle = 1;
    s->sessions = g_hash_table_new(g_direct_hash, g_direct_equal);
    s->share_handles = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                             g_free, vmedia_share_free);
    QTAILQ_INIT(&s->pending_events);

    virtio_init(vdev, VIRTIO_ID_MEDIA, sizeof(s->config));
    s->command_vq = virtio_add_queue(vdev, VIRTIO_MEDIA_VQ_SIZE,
                                     vmedia_handle_command);
    s->event_vq = virtio_add_queue(vdev, VIRTIO_MEDIA_VQ_SIZE,
                                   vmedia_handle_event);
}

static void vmedia_drain_pending_events(VirtIOMedia *s)
{
    while (!QTAILQ_EMPTY(&s->pending_events)) {
        VirtIOMediaEvent *evt = QTAILQ_FIRST(&s->pending_events);

        QTAILQ_REMOVE(&s->pending_events, evt, next);
        g_free(evt);
    }
    s->pending_events_count = 0;
}

/*
 * Tear down all per-session state (host fds, host maps, buffers, grants) and
 * the pending event backlog. Called on device reset (guest reboot) and reused
 * by unrealize. Without this, a guest reset would leak host fds/grants and
 * leave stale sessions that the next guest could reference.
 */
static void vmedia_free_all_sessions(VirtIOMedia *s)
{
    GHashTableIter iter;
    gpointer key;
    gpointer value;

    if (!s->sessions) {
        return;
    }

    g_hash_table_iter_init(&iter, s->sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        vmedia_session_free(s, value);
    }
    g_hash_table_remove_all(s->sessions);
}

static void vmedia_reset(VirtIODevice *vdev)
{
    VirtIOMedia *s = VIRTIO_MEDIA(vdev);

    vmedia_free_all_sessions(s);
    if (s->share_handles) {
        g_hash_table_remove_all(s->share_handles);
    }
    vmedia_drain_pending_events(s);
}

static void vmedia_unrealize(DeviceState *dev)
{
    VirtIOMedia *s = VIRTIO_MEDIA(dev);
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    vmedia_free_all_sessions(s);
    g_hash_table_destroy(s->sessions);
    s->sessions = NULL;
    g_hash_table_destroy(s->share_handles);
    s->share_handles = NULL;

    vmedia_drain_pending_events(s);

    virtio_del_queue(vdev, VIRTIO_MEDIA_EVENT_VQ);
    virtio_del_queue(vdev, VIRTIO_MEDIA_COMMAND_VQ);
    virtio_cleanup(vdev);

    if (s->use_grefs) {
        vmedia_gntalloc_cleanup(s);
    }
}

static const Property virtio_media_properties[] = {
    DEFINE_PROP_UINT32("max-buffers", VirtIOMedia, max_buffers, 8),
    DEFINE_PROP_STRING("host-device", VirtIOMedia, host_device),
    DEFINE_PROP_STRING("host-v4l2-memory", VirtIOMedia, host_v4l2_mem),
    DEFINE_PROP_BOOL("xen-grants", VirtIOMedia, xen_grants, true),
};

static void vmedia_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_media_properties);
    dc->vmsd = &vmstate_virtio_media;
    vdc->realize = vmedia_realize;
    vdc->unrealize = vmedia_unrealize;
    vdc->reset = vmedia_reset;
    vdc->get_config = vmedia_get_config;
    vdc->get_features = vmedia_get_features;
}

static const TypeInfo virtio_media_info = {
    .name = TYPE_VIRTIO_MEDIA,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOMedia),
    .class_init = vmedia_class_init,
};

static void vmedia_register_types(void)
{
    type_register_static(&virtio_media_info);
}

type_init(vmedia_register_types);
