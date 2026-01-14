/*
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
#include "qemu/module.h"
#include "qemu/queue.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-media.h"
#include "standard-headers/linux/virtio_ids.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <linux/ioctl.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

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

#define VIRTIO_MEDIA_EVT_ERROR  0
#define VIRTIO_MEDIA_EVT_DQBUF  1
#define VIRTIO_MEDIA_EVT_EVENT  2

#define VIRTIO_MEDIA_MMAP_FLAG_RW (1 << 0)

#define VIRTIO_MEDIA_MAX_PLANES VIDEO_MAX_PLANES

#define VIRTIO_MEDIA_WIDTH  640u
#define VIRTIO_MEDIA_HEIGHT 480u
#define VIRTIO_MEDIA_PIXFMT_MPLANE V4L2_PIX_FMT_YUV420
#define VIRTIO_MEDIA_PIXFMT_SINGLE V4L2_PIX_FMT_YUYV
#define VIRTIO_MEDIA_BUFFER_SIZE_MPLANE (VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT * 3 / 2)
#define VIRTIO_MEDIA_BUFFER_SIZE_SINGLE (VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT * 2)

static int vmedia_ioctl_nointr(int fd, unsigned long req, void *arg);

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

struct virtio_media_resp_mmap {
    struct virtio_media_resp_header hdr;
    uint64_t driver_addr;
    uint64_t len;
};

struct virtio_media_cmd_munmap {
    struct virtio_media_cmd_header hdr;
    uint64_t driver_addr;
};

struct virtio_media_resp_munmap {
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

typedef struct VirtIOMediaBuffer {
    QTAILQ_ENTRY(VirtIOMediaBuffer) next;
    uint32_t index;
    bool queued;
    uint32_t sequence;
    uint64_t base_offset;
    uint64_t plane_offsets[3];
    uint32_t plane_lengths[3];
    struct v4l2_buffer buffer;
    struct v4l2_plane planes[3];
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
    bool host_streaming;
    void **host_maps;
    uint32_t *host_lengths;
    uint32_t *host_offsets;
    uint32_t host_num_buffers;
    uint32_t host_num_planes;
    uint32_t host_plane_lengths[VIRTIO_MEDIA_MAX_PLANES];
    QTAILQ_HEAD(, VirtIOMediaBuffer) queued_buffers;
} VirtIOMediaSession;

struct VirtIOMediaEvent {
    QTAILQ_ENTRY(VirtIOMediaEvent) next;
    size_t len;
    uint8_t data[sizeof(struct virtio_media_event_dqbuf)];
};

static void vmedia_host_fd_handler(void *opaque);
static void vmedia_emit_dqbuf(VirtIOMedia *s, VirtIOMediaSession *session,
                                    VirtIOMediaBuffer *buf);
static void vmedia_flush_events(VirtIOMedia *s);
static void vmedia_proxy_stop(VirtIOMediaSession *session);

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

static void vmedia_proxy_release_buffers(VirtIOMedia *s,
                                         VirtIOMediaSession *session)
{
    uint32_t i;
    uint32_t p;
    uint32_t planes;

    if (!s->use_host_device || !session->host_maps) {
        return;
    }

    planes = session->host_num_planes ? session->host_num_planes : 1;
    for (i = 0; i < session->host_num_buffers; i++) {
        for (p = 0; p < planes; p++) {
            uint32_t idx = i * planes + p;

            if (session->host_maps[idx]) {
                munmap(session->host_maps[idx], session->host_lengths[idx]);
            }
        }
    }

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
    VirtIOMediaEvent *evt = g_new0(VirtIOMediaEvent, 1);

    evt->len = MIN(len, sizeof(evt->data));
    memcpy(evt->data, data, evt->len);
    QTAILQ_INSERT_TAIL(&s->pending_events, evt, next);
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

    for (;;) {
        memset(&buf, 0, sizeof(buf));
        memset(planes, 0, sizeof(planes));
        buf.type = session->mplane ? V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE :
                                     V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        if (session->mplane) {
            buf.length = session->host_num_planes;
            buf.m.planes = planes;
        }

        int ret = vmedia_ioctl_nointr(session->host_fd, VIDIOC_DQBUF, &buf);
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

        if (session->mplane && session->host_num_planes) {
            uint32_t num_planes = MIN(session->host_num_planes,
                                      session->buffers[buf.index].buffer.length);
            for (uint32_t p = 0; p < num_planes; p++) {
                uint32_t idx = buf.index * session->host_num_planes + p;
                uint32_t bytes = planes[p].bytesused ?
                    planes[p].bytesused : session->host_lengths[idx];

                memcpy(memory_region_get_ram_ptr(&s->hostmem) +
                       session->buffers[buf.index].plane_offsets[p],
                       session->host_maps[idx],
                       MIN(bytes, session->buffers[buf.index].plane_lengths[p]));
                session->buffers[buf.index].planes[p].bytesused = bytes;
            }
        } else {
            memcpy(memory_region_get_ram_ptr(&s->hostmem) +
                   session->buffers[buf.index].base_offset,
                   session->host_maps[buf.index],
                   MIN(buf.bytesused, session->host_lengths[buf.index]));
        }

        session->buffers[buf.index].queued = false;
        session->buffers[buf.index].sequence = buf.sequence;
        if (!session->mplane) {
            session->buffers[buf.index].buffer.bytesused = buf.bytesused;
        }
        session->buffers[buf.index].buffer.timestamp = buf.timestamp;

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
        g_autofree VirtQueueElement *elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
        size_t in_len;
        size_t written;

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
    }
}

static void vmedia_fill_fmtdesc(struct v4l2_fmtdesc *desc, uint32_t type)
{
    memset(desc, 0, sizeof(*desc));
    desc->index = 0;
    desc->type = type;
    if (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        desc->pixelformat = VIRTIO_MEDIA_PIXFMT_MPLANE;
        snprintf((char *)desc->description, sizeof(desc->description), "YUV420");
    } else {
        desc->pixelformat = VIRTIO_MEDIA_PIXFMT_SINGLE;
        snprintf((char *)desc->description, sizeof(desc->description), "YUYV");
    }
}

static void vmedia_fill_format(struct v4l2_format *fmt, uint32_t type)
{
    memset(fmt, 0, sizeof(*fmt));
    fmt->type = type;
    if (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        struct v4l2_pix_format_mplane *pix_mp = &fmt->fmt.pix_mp;

        pix_mp->width = VIRTIO_MEDIA_WIDTH;
        pix_mp->height = VIRTIO_MEDIA_HEIGHT;
        pix_mp->pixelformat = VIRTIO_MEDIA_PIXFMT_MPLANE;
        pix_mp->field = V4L2_FIELD_NONE;
        pix_mp->colorspace = V4L2_COLORSPACE_SRGB;
        pix_mp->num_planes = 3;
        pix_mp->plane_fmt[0].sizeimage = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT;
        pix_mp->plane_fmt[0].bytesperline = VIRTIO_MEDIA_WIDTH;
        pix_mp->plane_fmt[1].sizeimage = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT / 4;
        pix_mp->plane_fmt[1].bytesperline = VIRTIO_MEDIA_WIDTH / 2;
        pix_mp->plane_fmt[2].sizeimage = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT / 4;
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
    uint8_t *base = memory_region_get_ram_ptr(&s->hostmem);
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
        buffer->timestamp.tv_sec = buf->sequence / 1000;
        buffer->timestamp.tv_usec = buf->sequence % 1000;
    }
    buffer->m.planes = NULL;

    if (session->mplane) {
        buf->planes[0].bytesused = buf->plane_lengths[0];
        buf->planes[1].bytesused = buf->plane_lengths[1];
        buf->planes[2].bytesused = buf->plane_lengths[2];
        memcpy(evt.planes, buf->planes, sizeof(buf->planes));
    } else {
        buffer->bytesused = session->buffer_size;
    }
    vmedia_queue_event(s, &evt, sizeof(evt));
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
                if (p > 0) {
                    buf->plane_offsets[p] =
                        buf->plane_offsets[p - 1] + plane_lengths[p - 1];
                }
                buf->plane_lengths[p] = plane_lengths[p];
                buf_size += plane_lengths[p];
            }
        } else {
            buf->plane_offsets[0] = offset;
            buf->plane_lengths[0] = session->buffer_size;
            buf_size = session->buffer_size;
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

    if (offset > s->hostmem_size) {
        return -ENOMEM;
    }

    return 0;
}

static int vmedia_find_plane(VirtIOMediaSession *session, uint32_t offset,
                                   uint64_t *addr, uint64_t *len)
{
    uint32_t i;

    for (i = 0; i < session->num_buffers; i++) {
        VirtIOMediaBuffer *buf = &session->buffers[i];
        int p;

        if (!session->mplane) {
            if (buf->plane_offsets[0] == offset) {
                *addr = buf->plane_offsets[0];
                *len = buf->plane_lengths[0];
                return 0;
            }
            continue;
        }

        for (p = 0; p < 3; p++) {
            if (buf->plane_offsets[p] == offset) {
                *addr = buf->plane_offsets[p];
                *len = buf->plane_lengths[p];
                return 0;
            }
        }
    }

    return -EINVAL;
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
                                     size_t offset, const struct v4l2_plane *planes,
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
        ret = vmedia_proxy_ioctl(fd, VIDIOC_ENUM_FMT, &desc);
        if (ret < 0) {
            break;
        }

        max_sizeimage = MAX(max_sizeimage,
                            vmedia_proxy_max_sizeimage_for_format(fd,
                                                                        desc.pixelformat));
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
                                size_t out_off)
{
    uint32_t input;

    if (vmedia_iov_read(out_sg, out_num, out_off, &input,
                              sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return vmedia_proxy_ioctl(session->host_fd, VIDIOC_S_INPUT, &input);
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

        stop_ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_STREAMOFF, &type);
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

    if (fmt.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        sizeimage = 0;
        for (int i = 0; i < fmt.fmt.pix_mp.num_planes; i++) {
            sizeimage += fmt.fmt.pix_mp.plane_fmt[i].sizeimage;
        }
        if (!sizeimage) {
            sizeimage = (uint64_t)fmt.fmt.pix_mp.width *
                        (uint64_t)fmt.fmt.pix_mp.height * 2;
        }
    } else {
        sizeimage = fmt.fmt.pix.sizeimage;
        if (!sizeimage) {
            sizeimage = (uint64_t)fmt.fmt.pix.width *
                        (uint64_t)fmt.fmt.pix.height * 2;
        }
    }
    if (sizeimage &&
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
    struct v4l2_buffer buf;
    uint32_t i;
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

    reqbufs.count = MIN(reqbufs.count, s->max_buffers);

    vmedia_proxy_release_buffers(s, session);

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS, &reqbufs);
    if (ret < 0) {
        return ret;
    }

    session->mplane = (reqbufs.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
    session->buffer_size = VIRTIO_MEDIA_BUFFER_SIZE_SINGLE;
    session->host_num_planes = session->mplane ? 0 : 1;
    session->host_num_buffers = reqbufs.count;

    if (reqbufs.count == 0) {
        vmedia_reset_buffers(session);
        if (vmedia_iov_write(in_sg, in_num, in_off, &reqbufs,
                                   sizeof(reqbufs)) != sizeof(reqbufs)) {
            return -EINVAL;
        }
        return 0;
    }

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
        session->host_num_planes = 1;
    }

    session->host_maps = g_new0(void *,
                                reqbufs.count * session->host_num_planes);
    session->host_lengths = g_new0(uint32_t,
                                   reqbufs.count * session->host_num_planes);
    session->host_offsets = g_new0(uint32_t,
                                   reqbufs.count * session->host_num_planes);

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
            memset(&reqbufs, 0, sizeof(reqbufs));
            reqbufs.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
            reqbufs.memory = V4L2_MEMORY_MMAP;
            vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS, &reqbufs);
            return ret;
        }

        if (session->mplane) {
            uint32_t p;

            for (p = 0; p < session->host_num_planes; p++) {
                uint32_t idx = i * session->host_num_planes + p;

                session->host_offsets[idx] = planes[p].m.mem_offset;
                session->host_lengths[idx] = planes[p].length;
                session->host_maps[idx] = mmap(NULL, planes[p].length,
                                               PROT_READ | PROT_WRITE,
                                               MAP_SHARED,
                                               session->host_fd,
                                               planes[p].m.mem_offset);
                if (session->host_maps[idx] == MAP_FAILED) {
                    session->host_maps[idx] = NULL;
                    ret = -errno;
                    vmedia_proxy_release_buffers(s, session);
                    memset(&reqbufs, 0, sizeof(reqbufs));
                    reqbufs.type = session->mplane ?
                        V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE :
                        V4L2_BUF_TYPE_VIDEO_CAPTURE;
                    reqbufs.memory = V4L2_MEMORY_MMAP;
                    vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS,
                                       &reqbufs);
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
            session->host_maps[i] = mmap(NULL, buf.length,
                                         PROT_READ | PROT_WRITE, MAP_SHARED,
                                         session->host_fd, buf.m.offset);
            if (session->host_maps[i] == MAP_FAILED) {
                session->host_maps[i] = NULL;
                ret = -errno;
                vmedia_proxy_release_buffers(s, session);
                memset(&reqbufs, 0, sizeof(reqbufs));
                reqbufs.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
                reqbufs.memory = V4L2_MEMORY_MMAP;
                vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS, &reqbufs);
                return ret;
            }
            session->host_lengths[i] = buf.length;
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

    ret = vmedia_alloc_buffers(s, session, reqbufs.count);
    if (ret < 0) {
        vmedia_proxy_release_buffers(s, session);
        memset(&reqbufs, 0, sizeof(reqbufs));
        reqbufs.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        reqbufs.memory = V4L2_MEMORY_MMAP;
        vmedia_proxy_ioctl(session->host_fd, VIDIOC_REQBUFS, &reqbufs);
        return ret;
    }

    reqbufs.count = session->num_buffers;
    if (vmedia_iov_write(in_sg, in_num, in_off, &reqbufs,
                               sizeof(reqbufs)) != sizeof(reqbufs)) {
        return -EINVAL;
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
    if ((buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
         buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
        buf.memory != V4L2_MEMORY_MMAP ||
        index >= session->num_buffers) {
        return -EINVAL;
    }

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

        for (i = 0; i < session->buffers[index].buffer.length; i++) {
            planes[i].length = session->buffers[index].plane_lengths[i];
            planes[i].bytesused = 0;
            planes[i].m.mem_offset = session->buffers[index].plane_offsets[i];
        }

        buf.length = session->buffers[index].buffer.length;
        buf.bytesused = 0;
        buf.flags = 0;

        if (vmedia_iov_write(in_sg, in_num, in_off, &buf,
                             sizeof(buf)) != sizeof(buf)) {
            return -EINVAL;
        }
        if (vmedia_write_planes(in_sg, in_num,
                                in_off + sizeof(buf),
                                planes, session->buffers[index].buffer.length)) {
            return -EINVAL;
        }
        *payload_len = sizeof(struct v4l2_buffer) +
            sizeof(struct v4l2_plane) * session->buffers[index].buffer.length;
    } else {
        buf.length = session->buffers[index].plane_lengths[0];
        buf.bytesused = 0;
        buf.flags = 0;
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
        return -EINVAL;
    }

    if ((buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
         buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
        buf.memory != V4L2_MEMORY_MMAP) {
        return -EINVAL;
    }

    if (session->mplane != (buf.type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)) {
        return -EINVAL;
    }

    index = buf.index;
    if (index >= session->num_buffers || index >= session->host_num_buffers) {
        return -EINVAL;
    }

    if (session->buffers[index].queued) {
        return -EINVAL;
    }

    memset(&host_buf, 0, sizeof(host_buf));
    host_buf.type = session->mplane ? V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE :
                                      V4L2_BUF_TYPE_VIDEO_CAPTURE;
    host_buf.memory = V4L2_MEMORY_MMAP;
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

            planes[p].length = session->host_lengths[idx];
            planes[p].m.mem_offset = session->host_offsets[idx];
        }
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_QBUF, &host_buf);
    if (ret < 0) {
        return ret;
    }

    session->buffers[index].queued = true;

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

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_ENUM_FRAMESIZES, &frmsize);
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
                                                  const struct iovec *out_sg, int out_num,
                                                  const struct iovec *in_sg, int in_num,
                                                  size_t out_off, size_t in_off)
{
    struct v4l2_frmivalenum frmival;
    int ret;

    if (vmedia_iov_read(out_sg, out_num, out_off, &frmival,
                              sizeof(frmival)) != sizeof(frmival)) {
        return -EINVAL;
    }

    ret = vmedia_proxy_ioctl(session->host_fd, VIDIOC_ENUM_FRAMEINTERVALS, &frmival);
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

static int vmedia_proxy_ext_ctrls(VirtIOMediaSession *session, unsigned long req,
                                        const struct iovec *out_sg, int out_num,
                                        const struct iovec *in_sg, int in_num,
                                        size_t out_off, size_t in_off,
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
        size_t controls_size = ctrls.count * sizeof(*controls);
        size_t base = sizeof(ctrls) + controls_size;
        size_t out_len = iov_size(out_sg, out_num);

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

    ret = vmedia_proxy_ioctl(session->host_fd, req, buf);
    if (ret < 0) {
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

        for (i = 0; i < 3; i++) {
            planes[i].length = session->buffers[index].plane_lengths[i];
            planes[i].bytesused = 0;
            planes[i].m.mem_offset = session->buffers[index].plane_offsets[i];
        }

        buf.length = 3;
        buf.bytesused = 0;
        buf.flags = 0;

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
        buf.flags = 0;
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

    QTAILQ_INSERT_TAIL(&session->queued_buffers, &session->buffers[index], next);

    if (session->streaming) {
        VirtIOMediaBuffer *qbuf = QTAILQ_FIRST(&session->queued_buffers);
        QTAILQ_REMOVE(&session->queued_buffers, qbuf, next);
        qbuf->queued = false;
        vmedia_generate_frame(s, session, qbuf);
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
                                      size_t out_off)
{
    uint32_t input;

    if (vmedia_iov_read(out_sg, out_num, out_off, &input,
                              sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return (input == 0) ? 0 : -EINVAL;
}

static int vmedia_ioctl_subscribe_event(const struct iovec *out_sg,
		                              int out_num,
                                              size_t out_off)
{
    struct v4l2_event_subscription sub;

    if (vmedia_iov_read(out_sg, out_num, out_off, &sub,
                              sizeof(sub)) != sizeof(sub)) {
        return -EINVAL;
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
        *payload_len = 0;
        if (s->use_host_device) {
            return vmedia_proxy_s_input(session, elem->out_sg, elem->out_num,
                                        out_off);
        }
        return vmedia_ioctl_s_input(elem->out_sg, elem->out_num, out_off);
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
            return vmedia_proxy_crop(session, false, elem->out_sg, elem->out_num,
                                           elem->in_sg, elem->in_num,
                                           out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_S_CROP):
        *payload_len = sizeof(struct v4l2_crop);
        if (s->use_host_device) {
            return vmedia_proxy_crop(session, true, elem->out_sg, elem->out_num,
                                           elem->in_sg, elem->in_num,
                                           out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_G_SELECTION):
        *payload_len = sizeof(struct v4l2_selection);
        if (s->use_host_device) {
            return vmedia_proxy_selection(session, false, elem->out_sg, elem->out_num,
                                                elem->in_sg, elem->in_num,
                                                out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_S_SELECTION):
        *payload_len = sizeof(struct v4l2_selection);
        if (s->use_host_device) {
            return vmedia_proxy_selection(session, true, elem->out_sg, elem->out_num,
                                                elem->in_sg, elem->in_num,
                                                out_off, in_off);
        }
        return -ENOTTY;
    case _IOC_NR(VIDIOC_QUERY_EXT_CTRL):
        *payload_len = sizeof(struct v4l2_query_ext_ctrl);
        if (s->use_host_device) {
            return vmedia_proxy_query_ext_ctrl(session, elem->out_sg, elem->out_num,
                                                     elem->in_sg, elem->in_num,
                                                     out_off, in_off);
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
    case _IOC_NR(VIDIOC_SUBSCRIBE_EVENT):
    case _IOC_NR(VIDIOC_UNSUBSCRIBE_EVENT):
        *payload_len = 0;
        return vmedia_ioctl_subscribe_event(elem->out_sg, elem->out_num,
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
        int status = 0;
        int host_fd = -1;

        if (in_len < sizeof(resp)) {
            virtio_error(vdev, "virtio-media: short OPEN response buffer");
            virtqueue_push(vq, elem, 0);
            break;
        }

        if (s->use_host_device) {
            host_fd = open(s->host_device, O_RDWR | O_NONBLOCK);
            if (host_fd < 0) {
                status = errno;
            }
        }

        if (status == 0) {
            session = vmedia_session_new(s, s->session_next_id++);
            session->host_fd = host_fd;
            g_hash_table_insert(s->sessions, GUINT_TO_POINTER(session->id),
                                session);
        } else if (host_fd >= 0) {
            close(host_fd);
        }

        vmedia_write_resp_header(&resp.hdr, status);
        resp.session_id = cpu_to_le32(status == 0 ? session->id : 0);
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
                                  &close_cmd, sizeof(close_cmd)) != sizeof(close_cmd)) {
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
                                  &ioctl_cmd, sizeof(ioctl_cmd)) != sizeof(ioctl_cmd)) {
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
        if (status < 0) {
            payload_len = 0;
        }

        vmedia_write_resp_header(&resp.hdr, status < 0 ? -status : 0);
        vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                               &resp, sizeof(resp));
        used = sizeof(resp) + payload_len;
        if (used > in_len) {
            used = in_len;
        }
        virtqueue_push(vq, elem, used);
        break;
    }
    case VIRTIO_MEDIA_CMD_MMAP: {
        struct virtio_media_cmd_mmap mmap_cmd;
        struct virtio_media_resp_mmap resp;
        VirtIOMediaSession *session;
        uint64_t addr = 0;
        uint64_t len = 0;
        uint32_t id;
        int status;

        if (in_len < sizeof(resp)) {
            virtio_error(vdev, "virtio-media: short MMAP response buffer");
            virtqueue_push(vq, elem, 0);
            break;
        }

        if (vmedia_iov_read(elem->out_sg, elem->out_num, 0,
                                  &mmap_cmd, sizeof(mmap_cmd)) != sizeof(mmap_cmd)) {
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
        vmedia_iov_write(elem->in_sg, elem->in_num, 0,
                               &resp, sizeof(resp));
        virtqueue_push(vq, elem, sizeof(resp));
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
    int caps;

    if (s->max_buffers == 0) {
        s->max_buffers = 8;
    }

    s->use_host_device = false;

    if (s->host_device) {
        uint64_t max_sizeimage;
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
        if (vmedia_ioctl_nointr(host_fd, VIDIOC_G_FMT, &fmt) == 0 &&
            fmt.fmt.pix.sizeimage > 0) {
            buffer_size = fmt.fmt.pix.sizeimage;
        }

        max_sizeimage = vmedia_proxy_max_sizeimage(host_fd);
        if (max_sizeimage > buffer_size) {
            buffer_size = max_sizeimage;
        }

        caps = cap.device_caps ? cap.device_caps : cap.capabilities;
        caps &= V4L2_CAP_VIDEO_CAPTURE |
            V4L2_CAP_VIDEO_CAPTURE_MPLANE |
            V4L2_CAP_STREAMING |
            V4L2_CAP_READWRITE |
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
    memory_region_init_ram(&s->hostmem, OBJECT(s), "virtio-media-hostmem",
                           s->hostmem_size, errp);
    if (*errp) {
        return;
    }

    s->use_hostmem = true;
    s->session_next_id = 1;
    s->sessions = g_hash_table_new(g_direct_hash, g_direct_equal);
    QTAILQ_INIT(&s->pending_events);

    virtio_init(vdev, VIRTIO_ID_MEDIA, sizeof(s->config));
    s->command_vq = virtio_add_queue(vdev, VIRTIO_MEDIA_VQ_SIZE,
                                     vmedia_handle_command);
    s->event_vq = virtio_add_queue(vdev, VIRTIO_MEDIA_VQ_SIZE,
                                   vmedia_handle_event);
}

static void vmedia_unrealize(DeviceState *dev)
{
    VirtIOMedia *s = VIRTIO_MEDIA(dev);
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    GHashTableIter iter;
    gpointer key;
    gpointer value;
    VirtIOMediaEvent *evt;

    g_hash_table_iter_init(&iter, s->sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        vmedia_session_free(s, value);
    }
    g_hash_table_destroy(s->sessions);
    s->sessions = NULL;

    while (!QTAILQ_EMPTY(&s->pending_events)) {
        evt = QTAILQ_FIRST(&s->pending_events);
        QTAILQ_REMOVE(&s->pending_events, evt, next);
        g_free(evt);
    }

    virtio_del_queue(vdev, VIRTIO_MEDIA_EVENT_VQ);
    virtio_del_queue(vdev, VIRTIO_MEDIA_COMMAND_VQ);
    virtio_cleanup(vdev);
}

static const Property virtio_media_properties[] = {
    DEFINE_PROP_UINT32("max-buffers", VirtIOMedia, max_buffers, 8),
    DEFINE_PROP_STRING("host-device", VirtIOMedia, host_device),
};

static void vmedia_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_media_properties);
    dc->vmsd = &vmstate_virtio_media;
    vdc->realize = vmedia_realize;
    vdc->unrealize = vmedia_unrealize;
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
