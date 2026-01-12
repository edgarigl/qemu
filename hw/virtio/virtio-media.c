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
#include "qemu/module.h"
#include "qemu/queue.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-media.h"
#include "standard-headers/linux/virtio_ids.h"

#include <glib.h>
#include <linux/ioctl.h>
#include <linux/videodev2.h>

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
#define VIRTIO_MEDIA_PIXFMT V4L2_PIX_FMT_YUV420
#define VIRTIO_MEDIA_BUFFER_SIZE (VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT * 3 / 2)

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
    uint32_t id;
    bool streaming;
    uint32_t sequence;
    uint32_t num_buffers;
    VirtIOMediaBuffer *buffers;
    QTAILQ_HEAD(, VirtIOMediaBuffer) queued_buffers;
} VirtIOMediaSession;

struct VirtIOMediaEvent {
    QTAILQ_ENTRY(VirtIOMediaEvent) next;
    size_t len;
    uint8_t data[sizeof(struct virtio_media_event_dqbuf)];
};

static void virtio_media_reset_buffers(VirtIOMediaSession *session)
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

static void virtio_media_session_free(VirtIOMediaSession *session)
{
    if (!session) {
        return;
    }

    virtio_media_reset_buffers(session);
    g_free(session);
}

static VirtIOMediaSession *virtio_media_session_new(uint32_t id)
{
    VirtIOMediaSession *session = g_new0(VirtIOMediaSession, 1);

    session->id = id;
    QTAILQ_INIT(&session->queued_buffers);
    return session;
}

static size_t virtio_media_iov_read(const struct iovec *iov, int iov_cnt,
                                    size_t offset, void *dst, size_t len)
{
    return iov_to_buf(iov, iov_cnt, offset, dst, len);
}

static size_t virtio_media_iov_write(const struct iovec *iov, int iov_cnt,
                                     size_t offset, const void *src, size_t len)
{
    return iov_from_buf(iov, iov_cnt, offset, src, len);
}

static void virtio_media_write_resp_header(struct virtio_media_resp_header *resp,
                                           int status)
{
    resp->status = cpu_to_le32(status);
    resp->reserved = 0;
}

static void virtio_media_queue_event(VirtIOMedia *s, const void *data, size_t len)
{
    VirtIOMediaEvent *evt = g_new0(VirtIOMediaEvent, 1);

    evt->len = MIN(len, sizeof(evt->data));
    memcpy(evt->data, data, evt->len);
    QTAILQ_INSERT_TAIL(&s->pending_events, evt, next);
}

static void virtio_media_flush_events(VirtIOMedia *s)
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
        written = virtio_media_iov_write(elem->in_sg, elem->in_num, 0,
                                         evt->data, MIN(in_len, evt->len));
        virtqueue_push(vq, elem, written);
        virtio_notify(&s->parent_obj, vq);
        QTAILQ_REMOVE(&s->pending_events, evt, next);
        g_free(evt);
    }
}

static void virtio_media_fill_fmtdesc(struct v4l2_fmtdesc *desc, uint32_t type)
{
    memset(desc, 0, sizeof(*desc));
    desc->index = 0;
    desc->type = type;
    desc->pixelformat = VIRTIO_MEDIA_PIXFMT;
    snprintf((char *)desc->description, sizeof(desc->description), "YUV420");
}

static void virtio_media_fill_format(struct v4l2_format *fmt, uint32_t type)
{
    struct v4l2_pix_format_mplane *pix_mp = &fmt->fmt.pix_mp;

    memset(fmt, 0, sizeof(*fmt));
    fmt->type = type;
    pix_mp->width = VIRTIO_MEDIA_WIDTH;
    pix_mp->height = VIRTIO_MEDIA_HEIGHT;
    pix_mp->pixelformat = VIRTIO_MEDIA_PIXFMT;
    pix_mp->field = V4L2_FIELD_NONE;
    pix_mp->colorspace = V4L2_COLORSPACE_SRGB;
    pix_mp->num_planes = 3;
    pix_mp->plane_fmt[0].sizeimage = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT;
    pix_mp->plane_fmt[0].bytesperline = VIRTIO_MEDIA_WIDTH;
    pix_mp->plane_fmt[1].sizeimage = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT / 4;
    pix_mp->plane_fmt[1].bytesperline = VIRTIO_MEDIA_WIDTH / 2;
    pix_mp->plane_fmt[2].sizeimage = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT / 4;
    pix_mp->plane_fmt[2].bytesperline = VIRTIO_MEDIA_WIDTH / 2;
}

static void virtio_media_generate_frame(VirtIOMedia *s, VirtIOMediaSession *session,
                                        VirtIOMediaBuffer *buf)
{
    uint8_t *base = memory_region_get_ram_ptr(&s->hostmem);
    uint8_t *ptr = base + buf->base_offset;
    uint32_t y_size = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT;
    uint32_t uv_size = y_size / 4;
    uint8_t y = session->sequence % 256;
    uint8_t u = (session->sequence + 64) % 256;
    uint8_t v = (session->sequence + 128) % 256;

    memset(ptr, y, y_size);
    memset(ptr + y_size, u, uv_size);
    memset(ptr + y_size + uv_size, v, uv_size);

    buf->sequence = session->sequence++;
}

static void virtio_media_emit_dqbuf(VirtIOMedia *s, VirtIOMediaSession *session,
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
    buffer->timestamp.tv_sec = buf->sequence / 1000;
    buffer->timestamp.tv_usec = buf->sequence % 1000;
    buffer->m.planes = NULL;

    buf->planes[0].bytesused = buf->plane_lengths[0];
    buf->planes[1].bytesused = buf->plane_lengths[1];
    buf->planes[2].bytesused = buf->plane_lengths[2];
    memcpy(evt.planes, buf->planes, sizeof(buf->planes));
    virtio_media_queue_event(s, &evt, sizeof(evt));
}

static int virtio_media_alloc_buffers(VirtIOMedia *s, VirtIOMediaSession *session,
                                      uint32_t count)
{
    uint64_t offset = 0;
    uint32_t i;

    virtio_media_reset_buffers(session);

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

        buf->index = i;
        buf->queued = false;
        buf->base_offset = offset;
        buf->plane_offsets[0] = offset;
        buf->plane_offsets[1] = offset + VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT;
        buf->plane_offsets[2] = buf->plane_offsets[1] + VIRTIO_MEDIA_WIDTH *
                                                   VIRTIO_MEDIA_HEIGHT / 4;
        buf->plane_lengths[0] = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT;
        buf->plane_lengths[1] = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT / 4;
        buf->plane_lengths[2] = VIRTIO_MEDIA_WIDTH * VIRTIO_MEDIA_HEIGHT / 4;

        memset(&buf->buffer, 0, sizeof(buf->buffer));
        buf->buffer.index = i;
        buf->buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
        buf->buffer.memory = V4L2_MEMORY_MMAP;
        buf->buffer.length = 3;
        buf->buffer.m.planes = planes;

        memset(planes, 0, sizeof(buf->planes));
        planes[0].length = buf->plane_lengths[0];
        planes[0].m.mem_offset = buf->plane_offsets[0];
        planes[1].length = buf->plane_lengths[1];
        planes[1].m.mem_offset = buf->plane_offsets[1];
        planes[2].length = buf->plane_lengths[2];
        planes[2].m.mem_offset = buf->plane_offsets[2];

        offset += VIRTIO_MEDIA_BUFFER_SIZE;
    }

    if (offset > s->hostmem_size) {
        return -ENOMEM;
    }

    return 0;
}

static int virtio_media_find_plane(VirtIOMediaSession *session, uint32_t offset,
                                   uint64_t *addr, uint64_t *len)
{
    uint32_t i;

    for (i = 0; i < session->num_buffers; i++) {
        VirtIOMediaBuffer *buf = &session->buffers[i];
        int p;

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

static int virtio_media_read_planes(const struct iovec *iov, int iov_cnt,
                                    size_t offset, struct v4l2_plane *planes,
                                    uint32_t num_planes)
{
    size_t len = sizeof(struct v4l2_plane) * num_planes;
    size_t read = virtio_media_iov_read(iov, iov_cnt, offset, planes, len);

    return (read == len) ? 0 : -EINVAL;
}

static int virtio_media_write_planes(const struct iovec *iov, int iov_cnt,
                                     size_t offset, const struct v4l2_plane *planes,
                                     uint32_t num_planes)
{
    size_t len = sizeof(struct v4l2_plane) * num_planes;
    size_t written = virtio_media_iov_write(iov, iov_cnt, offset, planes, len);

    return (written == len) ? 0 : -EINVAL;
}

static int virtio_media_ioctl_enum_fmt(VirtIOMediaSession *session,
                                       const struct iovec *out_sg, int out_num,
                                       const struct iovec *in_sg, int in_num,
                                       size_t out_off, size_t in_off)
{
    struct v4l2_fmtdesc desc;

    (void)session;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &desc,
                              sizeof(desc)) != sizeof(desc)) {
        return -EINVAL;
    }

    if (desc.index != 0 ||
        desc.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    virtio_media_fill_fmtdesc(&desc, desc.type);

    if (virtio_media_iov_write(in_sg, in_num, in_off, &desc,
                               sizeof(desc)) != sizeof(desc)) {
        return -EINVAL;
    }

    return 0;
}

static int virtio_media_ioctl_g_fmt(const struct iovec *in_sg, int in_num,
                                    size_t in_off)
{
    struct v4l2_format fmt;

    virtio_media_fill_format(&fmt, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
    if (virtio_media_iov_write(in_sg, in_num, in_off, &fmt,
                               sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    return 0;
}

static int virtio_media_ioctl_s_fmt(const struct iovec *out_sg, int out_num,
                                    const struct iovec *in_sg, int in_num,
                                    size_t out_off, size_t in_off)
{
    struct v4l2_format fmt;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &fmt,
                              sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    if (fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    virtio_media_fill_format(&fmt, fmt.type);
    if (virtio_media_iov_write(in_sg, in_num, in_off, &fmt,
                               sizeof(fmt)) != sizeof(fmt)) {
        return -EINVAL;
    }

    return 0;
}

static int virtio_media_ioctl_reqbufs(VirtIOMedia *s, VirtIOMediaSession *session,
                                      const struct iovec *out_sg, int out_num,
                                      const struct iovec *in_sg, int in_num,
                                      size_t out_off, size_t in_off)
{
    struct v4l2_requestbuffers reqbufs;
    int ret;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &reqbufs,
                              sizeof(reqbufs)) != sizeof(reqbufs)) {
        return -EINVAL;
    }

    if (reqbufs.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE ||
        reqbufs.memory != V4L2_MEMORY_MMAP) {
        return -EINVAL;
    }

    ret = virtio_media_alloc_buffers(s, session, reqbufs.count);
    if (ret < 0) {
        return ret;
    }

    reqbufs.count = session->num_buffers;
    if (virtio_media_iov_write(in_sg, in_num, in_off, &reqbufs,
                               sizeof(reqbufs)) != sizeof(reqbufs)) {
        return -EINVAL;
    }

    return 0;
}

static int virtio_media_ioctl_querybuf(VirtIOMediaSession *session,
                                       const struct iovec *out_sg, int out_num,
                                       const struct iovec *in_sg, int in_num,
                                       size_t out_off, size_t in_off)
{
    struct v4l2_buffer buf;
    struct v4l2_plane planes[3];
    uint32_t index;
    uint32_t length;
    uint32_t i;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &buf,
                              sizeof(buf)) != sizeof(buf)) {
        return -EINVAL;
    }

    index = buf.index;
    length = buf.length;
    if (buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE ||
        buf.memory != V4L2_MEMORY_MMAP ||
        index >= session->num_buffers ||
        length < 3) {
        return -EINVAL;
    }

    if (virtio_media_read_planes(out_sg, out_num,
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

    if (virtio_media_iov_write(in_sg, in_num, in_off, &buf,
                               sizeof(buf)) != sizeof(buf)) {
        return -EINVAL;
    }
    if (virtio_media_write_planes(in_sg, in_num,
                                  in_off + sizeof(buf),
                                  planes, 3)) {
        return -EINVAL;
    }

    return 0;
}

static int virtio_media_ioctl_qbuf(VirtIOMedia *s, VirtIOMediaSession *session,
                                   const struct iovec *out_sg, int out_num,
                                   const struct iovec *in_sg, int in_num,
                                   size_t out_off, size_t in_off)
{
    struct v4l2_buffer buf;
    struct v4l2_plane planes[3];
    uint32_t index;
    uint32_t length;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &buf,
                              sizeof(buf)) != sizeof(buf)) {
        return -EINVAL;
    }

    index = buf.index;
    length = buf.length;
    if (buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE ||
        buf.memory != V4L2_MEMORY_MMAP ||
        index >= session->num_buffers ||
        length < 3) {
        return -EINVAL;
    }

    if (virtio_media_read_planes(out_sg, out_num,
                                 out_off + sizeof(buf),
                                 planes, 3)) {
        return -EINVAL;
    }

    if (session->buffers[index].queued) {
        return -EINVAL;
    }

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
    session->buffers[index].queued = true;

    QTAILQ_INSERT_TAIL(&session->queued_buffers, &session->buffers[index], next);

    if (session->streaming) {
        VirtIOMediaBuffer *qbuf = QTAILQ_FIRST(&session->queued_buffers);
        QTAILQ_REMOVE(&session->queued_buffers, qbuf, next);
        qbuf->queued = false;
        virtio_media_generate_frame(s, session, qbuf);
        virtio_media_emit_dqbuf(s, session, qbuf);
        virtio_media_flush_events(s);
    }

    if (virtio_media_iov_write(in_sg, in_num, in_off, &buf,
                               sizeof(buf)) != sizeof(buf)) {
        return -EINVAL;
    }
    if (virtio_media_write_planes(in_sg, in_num,
                                  in_off + sizeof(buf),
                                  planes, 3)) {
        return -EINVAL;
    }

    return 0;
}

static int virtio_media_ioctl_streamon(VirtIOMedia *s, VirtIOMediaSession *session,
                                       const struct iovec *out_sg, int out_num,
                                       size_t out_off)
{
    uint32_t type;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &type,
                              sizeof(type)) != sizeof(type)) {
        return -EINVAL;
    }

    if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    session->streaming = true;
    while (!QTAILQ_EMPTY(&session->queued_buffers)) {
        VirtIOMediaBuffer *qbuf = QTAILQ_FIRST(&session->queued_buffers);
        QTAILQ_REMOVE(&session->queued_buffers, qbuf, next);
        qbuf->queued = false;
        virtio_media_generate_frame(s, session, qbuf);
        virtio_media_emit_dqbuf(s, session, qbuf);
    }
    virtio_media_flush_events(s);
    return 0;
}

static int virtio_media_ioctl_streamoff(VirtIOMediaSession *session,
                                        const struct iovec *out_sg, int out_num,
                                        size_t out_off)
{
    uint32_t type;
    uint32_t i;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &type,
                              sizeof(type)) != sizeof(type)) {
        return -EINVAL;
    }

    if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        return -EINVAL;
    }

    session->streaming = false;
    QTAILQ_INIT(&session->queued_buffers);
    for (i = 0; i < session->num_buffers; i++) {
        session->buffers[i].queued = false;
    }
    return 0;
}

static int virtio_media_ioctl_enuminput(const struct iovec *out_sg, int out_num,
                                        const struct iovec *in_sg, int in_num,
                                        size_t out_off, size_t in_off)
{
    struct v4l2_input input;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &input,
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

    if (virtio_media_iov_write(in_sg, in_num, in_off, &input,
                               sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return 0;
}

static int virtio_media_ioctl_g_input(const struct iovec *in_sg, int in_num,
                                      size_t in_off)
{
    uint32_t input = 0;

    if (virtio_media_iov_write(in_sg, in_num, in_off, &input,
                               sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return 0;
}

static int virtio_media_ioctl_s_input(const struct iovec *out_sg, int out_num,
                                      size_t out_off)
{
    uint32_t input;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &input,
                              sizeof(input)) != sizeof(input)) {
        return -EINVAL;
    }

    return (input == 0) ? 0 : -EINVAL;
}

static int virtio_media_ioctl_subscribe_event(const struct iovec *out_sg, int out_num,
                                              size_t out_off)
{
    struct v4l2_event_subscription sub;

    if (virtio_media_iov_read(out_sg, out_num, out_off, &sub,
                              sizeof(sub)) != sizeof(sub)) {
        return -EINVAL;
    }

    return 0;
}

static int virtio_media_handle_ioctl(VirtIOMedia *s, VirtIOMediaSession *session,
                                     uint32_t code, VirtQueueElement *elem,
                                     size_t *payload_len)
{
    size_t out_off = sizeof(struct virtio_media_cmd_ioctl);
    size_t in_off = sizeof(struct virtio_media_resp_ioctl);

    switch (code) {
    case _IOC_NR(VIDIOC_ENUM_FMT):
        *payload_len = sizeof(struct v4l2_fmtdesc);
        return virtio_media_ioctl_enum_fmt(session, elem->out_sg, elem->out_num,
                                           elem->in_sg, elem->in_num,
                                           out_off, in_off);
    case _IOC_NR(VIDIOC_G_FMT):
        *payload_len = sizeof(struct v4l2_format);
        return virtio_media_ioctl_g_fmt(elem->in_sg, elem->in_num, in_off);
    case _IOC_NR(VIDIOC_S_FMT):
    case _IOC_NR(VIDIOC_TRY_FMT):
        *payload_len = sizeof(struct v4l2_format);
        return virtio_media_ioctl_s_fmt(elem->out_sg, elem->out_num,
                                        elem->in_sg, elem->in_num,
                                        out_off, in_off);
    case _IOC_NR(VIDIOC_REQBUFS):
        *payload_len = sizeof(struct v4l2_requestbuffers);
        return virtio_media_ioctl_reqbufs(s, session, elem->out_sg, elem->out_num,
                                          elem->in_sg, elem->in_num,
                                          out_off, in_off);
    case _IOC_NR(VIDIOC_QUERYBUF):
        *payload_len = sizeof(struct v4l2_buffer) + sizeof(struct v4l2_plane) * 3;
        return virtio_media_ioctl_querybuf(session, elem->out_sg, elem->out_num,
                                           elem->in_sg, elem->in_num,
                                           out_off, in_off);
    case _IOC_NR(VIDIOC_QBUF):
        *payload_len = sizeof(struct v4l2_buffer) + sizeof(struct v4l2_plane) * 3;
        return virtio_media_ioctl_qbuf(s, session, elem->out_sg, elem->out_num,
                                       elem->in_sg, elem->in_num,
                                       out_off, in_off);
    case _IOC_NR(VIDIOC_STREAMON):
        *payload_len = 0;
        return virtio_media_ioctl_streamon(s, session, elem->out_sg,
                                           elem->out_num, out_off);
    case _IOC_NR(VIDIOC_STREAMOFF):
        *payload_len = 0;
        return virtio_media_ioctl_streamoff(session, elem->out_sg,
                                            elem->out_num, out_off);
    case _IOC_NR(VIDIOC_ENUMINPUT):
        *payload_len = sizeof(struct v4l2_input);
        return virtio_media_ioctl_enuminput(elem->out_sg, elem->out_num,
                                            elem->in_sg, elem->in_num,
                                            out_off, in_off);
    case _IOC_NR(VIDIOC_G_INPUT):
        *payload_len = sizeof(uint32_t);
        return virtio_media_ioctl_g_input(elem->in_sg, elem->in_num, in_off);
    case _IOC_NR(VIDIOC_S_INPUT):
        *payload_len = 0;
        return virtio_media_ioctl_s_input(elem->out_sg, elem->out_num, out_off);
    case _IOC_NR(VIDIOC_SUBSCRIBE_EVENT):
    case _IOC_NR(VIDIOC_UNSUBSCRIBE_EVENT):
        *payload_len = 0;
        return virtio_media_ioctl_subscribe_event(elem->out_sg, elem->out_num,
                                                  out_off);
    default:
        *payload_len = 0;
        return -ENOTTY;
    }
}

static void virtio_media_handle_command(VirtIODevice *vdev, VirtQueue *vq)
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

        if (virtio_media_iov_read(elem->out_sg, elem->out_num, 0,
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
        VirtIOMediaSession *session;

        if (in_len < sizeof(resp)) {
            virtio_error(vdev, "virtio-media: short OPEN response buffer");
            virtqueue_push(vq, elem, 0);
            break;
        }

        session = virtio_media_session_new(s->session_next_id++);
        g_hash_table_insert(s->sessions, GUINT_TO_POINTER(session->id), session);

        virtio_media_write_resp_header(&resp.hdr, 0);
        resp.session_id = cpu_to_le32(session->id);
        resp.reserved = 0;
        virtio_media_iov_write(elem->in_sg, elem->in_num, 0,
                               &resp, sizeof(resp));
        virtqueue_push(vq, elem, sizeof(resp));
        break;
    }
    case VIRTIO_MEDIA_CMD_CLOSE: {
        struct virtio_media_cmd_close close_cmd;
        uint32_t id;
        VirtIOMediaSession *session;

        if (virtio_media_iov_read(elem->out_sg, elem->out_num, 0,
                                  &close_cmd, sizeof(close_cmd)) != sizeof(close_cmd)) {
            virtqueue_push(vq, elem, 0);
            break;
        }

        id = le32_to_cpu(close_cmd.session_id);
        session = g_hash_table_lookup(s->sessions, GUINT_TO_POINTER(id));
        if (session) {
            g_hash_table_remove(s->sessions, GUINT_TO_POINTER(id));
            virtio_media_session_free(session);
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

        if (virtio_media_iov_read(elem->out_sg, elem->out_num, 0,
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
            status = virtio_media_handle_ioctl(s, session, code, elem, &payload_len);
        }

        virtio_media_write_resp_header(&resp.hdr, status < 0 ? -status : 0);
        virtio_media_iov_write(elem->in_sg, elem->in_num, 0,
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

        if (virtio_media_iov_read(elem->out_sg, elem->out_num, 0,
                                  &mmap_cmd, sizeof(mmap_cmd)) != sizeof(mmap_cmd)) {
            virtqueue_push(vq, elem, 0);
            break;
        }

        id = le32_to_cpu(mmap_cmd.session_id);
        session = g_hash_table_lookup(s->sessions, GUINT_TO_POINTER(id));
        if (!session) {
            status = -EINVAL;
        } else {
            status = virtio_media_find_plane(session, le32_to_cpu(mmap_cmd.offset),
                                             &addr, &len);
        }

        virtio_media_write_resp_header(&resp.hdr, status < 0 ? -status : 0);
        resp.driver_addr = cpu_to_le64(addr);
        resp.len = cpu_to_le64(len);
        virtio_media_iov_write(elem->in_sg, elem->in_num, 0,
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

        virtio_media_write_resp_header(&resp.hdr, 0);
        virtio_media_iov_write(elem->in_sg, elem->in_num, 0,
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

        virtio_media_write_resp_header(&resp, ENOTTY);
        virtio_media_iov_write(elem->in_sg, elem->in_num, 0,
                               &resp, sizeof(resp));
        virtqueue_push(vq, elem, sizeof(resp));
        break;
    }
        }

        virtio_notify(vdev, vq);
        g_free(elem);
    }
}

static void virtio_media_handle_event(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOMedia *s = VIRTIO_MEDIA(vdev);

    virtio_media_flush_events(s);
}

static void virtio_media_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    VirtIOMedia *s = VIRTIO_MEDIA(vdev);

    memcpy(config_data, &s->config, sizeof(s->config));
}

static uint64_t virtio_media_get_features(VirtIODevice *vdev, uint64_t f,
                                          Error **errp)
{
    return f;
}

static int virtio_media_pre_load(void *opaque)
{
    return 0;
}

static int virtio_media_post_load(void *opaque, int version_id)
{
    return 0;
}

static const VMStateDescription vmstate_virtio_media = {
    .name = "virtio-media",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_load = virtio_media_pre_load,
    .post_load = virtio_media_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    }
};

static void virtio_media_realize(DeviceState *dev, Error **errp)
{
    VirtIOMedia *s = VIRTIO_MEDIA(dev);
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    if (s->max_buffers == 0) {
        s->max_buffers = 8;
    }

    s->hostmem_size = pow2ceil((uint64_t)s->max_buffers * VIRTIO_MEDIA_BUFFER_SIZE);
    memory_region_init_ram(&s->hostmem, OBJECT(s), "virtio-media-hostmem",
                           s->hostmem_size, errp);
    if (*errp) {
        return;
    }

    s->use_hostmem = true;
    s->session_next_id = 1;
    s->sessions = g_hash_table_new(g_direct_hash, g_direct_equal);
    QTAILQ_INIT(&s->pending_events);

    s->config.device_caps = cpu_to_le32(V4L2_CAP_VIDEO_CAPTURE_MPLANE |
                                        V4L2_CAP_STREAMING);
    s->config.device_type = cpu_to_le32(0);
    memset(s->config.card, 0, sizeof(s->config.card));
    snprintf((char *)s->config.card, sizeof(s->config.card),
             "%s", VIRTIO_MEDIA_CARD_NAME);

    virtio_init(vdev, VIRTIO_ID_MEDIA, sizeof(s->config));
    s->command_vq = virtio_add_queue(vdev, VIRTIO_MEDIA_VQ_SIZE,
                                     virtio_media_handle_command);
    s->event_vq = virtio_add_queue(vdev, VIRTIO_MEDIA_VQ_SIZE,
                                   virtio_media_handle_event);
}

static void virtio_media_unrealize(DeviceState *dev)
{
    VirtIOMedia *s = VIRTIO_MEDIA(dev);
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    GHashTableIter iter;
    gpointer key;
    gpointer value;
    VirtIOMediaEvent *evt;

    g_hash_table_iter_init(&iter, s->sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        virtio_media_session_free(value);
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
};

static void virtio_media_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_media_properties);
    dc->vmsd = &vmstate_virtio_media;
    vdc->realize = virtio_media_realize;
    vdc->unrealize = virtio_media_unrealize;
    vdc->get_config = virtio_media_get_config;
    vdc->get_features = virtio_media_get_features;
}

static const TypeInfo virtio_media_info = {
    .name = TYPE_VIRTIO_MEDIA,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOMedia),
    .class_init = virtio_media_class_init,
};

static void virtio_media_register_types(void)
{
    type_register_static(&virtio_media_info);
}

type_init(virtio_media_register_types);
