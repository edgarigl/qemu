/*
 * Virtio block DMA offload scheduling and teardown
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "qemu/main-loop.h"
#include "qemu/timer.h"
#include "block/block_int.h"
#include "hw/block/virtio-blk-dma.h"
#include "hw/virtio/virtio-access.h"
#include "system/block-ram-registrar.h"

VirtIOBlockDMAQueue *virtio_blk_dma_queue(VirtIOBlock *s, VirtQueue *vq)
{
    unsigned int index = virtio_get_queue_index(vq);

    assert(index < s->conf.num_queues);
    return &s->dma_queues[index];
}

char *virtio_blk_get_dma_stats(Object *obj, Error **errp)
{
    VirtIOBlock *s = VIRTIO_BLK(obj);

    return g_strdup_printf(
        "merged_submissions=%" PRIu64 " merged_requests=%" PRIu64
        " merged_bytes=%" PRIu64 " deferred_submissions=%" PRIu64
        " retry_attempts=%" PRIu64 " retry_wakeups=%" PRIu64
        " wait_ns=%" PRIu64 " max_wait_ns=%" PRIu64
        " async_submissions=%" PRIu64 " async_completions=%" PRIu64
        " async_errors=%" PRIu64,
        qatomic_read(&s->dma_stats.merged_submissions),
        qatomic_read(&s->dma_stats.merged_requests),
        qatomic_read(&s->dma_stats.merged_bytes),
        qatomic_read(&s->dma_stats.deferred_submissions),
        qatomic_read(&s->dma_stats.retry_attempts),
        qatomic_read(&s->dma_stats.retry_wakeups),
        qatomic_read(&s->dma_stats.wait_ns),
        qatomic_read(&s->dma_stats.max_wait_ns),
        qatomic_read(&s->dma_stats.async_submissions),
        qatomic_read(&s->dma_stats.async_completions),
        qatomic_read(&s->dma_stats.async_errors));
}

void virtio_blk_dma_release(VirtIOBlockReq *req)
{
    virtqueue_dma_complete(&req->dma);
}

static void virtio_blk_submit_rw(VirtIOBlockReq *req, bool is_write)
{
    VirtIOBlock *s = req->dev;
    QEMUIOVector *qiov = req->dma.active ? &req->dma.iov : &req->qiov;
    BdrvRequestFlags flags = 0;

    if (!req->dma.active && blk_ram_registrar_ok(&s->blk_ram_registrar)) {
        flags |= BDRV_REQ_REGISTERED_BUF;
    }

    if (is_write) {
        blk_aio_pwritev(s->blk,
                        req->sector_num << BDRV_SECTOR_BITS, qiov,
                        flags, virtio_blk_rw_complete, req);
    } else {
        blk_aio_preadv(s->blk,
                       req->sector_num << BDRV_SECTOR_BITS, qiov,
                       flags, virtio_blk_rw_complete, req);
    }
}

static VirtIODMAResult virtio_blk_prepare_write(VirtIOBlockReq *req)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(req->dev);
    VirtIOBlockDMAQueue *q = virtio_blk_dma_queue(req->dev, req->vq);
    const VirtIODMAOffload *off = virtio_dma_offload_get(vdev->dma_as);
    unsigned int max_slots = VIRTIO_BLK_MAX_DMA_SLOTS;

    if (off && off->max_slots) {
        max_slots = MIN(max_slots, off->max_slots);
    }

    return virtqueue_dma_gather(vdev->dma_as, &req->qiov,
                                max_slots, &q->waiter, &req->dma);
}

static void virtio_blk_dma_gather_complete(void *opaque, int status)
{
    VirtIOBlockReq *req = opaque;
    VirtIOBlock *s = req->dev;
    VirtIOBlockDMAQueue *q = virtio_blk_dma_queue(s, req->vq);

    qatomic_inc(&q->wake_seq);
    qatomic_inc(&s->dma_stats.async_completions);

    if (virtqueue_dma_queue_stopping(&q->dma)) {
        virtio_blk_dma_drop_chain(req);
    } else {
        if (status) {
            qatomic_inc(&s->dma_stats.async_errors);
            virtio_blk_dma_release(req);
        }
        virtio_blk_submit_rw(req, true);
    }

    if (qatomic_read(&q->blocked) &&
        !virtqueue_dma_queue_stopping(&q->dma)) {
        qemu_bh_schedule(q->retry_bh);
    }
    blk_dec_in_flight(s->conf.conf.blk);
}

static void virtio_blk_track_async(VirtIOBlockReq *req)
{
    blk_inc_in_flight(req->dev->conf.conf.blk);
}

static void virtio_blk_untrack_async(VirtIOBlockReq *req)
{
    VirtIOBlockDMAQueue *q = virtio_blk_dma_queue(req->dev, req->vq);

    qatomic_inc(&q->wake_seq);
    blk_dec_in_flight(req->dev->conf.conf.blk);
}

VirtIODMAResult virtio_blk_start_write(VirtIOBlockReq *req)
{
    VirtIOBlock *s = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);
    VirtIOBlockDMAQueue *q = virtio_blk_dma_queue(s, req->vq);
    const VirtIODMAOffload *off = virtio_dma_offload_get(vdev->dma_as);
    VirtIODMAResult result;

    if (!off || !off->submit_async) {
        result = virtio_blk_prepare_write(req);
        if (result != VIRTIO_DMA_RETRY) {
            virtio_blk_submit_rw(req, true);
        }
        return result;
    }
    if (virtqueue_dma_queue_inflight(&q->dma) >=
        off->max_async_requests) {
        return VIRTIO_DMA_RETRY;
    }

    result = virtqueue_dma_prepare(vdev->dma_as, &req->qiov,
                                   MIN(VIRTIO_BLK_MAX_DMA_SLOTS,
                                       off->max_slots),
                                   &q->waiter, &req->dma);
    if (result != VIRTIO_DMA_OK) {
        if (result != VIRTIO_DMA_RETRY) {
            virtio_blk_submit_rw(req, true);
        }
        return result;
    }

    virtio_blk_track_async(req);
    result = virtqueue_dma_submit_async(
        &q->dma, &req->dma, &req->qiov, VIRTIO_DMA_FROM_REMOTE,
        qemu_get_current_aio_context(), virtio_blk_dma_gather_complete, req);
    if (result != VIRTIO_DMA_OK) {
        virtio_blk_untrack_async(req);
        virtio_blk_dma_release(req);
        if (result != VIRTIO_DMA_RETRY) {
            virtio_blk_submit_rw(req, true);
        }
        return result;
    }

    qatomic_inc(&s->dma_stats.async_submissions);
    return VIRTIO_DMA_OK;
}

VirtIODMAResult virtio_blk_start_read(VirtIOBlockReq *req)
{
    VirtIOBlock *s = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);
    VirtIOBlockDMAQueue *q = virtio_blk_dma_queue(s, req->vq);
    const VirtIODMAOffload *off = virtio_dma_offload_get(vdev->dma_as);
    VirtIODMAResult result;

    if (!off || !off->submit_async || !off->async_scatter) {
        virtio_blk_submit_rw(req, false);
        return VIRTIO_DMA_FALLBACK;
    }
    if (virtqueue_dma_queue_inflight(&q->dma) >=
        off->max_async_requests) {
        return VIRTIO_DMA_RETRY;
    }

    result = virtqueue_dma_prepare(vdev->dma_as, &req->qiov,
                                   MIN(VIRTIO_BLK_MAX_DMA_SLOTS,
                                       off->max_slots),
                                   &q->waiter, &req->dma);
    if (result != VIRTIO_DMA_OK) {
        if (result != VIRTIO_DMA_RETRY) {
            virtio_blk_submit_rw(req, false);
        }
        return result;
    }

    virtio_blk_submit_rw(req, false);
    return VIRTIO_DMA_OK;
}

static void virtio_blk_dma_scatter_complete(void *opaque, int status)
{
    VirtIOBlockReq *req = opaque;
    VirtIOBlock *s = req->dev;
    VirtIOBlockDMAQueue *q = virtio_blk_dma_queue(s, req->vq);

    qatomic_inc(&s->dma_stats.async_completions);

    if (virtqueue_dma_queue_stopping(&q->dma)) {
        virtio_blk_dma_drop_chain(req);
    } else {
        if (status) {
            qatomic_inc(&s->dma_stats.async_errors);
        }
        virtio_blk_dma_release(req);
        virtio_blk_rw_complete(req, status ? -EIO : 0);
    }

    if (qatomic_read(&q->blocked) &&
        !virtqueue_dma_queue_stopping(&q->dma)) {
        qemu_bh_schedule(q->retry_bh);
    }
    blk_dec_in_flight(s->conf.conf.blk);
}

VirtIODMAResult virtio_blk_start_scatter(VirtIOBlockReq *req)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(req->dev);
    VirtIOBlockDMAQueue *q = virtio_blk_dma_queue(req->dev, req->vq);
    const VirtIODMAOffload *off = virtio_dma_offload_get(vdev->dma_as);
    VirtIODMAResult result;

    if (!off || !off->submit_async || !off->async_scatter) {
        return VIRTIO_DMA_FALLBACK;
    }
    if (virtqueue_dma_queue_inflight(&q->dma) >=
        off->max_async_requests) {
        return VIRTIO_DMA_RETRY;
    }
    virtio_blk_track_async(req);
    result = virtqueue_dma_submit_async(
        &q->dma, &req->dma, &req->qiov, VIRTIO_DMA_TO_REMOTE,
        qemu_get_current_aio_context(), virtio_blk_dma_scatter_complete,
        req);
    if (result != VIRTIO_DMA_OK) {
        virtio_blk_untrack_async(req);
        return result;
    }
    qatomic_inc(&req->dev->dma_stats.async_submissions);
    return VIRTIO_DMA_OK;
}

bool virtio_blk_dma_handle_rw_complete(VirtIOBlockReq *req, int *ret)
{
    VirtIOBlockDMAQueue *q = virtio_blk_dma_queue(req->dev, req->vq);
    int type = virtio_ldl_p(VIRTIO_DEVICE(req->dev), &req->out.type);
    VirtIODMAResult result;

    if (*ret || !req->dma.active || (type & VIRTIO_BLK_T_OUT)) {
        return false;
    }
    if (virtqueue_dma_queue_stopping(&q->dma)) {
        *ret = -EIO;
        return false;
    }

    result = virtio_blk_start_scatter(req);
    if (result == VIRTIO_DMA_OK) {
        return true;
    }
    if (result == VIRTIO_DMA_RETRY &&
        virtio_blk_dma_queue_request(req,
                                     VIRTIO_BLK_DMA_PENDING_SCATTER)) {
        return true;
    }
    *ret = -EIO;
    return false;
}

bool virtio_blk_dma_queue_request(VirtIOBlockReq *req, unsigned int op)
{
    VirtIOBlockDMAQueue *q = virtio_blk_dma_queue(req->dev, req->vq);

    req->dma_pending_op = op;
    req->dma_wait_start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    QTAILQ_INSERT_TAIL(&q->pending, req, dma_next);
    qatomic_set(&q->blocked, true);
    qatomic_inc(&req->dev->dma_stats.deferred_submissions);

    /* Close the failed-reservation/notifier race with one immediate retry. */
    if (!virtqueue_dma_queue_stopping(&q->dma)) {
        qemu_bh_schedule(q->retry_bh);
    }
    return true;
}

static void virtio_blk_dma_update_max_wait(VirtIOBlock *s, uint64_t wait_ns)
{
    uint64_t old = qatomic_read(&s->dma_stats.max_wait_ns);

    while (wait_ns > old) {
        uint64_t seen = qatomic_cmpxchg(&s->dma_stats.max_wait_ns,
                                       old, wait_ns);

        if (seen == old) {
            break;
        }
        old = seen;
    }
}

static void virtio_blk_dma_account_wait(VirtIOBlockReq *req)
{
    uint64_t wait_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) -
                       req->dma_wait_start_ns;

    qatomic_add(&req->dev->dma_stats.wait_ns, wait_ns);
    virtio_blk_dma_update_max_wait(req->dev, wait_ns);
    req->dma_wait_start_ns = 0;
}

static void virtio_blk_dma_retry_bh(void *opaque)
{
    VirtIOBlockDMAQueue *q = opaque;
    VirtIOBlockReq *req;
    bool resume = false;

    if (virtqueue_dma_queue_stopping(&q->dma)) {
        return;
    }

    qatomic_set(&q->retry_running, true);
    while ((req = QTAILQ_FIRST(&q->pending))) {
        unsigned int op = req->dma_pending_op;
        VirtIODMAResult result = VIRTIO_DMA_OK;

        if (op == VIRTIO_BLK_DMA_PENDING_WRITE ||
            op == VIRTIO_BLK_DMA_PENDING_READ ||
            op == VIRTIO_BLK_DMA_PENDING_SCATTER) {
            uint64_t wake_seq = qatomic_read(&q->wake_seq);

            qatomic_inc(&q->s->dma_stats.retry_attempts);
            if (op == VIRTIO_BLK_DMA_PENDING_WRITE) {
                result = virtio_blk_start_write(req);
            } else if (op == VIRTIO_BLK_DMA_PENDING_READ) {
                result = virtio_blk_start_read(req);
            } else {
                result = virtio_blk_start_scatter(req);
            }
            if (result == VIRTIO_DMA_RETRY) {
                qatomic_set(&q->retry_running, false);
                /* A release raced this attempt while callbacks were muted. */
                if (qatomic_read(&q->wake_seq) != wake_seq &&
                    !virtqueue_dma_queue_stopping(&q->dma)) {
                    qemu_bh_schedule(q->retry_bh);
                }
                return;
            }
        } else {
            assert(req->dma_pending_op == VIRTIO_BLK_DMA_PENDING_FLUSH);
            if (virtqueue_dma_queue_inflight(&q->dma)) {
                qatomic_set(&q->retry_running, false);
                return;
            }
        }

        QTAILQ_REMOVE(&q->pending, req, dma_next);
        req->dma_pending_op = VIRTIO_BLK_DMA_PENDING_NONE;
        virtio_blk_dma_account_wait(req);
        if (op == VIRTIO_BLK_DMA_PENDING_FLUSH) {
            blk_aio_flush(q->s->blk, virtio_blk_flush_complete, req);
        } else if (op == VIRTIO_BLK_DMA_PENDING_SCATTER &&
                   result != VIRTIO_DMA_OK) {
            virtio_blk_dma_release(req);
            virtio_blk_rw_complete(req, -EIO);
        }
    }
    qatomic_set(&q->blocked, false);
    qatomic_set(&q->retry_running, false);
    if (!virtqueue_dma_queue_stopping(&q->dma)) {
        resume = true;
    }

    if (resume) {
        virtio_blk_handle_vq(q->s, q->vq);
    }
}

static void virtio_blk_dma_slot_available(Notifier *notifier, void *data)
{
    VirtIODMASlotWaiter *waiter =
        container_of(notifier, VirtIODMASlotWaiter, notifier);
    VirtIOBlockDMAQueue *q = container_of(waiter, VirtIOBlockDMAQueue,
                                          waiter);

    qatomic_inc(&q->wake_seq);
    if (qatomic_read(&q->blocked) &&
        !virtqueue_dma_queue_stopping(&q->dma) &&
        !qatomic_read(&q->retry_running)) {
        qatomic_inc(&q->s->dma_stats.retry_wakeups);
        qemu_bh_schedule(q->retry_bh);
    }
}

void virtio_blk_dma_drop_chain(VirtIOBlockReq *req)
{
    VirtIOBlockReq *next;

    virtio_blk_dma_release(req);
    if (req->qiov.nalloc != -1) {
        qemu_iovec_destroy(&req->qiov);
    }

    while (req) {
        next = req->mr_next;
        virtqueue_detach_element(req->vq, &req->elem, 0);
        g_free(req);
        req = next;
    }
}

static void virtio_blk_dma_purge_queue_bh(void *opaque)
{
    VirtIOBlockDMAQueue *q = opaque;
    VirtIOBlockReq *req;

    qemu_bh_cancel(q->retry_bh);
    while ((req = QTAILQ_FIRST(&q->pending))) {
        QTAILQ_REMOVE(&q->pending, req, dma_next);
        virtio_blk_dma_drop_chain(req);
    }
    assert(!virtqueue_dma_queue_inflight(&q->dma));
    qatomic_set(&q->blocked, false);
    qatomic_set(&q->retry_running, false);
}

void virtio_blk_dma_queues_stop(VirtIOBlock *s)
{
    unsigned int i;

    for (i = 0; i < s->conf.num_queues; i++) {
        virtqueue_dma_queue_stop(&s->dma_queues[i].dma);
        virtqueue_dma_waiter_cancel(&s->dma_queues[i].waiter);
    }
}

void virtio_blk_dma_queues_purge(VirtIOBlock *s)
{
    unsigned int i;

    for (i = 0; i < s->conf.num_queues; i++) {
        aio_wait_bh_oneshot(s->vq_aio_context[i],
                            virtio_blk_dma_purge_queue_bh,
                            &s->dma_queues[i]);
    }
}

void virtio_blk_dma_queues_start(VirtIOBlock *s)
{
    unsigned int i;

    for (i = 0; i < s->conf.num_queues; i++) {
        virtqueue_dma_queue_start(&s->dma_queues[i].dma);
    }
}

void virtio_blk_dma_queues_init(VirtIOBlock *s)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(s);
    unsigned int i;

    s->dma_queues = g_new0(VirtIOBlockDMAQueue, s->conf.num_queues);
    for (i = 0; i < s->conf.num_queues; i++) {
        VirtIOBlockDMAQueue *q = &s->dma_queues[i];

        q->s = s;
        q->vq = virtio_get_queue(vdev, i);
        virtqueue_dma_queue_init(&q->dma);
        QTAILQ_INIT(&q->pending);
        q->retry_bh = aio_bh_new(s->vq_aio_context[i],
                                 virtio_blk_dma_retry_bh, q);
        virtqueue_dma_waiter_init(&q->waiter,
                                  virtio_blk_dma_slot_available);
    }
}

void virtio_blk_dma_queues_cleanup(VirtIOBlock *s)
{
    unsigned int i;

    for (i = 0; i < s->conf.num_queues; i++) {
        VirtIOBlockDMAQueue *q = &s->dma_queues[i];

        virtqueue_dma_waiter_cancel(&q->waiter);
    }

    virtio_blk_dma_queues_purge(s);
    for (i = 0; i < s->conf.num_queues; i++) {
        qemu_bh_delete(s->dma_queues[i].retry_bh);
    }
    g_free(s->dma_queues);
    s->dma_queues = NULL;
}
