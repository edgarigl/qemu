/*
 * Offload for bulk reads out of a transport's remote address space.
 *
 * See include/hw/virtio/virtio-dma-offload.h for what this is for.  All that
 * lives here is the registry, which is a hash table keyed by AddressSpace
 * rather than a field on one because AddressSpace is core memory-API state
 * and this is a property of the transport that happens to own it.
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "hw/virtio/virtio-dma-offload.h"

/*
 * Not locked, and the reason is narrower than it first looks.  Lookup is *not*
 * confined to the BQL -- virtio-blk calls it per request from its iothread, so
 * several threads read this table concurrently.  Concurrent readers are fine;
 * a reader running while the table is mutated would not be, because an insert
 * may rehash.
 *
 * The invariant is therefore that mutation happens only while no dataplane can
 * be looking.  That holds today because the sole registrant is a transport
 * which registers at its own realize -- before any device on it exists -- and
 * unregisters at unrealize.  The assertions below check the part that is cheap
 * to check, and would catch a future registrant mutating from an iothread.  A
 * transport that could come or go while devices are running needs this table
 * made RCU, not merely BQL-locked.
 */
static GHashTable *virtio_dma_offloads;

void virtio_dma_offload_register(AddressSpace *as, const VirtIODMAOffload *o)
{
    assert(bql_locked());

    if (!virtio_dma_offloads) {
        virtio_dma_offloads = g_hash_table_new(NULL, NULL);
    }

    g_hash_table_insert(virtio_dma_offloads, as, (gpointer)o);
}

void virtio_dma_offload_unregister(AddressSpace *as)
{
    assert(bql_locked());

    if (virtio_dma_offloads) {
        g_hash_table_remove(virtio_dma_offloads, as);
    }
}

const VirtIODMAOffload *virtio_dma_offload_get(AddressSpace *as)
{
    if (!virtio_dma_offloads || !as) {
        return NULL;
    }

    return g_hash_table_lookup(virtio_dma_offloads, as);
}

void virtqueue_dma_init(VirtQueueDMA *dma)
{
    memset(dma, 0, sizeof(*dma));
}

void virtqueue_dma_queue_init(VirtQueueDMAState *queue)
{
    memset(queue, 0, sizeof(*queue));
}

void virtqueue_dma_queue_start(VirtQueueDMAState *queue)
{
    assert(!qatomic_read(&queue->inflight));
    qatomic_set(&queue->stopping, false);
}

void virtqueue_dma_queue_stop(VirtQueueDMAState *queue)
{
    qatomic_set(&queue->stopping, true);
}

bool virtqueue_dma_queue_stopping(const VirtQueueDMAState *queue)
{
    return qatomic_read(&queue->stopping);
}

unsigned int virtqueue_dma_queue_inflight(const VirtQueueDMAState *queue)
{
    return qatomic_read(&queue->inflight);
}

void virtqueue_dma_complete(VirtQueueDMA *dma)
{
    const VirtIODMAOffload *off = dma->offload;
    unsigned int i;

    if (!dma->active) {
        return;
    }
    assert(!dma->async_inflight);

    if (virtio_dma_offload_get(dma->as) == off) {
        if (off->slots_release) {
            off->slots_release(off->opaque, dma->nslots, dma->slots,
                               dma->slot_lengths);
        } else {
            for (i = 0; i < dma->nslots; i++) {
                off->slot_delete(off->opaque, dma->slots[i],
                                 dma->slot_lengths[i]);
            }
        }
    }

    qemu_iovec_destroy(&dma->iov);
    g_free(dma->slot_lengths);
    g_free(dma->slots);
    virtqueue_dma_init(dma);
}

void virtqueue_dma_cancel(VirtQueueDMA *dma)
{
    virtqueue_dma_complete(dma);
}

void virtqueue_dma_waiter_init(VirtIODMASlotWaiter *waiter,
                               void (*notify)(Notifier *, void *))
{
    memset(waiter, 0, sizeof(*waiter));
    waiter->notifier.notify = notify;
}

void virtqueue_dma_waiter_cancel(VirtIODMASlotWaiter *waiter)
{
    const VirtIODMAOffload *off = waiter->offload;

    if (off && virtio_dma_offload_get(waiter->as) == off &&
        off->slot_wait_cancel) {
        off->slot_wait_cancel(off->opaque, waiter);
    }
    waiter->offload = NULL;
    waiter->as = NULL;
    waiter->queued = false;
    waiter->granted = false;
}

void virtio_dma_offload_drain(AddressSpace *as)
{
    const VirtIODMAOffload *off = virtio_dma_offload_get(as);

    if (off && off->drain_async) {
        off->drain_async(off->opaque);
    }
}

static size_t virtqueue_dma_next_chunk(const VirtIODMAOffload *off,
                                       const QEMUIOVector *source,
                                       unsigned int *iov_index,
                                       size_t *iov_offset,
                                       struct iovec *sg,
                                       unsigned int *nsegs)
{
    unsigned int i = *iov_index;
    size_t offset = *iov_offset;
    size_t len = 0;
    unsigned int n = 0;

    while (i < source->niov && n < off->max_segs && len < off->max_len) {
        size_t available;
        size_t take;

        if (offset == source->iov[i].iov_len) {
            i++;
            offset = 0;
            continue;
        }

        available = source->iov[i].iov_len - offset;
        take = MIN(available, off->max_len - len);
        if (sg) {
            sg[n].iov_base = (uint8_t *)source->iov[i].iov_base + offset;
            sg[n].iov_len = take;
        }
        n++;
        len += take;
        offset += take;
    }

    while (i < source->niov && offset == source->iov[i].iov_len) {
        i++;
        offset = 0;
    }

    *iov_index = i;
    *iov_offset = offset;
    *nsegs = n;
    return len;
}

VirtIODMAResult virtqueue_dma_prepare(AddressSpace *as,
                                      const QEMUIOVector *remote,
                                      unsigned int max_slots,
                                      VirtIODMASlotWaiter *waiter,
                                      VirtQueueDMA *dma)
{
    VirtIODMAFallbackReason reason = VIRTIO_DMA_FALLBACK_BELOW_MIN;
    const VirtIODMAOffload *off = virtio_dma_offload_get(as);
    unsigned int i = 0, nslots = 0;
    size_t iov_offset = 0;
    size_t *lengths;
    void **slots;

    assert(!dma->active);
    if (!off) {
        return VIRTIO_DMA_FALLBACK;
    }
    if (remote->size < off->min_len) {
        virtio_dma_offload_record_fallback(
            off, VIRTIO_DMA_FALLBACK_BELOW_MIN, remote->size);
        return VIRTIO_DMA_FALLBACK;
    }
    if (!off->max_len || !off->max_segs || !max_slots) {
        virtio_dma_offload_record_fallback(
            off, VIRTIO_DMA_FALLBACK_POOL_UNAVAILABLE, remote->size);
        return VIRTIO_DMA_FALLBACK;
    }

    lengths = g_new(size_t, max_slots);
    while (i < remote->niov) {
        unsigned int nsegs;
        size_t len;

        if (nslots == max_slots) {
            reason = VIRTIO_DMA_FALLBACK_SLOT_LIMIT;
            goto fallback;
        }

        len = virtqueue_dma_next_chunk(off, remote, &i, &iov_offset,
                                       NULL, &nsegs);
        if (!nsegs) {
            reason = VIRTIO_DMA_FALLBACK_SLOT_TOO_LARGE;
            goto fallback;
        }
        if (len < off->min_len) {
            reason = VIRTIO_DMA_FALLBACK_BELOW_MIN;
            goto fallback;
        }

        lengths[nslots++] = len;
    }

    slots = g_new(void *, nslots);
    if (off->slots_reserve) {
        if (waiter) {
            waiter->offload = off;
            waiter->as = as;
        }
        VirtIODMAResult result = off->slots_reserve(off->opaque, nslots,
                                                    lengths, slots, waiter,
                                                    &reason);

        if (result != VIRTIO_DMA_OK) {
            g_free(slots);
            g_free(lengths);
            if (result == VIRTIO_DMA_FALLBACK) {
                virtio_dma_offload_record_fallback(off, reason,
                                                   remote->size);
                if (waiter) {
                    waiter->offload = NULL;
                    waiter->as = NULL;
                }
            }
            return result;
        }
        if (waiter) {
            waiter->offload = NULL;
            waiter->as = NULL;
        }
    } else {
        for (i = 0; i < nslots; i++) {
            slots[i] = off->slot_new(off->opaque, lengths[i], &reason);
            if (!slots[i]) {
                while (i) {
                    i--;
                    off->slot_delete(off->opaque, slots[i], lengths[i]);
                }
                g_free(slots);
                g_free(lengths);
                if (reason == VIRTIO_DMA_FALLBACK_POOL_FULL) {
                    return VIRTIO_DMA_RETRY;
                }
                virtio_dma_offload_record_fallback(off, reason,
                                                   remote->size);
                return VIRTIO_DMA_FALLBACK;
            }
        }
    }

    qemu_iovec_init(&dma->iov, nslots);
    for (i = 0; i < nslots; i++) {
        qemu_iovec_add(&dma->iov, slots[i], lengths[i]);
    }
    dma->offload = off;
    dma->as = as;
    dma->slots = slots;
    dma->slot_lengths = lengths;
    dma->nslots = nslots;
    dma->active = true;
    return VIRTIO_DMA_OK;

fallback:
    g_free(lengths);
    virtio_dma_offload_record_fallback(off, reason, remote->size);
    return VIRTIO_DMA_FALLBACK;
}

VirtIODMAResult virtqueue_dma_gather(AddressSpace *as,
                                     const QEMUIOVector *source,
                                     unsigned int max_slots,
                                     VirtIODMASlotWaiter *waiter,
                                     VirtQueueDMA *dma)
{
    VirtIODMAFallbackReason reason = VIRTIO_DMA_FALLBACK_DMA_ERROR;
    const VirtIODMAOffload *off;
    VirtIODMAResult result;
    unsigned int i = 0, slot = 0;
    size_t iov_offset = 0;

    result = virtqueue_dma_prepare(as, source, max_slots, waiter, dma);
    if (result != VIRTIO_DMA_OK) {
        return result;
    }
    off = dma->offload;

    while (i < source->niov) {
        g_autofree struct iovec *sg = g_new(struct iovec, off->max_segs);
        unsigned int nsegs;
        size_t len;

        len = virtqueue_dma_next_chunk(off, source, &i, &iov_offset,
                                       sg, &nsegs);
        assert(slot < dma->nslots && len == dma->slot_lengths[slot]);
        if (!off->gather(off->opaque, dma->slots[slot], sg,
                         nsegs, len, &reason)) {
            virtqueue_dma_complete(dma);
            virtio_dma_offload_record_fallback(off, reason, source->size);
            return VIRTIO_DMA_FALLBACK;
        }
        slot++;
    }

    return VIRTIO_DMA_OK;
}

static void virtqueue_dma_async_done(void *opaque, int status)
{
    VirtQueueDMA *dma = opaque;
    VirtQueueDMAState *queue = dma->async_queue;
    VirtIODMAAsyncCallback *cb = dma->async_cb;
    void *cb_opaque = dma->async_opaque;

    dma->async_inflight = false;
    dma->async_queue = NULL;
    qatomic_dec(&queue->inflight);
    cb(cb_opaque, status);
}

VirtIODMAResult virtqueue_dma_submit_async(
    VirtQueueDMAState *queue, VirtQueueDMA *dma,
    const QEMUIOVector *remote,
    VirtIODMADirection direction, AioContext *ctx,
    VirtIODMAAsyncCallback *cb, void *cb_opaque)
{
    const VirtIODMAOffload *off = dma->offload;
    g_autofree VirtIODMASegment *segments = NULL;
    VirtIODMAFallbackReason reason = VIRTIO_DMA_FALLBACK_DMA_ERROR;
    VirtIODMAResult result;
    unsigned int i = 0, slot = 0, nsegs = 0;
    size_t iov_offset = 0, slot_offset = 0;

    if (!dma->active || !dma->offload->submit_async) {
        return VIRTIO_DMA_FALLBACK;
    }
    if (virtqueue_dma_queue_stopping(queue) ||
        virtqueue_dma_queue_inflight(queue) >= off->max_async_requests) {
        return VIRTIO_DMA_RETRY;
    }

    segments = g_new(VirtIODMASegment, remote->niov + dma->nslots);
    while (i < remote->niov) {
        size_t remote_left;
        size_t local_left;
        size_t len;

        while (i < remote->niov &&
               iov_offset == remote->iov[i].iov_len) {
            i++;
            iov_offset = 0;
        }
        if (i == remote->niov) {
            break;
        }
        assert(slot < dma->nslots);

        remote_left = remote->iov[i].iov_len - iov_offset;
        local_left = dma->slot_lengths[slot] - slot_offset;
        len = MIN(remote_left, local_left);
        segments[nsegs].remote =
            (uint8_t *)remote->iov[i].iov_base + iov_offset;
        segments[nsegs].local = (uint8_t *)dma->slots[slot] + slot_offset;
        segments[nsegs].len = len;
        nsegs++;
        iov_offset += len;
        slot_offset += len;

        if (slot_offset == dma->slot_lengths[slot]) {
            slot++;
            slot_offset = 0;
        }
    }
    assert(slot == dma->nslots && slot_offset == 0);
    if (!off->max_async_segs || nsegs > off->max_async_segs) {
        virtio_dma_offload_record_fallback(
            off, VIRTIO_DMA_FALLBACK_TOO_MANY_SEGS, remote->size);
        return VIRTIO_DMA_FALLBACK;
    }

    dma->async_cb = cb;
    dma->async_opaque = cb_opaque;
    dma->async_queue = queue;
    dma->async_inflight = true;
    qatomic_inc(&queue->inflight);

    result = off->submit_async(off->opaque, segments, nsegs, direction,
                               ctx, virtqueue_dma_async_done, dma, &reason);
    if (result != VIRTIO_DMA_OK) {
        qatomic_dec(&queue->inflight);
        dma->async_inflight = false;
        dma->async_queue = NULL;
    }
    return result;
}

VirtIODMAResult virtqueue_dma_prepare_submit_async(
    VirtQueueDMAState *queue, AddressSpace *as, VirtQueueDMA *dma,
    const QEMUIOVector *remote, unsigned int max_slots,
    VirtIODMASlotWaiter *waiter, VirtIODMADirection direction,
    AioContext *ctx, VirtIODMAAsyncCallback *cb, void *cb_opaque)
{
    const VirtIODMAOffload *off = virtio_dma_offload_get(as);
    VirtIODMAResult result;

    if (!off || !off->submit_async) {
        return VIRTIO_DMA_FALLBACK;
    }
    if (virtqueue_dma_queue_stopping(queue) ||
        virtqueue_dma_queue_inflight(queue) >= off->max_async_requests) {
        return VIRTIO_DMA_RETRY;
    }

    result = virtqueue_dma_prepare(as, remote, max_slots, waiter, dma);
    if (result != VIRTIO_DMA_OK) {
        return result;
    }

    result = virtqueue_dma_submit_async(queue, dma, remote, direction, ctx,
                                        cb, cb_opaque);
    if (result != VIRTIO_DMA_OK) {
        virtqueue_dma_complete(dma);
    }
    return result;
}
