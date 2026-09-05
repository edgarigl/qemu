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

void virtqueue_dma_complete(VirtQueueDMA *dma)
{
    const VirtIODMAOffload *off = dma->offload;
    unsigned int i;

    if (!dma->active) {
        return;
    }

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

VirtIODMAResult virtqueue_dma_gather(AddressSpace *as,
                                     const QEMUIOVector *source,
                                     unsigned int max_slots,
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
    if (source->size < off->min_len) {
        virtio_dma_offload_record_fallback(
            off, VIRTIO_DMA_FALLBACK_BELOW_MIN, source->size);
        return VIRTIO_DMA_FALLBACK;
    }
    if (!off->max_len || !off->max_segs || !max_slots) {
        virtio_dma_offload_record_fallback(
            off, VIRTIO_DMA_FALLBACK_POOL_UNAVAILABLE, source->size);
        return VIRTIO_DMA_FALLBACK;
    }

    lengths = g_new(size_t, max_slots);
    while (i < source->niov) {
        unsigned int nsegs;
        size_t len;

        if (nslots == max_slots) {
            reason = VIRTIO_DMA_FALLBACK_SLOT_LIMIT;
            goto fallback;
        }

        len = virtqueue_dma_next_chunk(off, source, &i, &iov_offset,
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
        VirtIODMAResult result = off->slots_reserve(off->opaque, nslots,
                                                    lengths, slots, &reason);

        if (result != VIRTIO_DMA_OK) {
            g_free(slots);
            g_free(lengths);
            if (result == VIRTIO_DMA_FALLBACK) {
                virtio_dma_offload_record_fallback(off, reason,
                                                   source->size);
            }
            return result;
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
                                                   source->size);
                return VIRTIO_DMA_FALLBACK;
            }
        }
    }

    qemu_iovec_init(&dma->iov, nslots);
    i = 0;
    iov_offset = 0;
    while (i < source->niov) {
        g_autofree struct iovec *sg = g_new(struct iovec, off->max_segs);
        unsigned int nsegs;
        size_t len;

        len = virtqueue_dma_next_chunk(off, source, &i, &iov_offset,
                                       sg, &nsegs);
        assert(dma->nslots < nslots && len == lengths[dma->nslots]);
        if (!off->gather(off->opaque, slots[dma->nslots], sg,
                         nsegs, len, &reason)) {
            unsigned int j;

            if (off->slots_release) {
                off->slots_release(off->opaque, nslots, slots, lengths);
            } else {
                for (j = 0; j < nslots; j++) {
                    off->slot_delete(off->opaque, slots[j], lengths[j]);
                }
            }
            qemu_iovec_destroy(&dma->iov);
            g_free(slots);
            g_free(lengths);
            virtio_dma_offload_record_fallback(off, reason, source->size);
            return VIRTIO_DMA_FALLBACK;
        }

        qemu_iovec_add(&dma->iov, slots[dma->nslots], len);
        dma->nslots++;
    }

    dma->offload = off;
    dma->as = as;
    dma->slots = slots;
    dma->slot_lengths = lengths;
    dma->active = true;
    return VIRTIO_DMA_OK;

fallback:
    g_free(lengths);
    virtio_dma_offload_record_fallback(off, reason, source->size);
    return VIRTIO_DMA_FALLBACK;
}
