/*
 * Offload for bulk reads out of a transport's remote address space.
 *
 * Most virtio transports put the driver's buffers in ordinary host RAM, so a
 * device model reads them with a plain load and there is nothing to optimise.
 * A transport that reaches its peer across a link is different: the buffers
 * are behind a window, and every byte a device model reads out of one costs
 * link bandwidth *and* a CPU that can do nothing else while it waits.
 *
 * Such a transport may have a DMA engine that can pull a descriptor chain
 * across far faster than the CPU can, into local memory the engine names
 * itself.  This is how it offers that to a device model without either side
 * having to know what the other is: the transport registers against the
 * AddressSpace it publishes, and a device model that is about to read a lot
 * of bytes out of some AddressSpace asks whether that one has an engine.
 *
 * It is strictly an optimisation.  Every caller must work correctly if
 * nothing is registered, or if gather()/scatter() decline -- which they will
 * whenever the buffers are not all in the window, a case that arises in
 * normal operation and is not an error.
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VIRTIO_DMA_OFFLOAD_H
#define QEMU_VIRTIO_DMA_OFFLOAD_H

#include "qemu/iov.h"
#include "qemu/notify.h"
#include "system/memory.h"

typedef enum VirtIODMAFallbackReason {
    VIRTIO_DMA_FALLBACK_BELOW_MIN,
    VIRTIO_DMA_FALLBACK_POOL_FULL,
    VIRTIO_DMA_FALLBACK_POOL_UNAVAILABLE,
    VIRTIO_DMA_FALLBACK_SLOT_TOO_LARGE,
    VIRTIO_DMA_FALLBACK_UNSUPPORTED_BUFFER,
    VIRTIO_DMA_FALLBACK_TOO_MANY_SEGS,
    VIRTIO_DMA_FALLBACK_DMA_BUSY,
    VIRTIO_DMA_FALLBACK_DMA_ERROR,
    VIRTIO_DMA_FALLBACK_SLOT_LIMIT,
    VIRTIO_DMA_FALLBACK__MAX,
} VirtIODMAFallbackReason;

typedef enum VirtIODMAResult {
    VIRTIO_DMA_OK,
    VIRTIO_DMA_FALLBACK,
    VIRTIO_DMA_RETRY,
} VirtIODMAResult;

typedef struct VirtQueueDMA {
    const struct VirtIODMAOffload *offload;
    AddressSpace *as;
    QEMUIOVector iov;
    void **slots;
    size_t *slot_lengths;
    unsigned int nslots;
    bool active;
} VirtQueueDMA;

typedef struct VirtIODMAOffload {
    /*
     * Pull the @num buffers described by @sg, @len bytes in total, into
     * @slot.  Returns false if the transport declined -- because a buffer
     * lies outside its window, because the chain is longer than the engine
     * takes, or because the transfer failed -- and the caller must then read
     * the buffers itself.  On success @slot holds the gathered bytes.
     */
    bool (*gather)(void *opaque, void *slot, const struct iovec *sg,
                   unsigned int num, size_t len,
                   VirtIODMAFallbackReason *reason);

    /*
     * The other direction: push @len bytes from @slot out into the @num
     * buffers described by @sg.  The caller has already placed the bytes in
     * @slot; scatter() only moves them across.  Declines under exactly the
     * same conditions as gather(), and means the same thing -- write the
     * buffers yourself.
     *
     * Note the asymmetry in what a caller must do to use this.  A gather()
     * caller already holds a chain it was going to read; a scatter() caller
     * usually holds bytes somewhere the engine cannot reach (a network
     * backend's buffer, say) and has to stage them into @slot first.  That
     * staging copy is local memory to local memory and costs a fraction of
     * what a write across the window does, but it is not free, and it is why
     * min_len is not the whole of the decision on this side.
     */
    bool (*scatter)(void *opaque, const void *slot, const struct iovec *sg,
                    unsigned int num, size_t len);

    /*
     * Slots come from the transport because the engine can only reach memory
     * it knows the address of, which rules out the heap.  A slot is valid
     * until it is deleted or the transport unregisters, whichever is first.
     */
    void *(*slot_new)(void *opaque, size_t len,
                      VirtIODMAFallbackReason *reason);
    void (*slot_delete)(void *opaque, void *slot, size_t len);

    /* Reserve or release a complete group without partial allocation. */
    VirtIODMAResult (*slots_reserve)(void *opaque, unsigned int nslots,
                                     const size_t *lengths, void **slots,
                                     VirtIODMAFallbackReason *reason);
    void (*slots_release)(void *opaque, unsigned int nslots, void **slots,
                          const size_t *lengths);

    /* Notify device models when a slot release may unblock deferred work. */
    void (*slot_notifier_add)(void *opaque, Notifier *notifier);
    void (*slot_notifier_remove)(void *opaque, Notifier *notifier);

    /* Account bytes that the device model copied after offload declined. */
    void (*record_fallback)(void *opaque, VirtIODMAFallbackReason reason,
                            size_t len);

    /*
     * Below this many bytes an engine's fixed setup cost exceeds what it
     * saves, so a caller should not offer it the work at all.  The transport
     * measures this; callers must not second-guess it.
     */
    size_t min_len;

    /*
     * And above these, gather() declines: @max_len is the largest slot the
     * transport hands out, @max_segs the longest chain its engine takes.
     * A caller with a chain that exceeds either can still use the engine by
     * cutting the chain into pieces that do not -- each piece into its own
     * slot -- which it cannot do without being told where the edges are.
     */
    size_t max_len;
    unsigned int max_segs;

    void *opaque;
} VirtIODMAOffload;

/*
 * Registering does not copy @o, so it must outlive the registration -- in
 * practice it is embedded in the transport's device state.
 */
void virtio_dma_offload_register(AddressSpace *as, const VirtIODMAOffload *o);
void virtio_dma_offload_unregister(AddressSpace *as);

/* NULL when @as has no engine behind it, which is the common case. */
const VirtIODMAOffload *virtio_dma_offload_get(AddressSpace *as);

void virtqueue_dma_init(VirtQueueDMA *dma);
VirtIODMAResult virtqueue_dma_gather(AddressSpace *as,
                                     const QEMUIOVector *source,
                                     unsigned int max_slots,
                                     VirtQueueDMA *dma);
void virtqueue_dma_complete(VirtQueueDMA *dma);
void virtqueue_dma_cancel(VirtQueueDMA *dma);

static inline void
virtio_dma_offload_record_fallback(const VirtIODMAOffload *off,
                                   VirtIODMAFallbackReason reason,
                                   size_t len)
{
    if (off->record_fallback) {
        off->record_fallback(off->opaque, reason, len);
    }
}

#endif /* QEMU_VIRTIO_DMA_OFFLOAD_H */
