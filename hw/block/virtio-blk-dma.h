/*
 * Virtio block DMA offload helpers
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_BLOCK_VIRTIO_BLK_DMA_H
#define HW_BLOCK_VIRTIO_BLK_DMA_H

#include "hw/virtio/virtio-blk.h"

enum {
    VIRTIO_BLK_DMA_PENDING_NONE,
    VIRTIO_BLK_DMA_PENDING_WRITE,
    VIRTIO_BLK_DMA_PENDING_READ,
    VIRTIO_BLK_DMA_PENDING_SCATTER,
    VIRTIO_BLK_DMA_PENDING_FLUSH,
};

typedef struct VirtIOBlockDMAQueue {
    VirtIOBlock *s;
    VirtQueue *vq;
    QEMUBH *retry_bh;
    VirtIODMASlotWaiter waiter;
    VirtQueueDMAState dma;
    QTAILQ_HEAD(, VirtIOBlockReq) pending;
    bool blocked;
    bool retry_running;
    uint64_t wake_seq;
} VirtIOBlockDMAQueue;

VirtIOBlockDMAQueue *virtio_blk_dma_queue(VirtIOBlock *s, VirtQueue *vq);
char *virtio_blk_get_dma_stats(Object *obj, Error **errp);
bool virtio_blk_dma_queue_request(VirtIOBlockReq *req, unsigned int op);
void virtio_blk_dma_release(VirtIOBlockReq *req);
void virtio_blk_dma_drop_chain(VirtIOBlockReq *req);

void virtio_blk_dma_queues_init(VirtIOBlock *s);
void virtio_blk_dma_queues_start(VirtIOBlock *s);
void virtio_blk_dma_queues_stop(VirtIOBlock *s);
void virtio_blk_dma_queues_purge(VirtIOBlock *s);
void virtio_blk_dma_queues_cleanup(VirtIOBlock *s);

/* Block request operations used by the deferred DMA scheduler. */
VirtIODMAResult virtio_blk_start_write(VirtIOBlockReq *req);
VirtIODMAResult virtio_blk_start_read(VirtIOBlockReq *req);
VirtIODMAResult virtio_blk_start_scatter(VirtIOBlockReq *req);
bool virtio_blk_dma_handle_rw_complete(VirtIOBlockReq *req, int *ret);
void virtio_blk_rw_complete(void *opaque, int ret);
void virtio_blk_flush_complete(void *opaque, int ret);

#endif /* HW_BLOCK_VIRTIO_BLK_DMA_H */
