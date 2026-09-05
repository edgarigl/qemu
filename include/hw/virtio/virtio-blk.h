/*
 * Virtio Block Device
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_VIRTIO_BLK_H
#define QEMU_VIRTIO_BLK_H

#include "standard-headers/linux/virtio_blk.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-dma-offload.h"
#include "hw/block/block.h"
#include "system/iothread.h"
#include "system/block-backend.h"
#include "system/block-ram-registrar.h"
#include "qom/object.h"
#include "qapi/qapi-types-virtio.h"

#define TYPE_VIRTIO_BLK "virtio-blk-device"
OBJECT_DECLARE_TYPE(VirtIOBlock, VirtIOBlkClass, VIRTIO_BLK)

/* This is the last element of the write scatter-gather list */
struct virtio_blk_inhdr
{
    unsigned char status;
};

#define VIRTIO_BLK_AUTO_NUM_QUEUES UINT16_MAX

struct VirtIOBlkConf
{
    BlockConf conf;
    IOThread *iothread;
    IOThreadVirtQueueMappingList *iothread_vq_mapping_list;
    char *serial;
    uint32_t request_merging;
    uint16_t num_queues;
    uint16_t queue_size;
    bool seg_max_adjust;
    bool report_discard_granularity;
    uint32_t max_discard_sectors;
    uint32_t max_write_zeroes_sectors;
    bool x_enable_wce_if_config_wce;
};

struct VirtIOBlockReq;
struct VirtIOBlockDMAQueue;
struct VirtIOBlock {
    VirtIODevice parent_obj;
    BlockBackend *blk;
    QemuMutex rq_lock;
    struct VirtIOBlockReq *rq; /* protected by rq_lock */
    VirtIOBlkConf conf;
    unsigned short sector_mask;
    bool original_wce;
    VMChangeStateEntry *change;
    bool ioeventfd_disabled;
    bool ioeventfd_started;
    bool ioeventfd_starting;
    bool ioeventfd_stopping;

    /*
     * The AioContext for each virtqueue. The BlockDriverState will use the
     * first element as its AioContext.
     */
    AioContext **vq_aio_context;

    uint64_t host_features;
    size_t config_size;
    BlockRAMRegistrar blk_ram_registrar;
    struct VirtIOBlockDMAQueue *dma_queues;

    struct {
        uint64_t merged_submissions;
        uint64_t merged_requests;
        uint64_t merged_bytes;
        uint64_t deferred_submissions;
        uint64_t retry_attempts;
        uint64_t retry_wakeups;
        uint64_t wait_ns;
        uint64_t max_wait_ns;
        uint64_t async_submissions;
        uint64_t async_completions;
        uint64_t async_errors;
    } dma_stats;
};

/*
 * How many DMA-offload slots one write may hold.  Eight times the transport's
 * slot size is the largest chain the engine gathers in one go; past that the
 * tail of the chain is written straight from the driver's buffers, which is
 * what would have happened to all of it anyway.
 */
#define VIRTIO_BLK_MAX_DMA_SLOTS 8

typedef struct VirtIOBlockReq {
    VirtQueueElement elem;
    int64_t sector_num;
    VirtIOBlock *dev;
    VirtQueue *vq;
    IOVDiscardUndo inhdr_undo;
    IOVDiscardUndo outhdr_undo;
    struct virtio_blk_inhdr *in;
    struct virtio_blk_outhdr out;
    QEMUIOVector qiov;
    /*
     * Where a DMA offload gathered this write, when the transport offers one.
     * @dma.iov describes the slots and replaces @qiov for the duration of the
     * block request, so both have to live until it completes; the slots go
     * back to the transport there too.  Only the head request of a merge
     * carries these -- it is the one the completion callback is given.
     */
    VirtQueueDMA dma;
    QTAILQ_ENTRY(VirtIOBlockReq) dma_next;
    unsigned int dma_pending_op;
    int64_t dma_wait_start_ns;
    size_t in_len;
    struct VirtIOBlockReq *next;
    struct VirtIOBlockReq *mr_next;
    BlockAcctCookie acct;
} VirtIOBlockReq;

#define VIRTIO_BLK_MAX_MERGE_REQS 32

typedef struct MultiReqBuffer {
    VirtIOBlockReq *reqs[VIRTIO_BLK_MAX_MERGE_REQS];
    unsigned int num_reqs;
    bool is_write;
} MultiReqBuffer;

typedef struct VirtIOBlkClass {
    /*< private >*/
    VirtioDeviceClass parent;
    /*< public >*/
    bool (*handle_unknown_request)(VirtIOBlockReq *req, MultiReqBuffer *mrb,
                                   uint32_t type);
} VirtIOBlkClass;

void virtio_blk_handle_vq(VirtIOBlock *s, VirtQueue *vq);
void virtio_blk_req_complete(VirtIOBlockReq *req, unsigned char status);

#endif
