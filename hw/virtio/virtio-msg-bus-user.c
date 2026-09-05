/*
 * Virtio-msg bus backend over the virtio-msg user ABI.
 *
 * A lightweight bridge that opens a /dev/virtio-msg-N misc device and
 * forwards messages between QEMU's virtio-msg core and whichever kernel
 * driver published that node.  Nothing here is board-specific: the
 * doorbell, the shared-memory handshake and any address translation all
 * live on the kernel side.  On rave2 that driver is versal-virtio-msg.ko,
 * but any driver implementing the same ABI works.
 *
 * The ABI this speaks is:
 *
 *   read()/write()  one packed virtio-msg message per call.
 *   mmap()          offset 0 is the peer's memory window.
 *   ioctl()         VIRTIO_MSG_USER_GET_MEM_SIZE reports that window's size.
 *                   VIRTIO_MSG_USER_GET_POOL_INFO and VIRTIO_MSG_USER_DMA_VEC
 *                   are the optional DMA offload; see below.
 *
 * The window size has to match what the kernel driver programmed exactly, so
 * it is queried rather than configured.  The mem-size property overrides the
 * query, for drivers predating the ioctl.
 *
 * The DMA offload, when the driver has one, is what keeps a device model from
 * reading the window a byte at a time with the CPU.  The driver publishes a
 * pool of local memory it can name to its engine; we map it, hand out slots,
 * and turn a descriptor chain into one ioctl.  Everything about it is
 * optional at every step: no pool, an old kernel, or a chain that does not
 * fit and the device model reads the window itself, as it always did.
 *
 * One failure is not optional, though.  If the driver ever answers EHWPOISON
 * it has lost control of an engine that may still write the pool whenever it
 * pleases, and the pool becomes untouchable for the life of the fd: no more
 * transfers, no reads, and no slot handed back to be filled by someone else.
 * That is what pool_dead below is for.
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "qapi/error.h"
#include "qemu/bitmap.h"
#include "qemu/error-report.h"
#include "qemu/queue.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "hw/core/qdev-properties.h"

#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/virtio-msg-prot.h"
#include "hw/virtio/virtio-dma-offload.h"

/*
 * From the kernel's <linux/virtio_msg.h>.  Spelled out here rather than
 * included: the transport is an out-of-tree module today, so the header is in
 * no sysroot.  Keep the two in step.
 */
#define VIRTIO_MSG_USER_GET_MEM_SIZE _IOR('v', 0x00, uint64_t)

struct virtio_msg_user_pool_info {
    uint64_t offset;
    uint64_t size;
};

#define VIRTIO_MSG_USER_GET_POOL_INFO \
    _IOR('v', 0x01, struct virtio_msg_user_pool_info)

struct virtio_msg_user_dma_seg {
    uint64_t host_off;
    uint64_t pool_off;
    uint32_t len;
    uint32_t reserved;
};

#define VIRTIO_MSG_USER_DMA_MAX_SEGS 64

struct virtio_msg_user_dma_vec {
    uint64_t segs;
    uint32_t nsegs;
    uint32_t dir;
    uint32_t flags;
    uint32_t done;
};

#define VIRTIO_MSG_USER_DMA_FROM_HOST 0
#define VIRTIO_MSG_USER_DMA_TO_HOST   1
#define VIRTIO_MSG_USER_DMA_NOWAIT    (1u << 0)

#define VIRTIO_MSG_USER_DMA_VEC \
    _IOWR('v', 0x03, struct virtio_msg_user_dma_vec)

#define TYPE_VIRTIO_MSG_BUS_USER "virtio-msg-bus-user"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGBusUser,
                           VIRTIO_MSG_BUS_USER)

typedef struct VmsgUserPending {
    VirtIOMSG msg;
    QTAILQ_ENTRY(VmsgUserPending) next;
} VmsgUserPending;

typedef struct VirtIOMSGBusUser {
    VirtIOMSGBusDevice parent_obj;

    int fd;
    AddressSpace as;
    MemoryRegion mr_host;
    MemoryRegion mr_host_ram;
    MemoryRegion mr_host_ram_alias;

    /* The engine's local memory, and how slots are handed out of it. */
    void *pool;
    uint64_t pool_size;
    unsigned long *pool_used;   /* one bit per slot */
    unsigned int pool_slots;
    QemuMutex pool_lock;
    NotifierList slot_notifiers;
    /*
     * Latched when the driver reports the engine unstoppable.  Read from the
     * iothreads that allocate slots as well as the main loop, hence atomic;
     * it only ever goes false to true, so a racing reader that misses it once
     * simply sees it on the next call.
     */
    bool pool_dead;

    QemuMutex tx_lock;
    QTAILQ_HEAD(, VmsgUserPending) tx_pending;
    QEMUBH *tx_bh;
    QEMUTimer *tx_retry_timer;
    bool tx_handler_enabled;
    bool stopping;

    struct {
        uint64_t rx_messages;
        uint64_t tx_messages;
        uint64_t tx_eagain;
        uint64_t tx_errors;
        uint64_t tx_queued;
        uint64_t tx_retried;
        uint64_t tx_coalesced;
        uint64_t tx_retry_wakeups;
        uint64_t slot_requests;
        uint64_t slots_allocated;
        uint64_t slots_released;
        uint64_t slots_in_use;
        uint64_t pool_high_water;
        uint64_t pool_retries;
        uint64_t dma_requests;
        uint64_t dma_completions;
        uint64_t dma_bytes;
        uint64_t dma_segments;
        uint64_t fallback_count[VIRTIO_DMA_FALLBACK__MAX];
        uint64_t fallback_bytes[VIRTIO_DMA_FALLBACK__MAX];
    } stats;

    VirtIODMAOffload offload;

    struct {
        char *dev_path;
        uint64_t mem_size;
        uint64_t dma_min;
        bool dma_nowait;
    } cfg;
} VirtIOMSGBusUser;

#define VMSG_USER_DEFAULT_DEV "/dev/virtio-msg-0"
#define VMSG_USER_WIRE_MIN    50
#define VMSG_USER_WIRE_MAX    64

/*
 * One slot holds one gathered chain.  A virtio-net TSO buffer reaches 64 KB
 * and carries a header, so 128 KB is the next power of two that always fits
 * and the 4 MB pool still divides into a useful number of them.
 */
#define VMSG_USER_SLOT_SIZE   (128 * 1024)

/*
 * Below this, don't.  Measured on rave2: the engine runs a gathered chain at
 * ~400 MB/s against ~290 MB/s for the CPU, but charges ~10 us to start one,
 * which those 110 MB/s only pay back above about 7.5 KB.  Overridable,
 * because it is a property of somebody's engine and not of this code.
 */
#define VMSG_USER_DMA_MIN     8192
#define VMSG_USER_TX_RETRY_MS 1

static const char *const vmsg_user_fallback_name[] = {
    [VIRTIO_DMA_FALLBACK_BELOW_MIN] = "below_min",
    [VIRTIO_DMA_FALLBACK_POOL_FULL] = "pool_full",
    [VIRTIO_DMA_FALLBACK_POOL_UNAVAILABLE] = "pool_unavailable",
    [VIRTIO_DMA_FALLBACK_SLOT_TOO_LARGE] = "slot_too_large",
    [VIRTIO_DMA_FALLBACK_UNSUPPORTED_BUFFER] = "unsupported_buffer",
    [VIRTIO_DMA_FALLBACK_TOO_MANY_SEGS] = "too_many_segs",
    [VIRTIO_DMA_FALLBACK_DMA_BUSY] = "dma_busy",
    [VIRTIO_DMA_FALLBACK_DMA_ERROR] = "dma_error",
    [VIRTIO_DMA_FALLBACK_SLOT_LIMIT] = "slot_limit",
};

static void vmsg_user_record_fallback(void *opaque,
                                      VirtIODMAFallbackReason reason,
                                      size_t len)
{
    VirtIOMSGBusUser *s = opaque;

    assert(reason < VIRTIO_DMA_FALLBACK__MAX);
    qatomic_inc(&s->stats.fallback_count[reason]);
    qatomic_add(&s->stats.fallback_bytes[reason], len);
}

static void vmsg_user_update_pool_high_water(VirtIOMSGBusUser *s,
                                             uint64_t in_use)
{
    uint64_t old = qatomic_read(&s->stats.pool_high_water);

    while (in_use > old) {
        uint64_t seen = qatomic_cmpxchg(&s->stats.pool_high_water,
                                       old, in_use);

        if (seen == old) {
            break;
        }
        old = seen;
    }
}

static char *vmsg_user_get_stats(Object *obj, Error **errp)
{
    VirtIOMSGBusUser *s = VIRTIO_MSG_BUS_USER(obj);
    GString *out = g_string_new(NULL);
    VmsgUserPending *pending;
    uint64_t pending_count = 0;
    unsigned int i;

    qemu_mutex_lock(&s->tx_lock);
    QTAILQ_FOREACH(pending, &s->tx_pending, next) {
        pending_count++;
    }
    qemu_mutex_unlock(&s->tx_lock);

    g_string_append_printf(out,
        "rx_messages=%" PRIu64 " tx_messages=%" PRIu64
        " tx_eagain=%" PRIu64 " tx_errors=%" PRIu64
        " tx_queued=%" PRIu64 " tx_retried=%" PRIu64
        " tx_coalesced=%" PRIu64 " tx_retry_wakeups=%" PRIu64
        " tx_pending=%" PRIu64 "\n"
        "slot_requests=%" PRIu64 " slots_allocated=%" PRIu64
        " slots_released=%" PRIu64 " slots_in_use=%" PRIu64
        " pool_high_water=%" PRIu64 " pool_slots=%u"
        " pool_retries=%" PRIu64 "\n"
        "dma_requests=%" PRIu64 " dma_completions=%" PRIu64
        " dma_bytes=%" PRIu64 " dma_segments=%" PRIu64 "\n",
        qatomic_read(&s->stats.rx_messages),
        qatomic_read(&s->stats.tx_messages),
        qatomic_read(&s->stats.tx_eagain),
        qatomic_read(&s->stats.tx_errors),
        qatomic_read(&s->stats.tx_queued),
        qatomic_read(&s->stats.tx_retried),
        qatomic_read(&s->stats.tx_coalesced),
        qatomic_read(&s->stats.tx_retry_wakeups), pending_count,
        qatomic_read(&s->stats.slot_requests),
        qatomic_read(&s->stats.slots_allocated),
        qatomic_read(&s->stats.slots_released),
        qatomic_read(&s->stats.slots_in_use),
        qatomic_read(&s->stats.pool_high_water), s->pool_slots,
        qatomic_read(&s->stats.pool_retries),
        qatomic_read(&s->stats.dma_requests),
        qatomic_read(&s->stats.dma_completions),
        qatomic_read(&s->stats.dma_bytes),
        qatomic_read(&s->stats.dma_segments));

    for (i = 0; i < VIRTIO_DMA_FALLBACK__MAX; i++) {
        g_string_append_printf(out, "fallback_%s=%" PRIu64
                               " fallback_%s_bytes=%" PRIu64 "\n",
                               vmsg_user_fallback_name[i],
                               qatomic_read(&s->stats.fallback_count[i]),
                               vmsg_user_fallback_name[i],
                               qatomic_read(&s->stats.fallback_bytes[i]));
    }

    return g_string_free(out, false);
}

static bool vmsg_user_recv_once(VirtIOMSGBusUser *s)
{
    union {
        VirtIOMSG msg;
        uint8_t buf[64];
    } msg;
    ssize_t len;

    len = read(s->fd, msg.buf, sizeof(msg));
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false;
        }
        warn_report("virtio-msg-bus-user: read failed on %s: %s",
                    s->cfg.dev_path ?
                    s->cfg.dev_path : "<unknown>", strerror(errno));
        return false;
    }

    if (len == 0) {
        /* EOF. Treat as no more data. */
        return false;
    }

    if (len < VMSG_USER_WIRE_MIN) {
        warn_report("virtio-msg-bus-user: short message (%zd bytes) dropped", len);
        return true;
    }

    qatomic_inc(&s->stats.rx_messages);
    virtio_msg_bus_receive(VIRTIO_MSG_BUS_DEVICE(s), &msg.msg);
    return len >= 0;
}

static void virtio_msg_bus_user_process(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusUser *s = VIRTIO_MSG_BUS_USER(bd);
    bool r;

    do {
        r = vmsg_user_recv_once(s);
    } while (r);
}

static void vmsg_user_read(void *opaque)
{
    VirtIOMSGBusDevice *bd = opaque;

    virtio_msg_bus_user_process(bd);
}

static bool vmsg_user_same_used(const VirtIOMSG *a, const VirtIOMSG *b)
{
    return a->msg_id == VIRTIO_MSG_EVENT_USED &&
           b->msg_id == VIRTIO_MSG_EVENT_USED &&
           a->type == b->type && a->dev_num == b->dev_num &&
           a->event_used.index == b->event_used.index;
}

/* Called with tx_lock held. */
static bool vmsg_user_queue_tx(VirtIOMSGBusUser *s, const VirtIOMSG *msg)
{
    VmsgUserPending *pending;
    bool duplicate = false;

    /*
     * One future wakeup is enough for repeated completions on the same
     * virtqueue.  Stop at a non-EVENT_USED record so a reset/configuration
     * response remains an ordering boundary.
     */
    QTAILQ_FOREACH(pending, &s->tx_pending, next) {
        if (pending->msg.msg_id != VIRTIO_MSG_EVENT_USED) {
            duplicate = false;
        } else if (vmsg_user_same_used(&pending->msg, msg)) {
            duplicate = true;
        }
    }
    if (duplicate) {
        qatomic_inc(&s->stats.tx_coalesced);
        return false;
    }

    pending = g_new(VmsgUserPending, 1);
    pending->msg = *msg;
    QTAILQ_INSERT_TAIL(&s->tx_pending, pending, next);
    qatomic_inc(&s->stats.tx_queued);
    return true;
}

static void vmsg_user_write(void *opaque)
{
    VirtIOMSGBusUser *s = opaque;

    for (;;) {
        VmsgUserPending *pending;
        ssize_t written;

        qemu_mutex_lock(&s->tx_lock);
        pending = QTAILQ_FIRST(&s->tx_pending);
        if (!pending || s->stopping) {
            s->tx_handler_enabled = false;
            qemu_mutex_unlock(&s->tx_lock);
            timer_del(s->tx_retry_timer);
            qemu_set_fd_handler(s->fd, vmsg_user_read, NULL, s);
            return;
        }

        written = write(s->fd, &pending->msg, sizeof(pending->msg));
        if (written == sizeof(pending->msg)) {
            QTAILQ_REMOVE(&s->tx_pending, pending, next);
            qemu_mutex_unlock(&s->tx_lock);
            g_free(pending);
            qatomic_inc(&s->stats.tx_messages);
            qatomic_inc(&s->stats.tx_retried);
            continue;
        }

        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            qatomic_inc(&s->stats.tx_eagain);
            qemu_mutex_unlock(&s->tx_lock);
            timer_mod(s->tx_retry_timer,
                      qemu_clock_get_ms(QEMU_CLOCK_REALTIME) +
                      VMSG_USER_TX_RETRY_MS);
            return;
        }

        QTAILQ_REMOVE(&s->tx_pending, pending, next);
        qemu_mutex_unlock(&s->tx_lock);
        warn_report("virtio-msg-bus-user: queued write failed on %s: %s",
                    s->cfg.dev_path ? s->cfg.dev_path : "<unknown>",
                    written < 0 ? strerror(errno) : "short write");
        qatomic_inc(&s->stats.tx_errors);
        g_free(pending);
    }
}

static void vmsg_user_retry_timer(void *opaque)
{
    VirtIOMSGBusUser *s = opaque;

    qatomic_inc(&s->stats.tx_retry_wakeups);
    vmsg_user_write(s);
}

static void vmsg_user_enable_write(void *opaque)
{
    VirtIOMSGBusUser *s = opaque;
    bool enable;

    qemu_mutex_lock(&s->tx_lock);
    enable = !s->stopping && !QTAILQ_EMPTY(&s->tx_pending);
    s->tx_handler_enabled = enable;
    qemu_mutex_unlock(&s->tx_lock);

    if (enable) {
        qemu_set_fd_handler(s->fd, vmsg_user_read, vmsg_user_write, s);
        timer_mod(s->tx_retry_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_REALTIME) +
                  VMSG_USER_TX_RETRY_MS);
    }
}

static int virtio_msg_bus_user_send(VirtIOMSGBusDevice *bd,
                                           VirtIOMSG *msg_req)
{
    VirtIOMSGBusUser *s = VIRTIO_MSG_BUS_USER(bd);
    bool schedule = false;
    ssize_t written;

    qemu_mutex_lock(&s->tx_lock);
    if (s->stopping) {
        qemu_mutex_unlock(&s->tx_lock);
        return VIRTIO_MSG_ERROR_MEMORY;
    }

    if (!QTAILQ_EMPTY(&s->tx_pending)) {
        vmsg_user_queue_tx(s, msg_req);
        schedule = !s->tx_handler_enabled;
        qemu_mutex_unlock(&s->tx_lock);
        if (schedule) {
            qemu_bh_schedule(s->tx_bh);
        }
        return VIRTIO_MSG_NO_ERROR;
    }

    written = write(s->fd, msg_req, sizeof *msg_req);

    if (written == sizeof *msg_req) {
        qemu_mutex_unlock(&s->tx_lock);
        qatomic_inc(&s->stats.tx_messages);
        return VIRTIO_MSG_NO_ERROR;
    }

    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        qatomic_inc(&s->stats.tx_eagain);
        vmsg_user_queue_tx(s, msg_req);
        schedule = !s->tx_handler_enabled;
        qemu_mutex_unlock(&s->tx_lock);
        if (schedule) {
            qemu_bh_schedule(s->tx_bh);
        }
        return VIRTIO_MSG_NO_ERROR;
    }

    qemu_mutex_unlock(&s->tx_lock);
    qatomic_inc(&s->stats.tx_errors);
    warn_report("virtio-msg-bus-user: write failed on %s: %s",
                s->cfg.dev_path ? s->cfg.dev_path : "<unknown>", strerror(errno));
    return VIRTIO_MSG_ERROR_MEMORY;
}

/*
 * Slots are fixed size and few, so the allocator is a bitmap scan.  Anything
 * cleverer would be optimising an operation that costs far less than the DMA
 * it sets up.
 *
 * The bit operations must be the atomic ones.  Callers are not confined to the
 * main loop: virtio-blk allocates a slot per request from its iothread, so two
 * dataplanes hit this concurrently.  With the plain load-modify-store variants
 * the same slot gets handed to two callers -- measured on rave2 at roughly one
 * collision per 9000 allocations with two blk devices on two iothreads, which
 * is silent data corruption, both writers gathering into one buffer.
 */
static VirtIODMAResult
vmsg_user_slots_reserve(void *opaque, unsigned int nslots,
                        const size_t *lengths, void **slots,
                        VirtIODMAFallbackReason *reason)
{
    VirtIOMSGBusUser *s = opaque;
    unsigned int free_slots = 0;
    unsigned int i, n = 0;

    qatomic_add(&s->stats.slot_requests, nslots);

    if (!s->pool || qatomic_read(&s->pool_dead)) {
        *reason = VIRTIO_DMA_FALLBACK_POOL_UNAVAILABLE;
        return VIRTIO_DMA_FALLBACK;
    }
    if (nslots > s->pool_slots) {
        *reason = VIRTIO_DMA_FALLBACK_SLOT_LIMIT;
        return VIRTIO_DMA_FALLBACK;
    }
    for (i = 0; i < nslots; i++) {
        if (lengths[i] > VMSG_USER_SLOT_SIZE) {
            *reason = VIRTIO_DMA_FALLBACK_SLOT_TOO_LARGE;
            return VIRTIO_DMA_FALLBACK;
        }
    }

    qemu_mutex_lock(&s->pool_lock);
    for (i = 0; i < s->pool_slots; i++) {
        if (!test_bit(i, s->pool_used)) {
            free_slots++;
        }
    }
    if (free_slots < nslots) {
        qemu_mutex_unlock(&s->pool_lock);
        qatomic_inc(&s->stats.pool_retries);
        *reason = VIRTIO_DMA_FALLBACK_POOL_FULL;
        return VIRTIO_DMA_RETRY;
    }

    for (i = 0; i < s->pool_slots && n < nslots; i++) {
        if (!test_bit(i, s->pool_used)) {
            set_bit(i, s->pool_used);
            slots[n++] = (uint8_t *)s->pool +
                         (size_t)i * VMSG_USER_SLOT_SIZE;
        }
    }

    qatomic_add(&s->stats.slots_allocated, nslots);
    vmsg_user_update_pool_high_water(
        s, qatomic_add_fetch(&s->stats.slots_in_use, nslots));
    qemu_mutex_unlock(&s->pool_lock);
    return VIRTIO_DMA_OK;
}

static void vmsg_user_slots_release(void *opaque, unsigned int nslots,
                                    void **slots, const size_t *lengths)
{
    VirtIOMSGBusUser *s = opaque;
    unsigned int i;

    (void)lengths;

    if (!s->pool || qatomic_read(&s->pool_dead)) {
        return;
    }

    qemu_mutex_lock(&s->pool_lock);
    for (i = 0; i < nslots; i++) {
        size_t off = (uint8_t *)slots[i] - (uint8_t *)s->pool;

        clear_bit(off / VMSG_USER_SLOT_SIZE, s->pool_used);
    }
    qatomic_add(&s->stats.slots_released, nslots);
    qatomic_sub(&s->stats.slots_in_use, nslots);
    notifier_list_notify(&s->slot_notifiers, NULL);
    qemu_mutex_unlock(&s->pool_lock);
}

static void *vmsg_user_slot_new(void *opaque, size_t len,
                                VirtIODMAFallbackReason *reason)
{
    void *slot;

    if (vmsg_user_slots_reserve(opaque, 1, &len, &slot, reason) ==
        VIRTIO_DMA_OK) {
        return slot;
    }

    return NULL;
}

static void vmsg_user_slot_delete(void *opaque, void *slot, size_t len)
{
    VirtIOMSGBusUser *s = opaque;
    if (!slot) {
        return;
    }

    vmsg_user_slots_release(s, 1, &slot, &len);
}

static void vmsg_user_slot_notifier_add(void *opaque, Notifier *notifier)
{
    VirtIOMSGBusUser *s = opaque;

    qemu_mutex_lock(&s->pool_lock);
    notifier_list_add(&s->slot_notifiers, notifier);
    qemu_mutex_unlock(&s->pool_lock);
}

static void vmsg_user_slot_notifier_remove(void *opaque, Notifier *notifier)
{
    VirtIOMSGBusUser *s = opaque;

    qemu_mutex_lock(&s->pool_lock);
    notifier_remove(notifier);
    qemu_mutex_unlock(&s->pool_lock);
}

static void vmsg_user_pool_retire(VirtIOMSGBusUser *s)
{
    qatomic_set(&s->pool_dead, true);
    qemu_mutex_lock(&s->pool_lock);
    notifier_list_notify(&s->slot_notifiers, NULL);
    qemu_mutex_unlock(&s->pool_lock);
}

/*
 * The two directions differ by one field.  A seg vector names a window offset
 * and a pool offset for every piece and the direction separately, so the same
 * vector that pulls a chain in pushes one back out -- which is the whole
 * reason adding the reverse costs a parameter rather than a driver change.
 * Kept as one function so a bounds check can never be fixed on one side only.
 */
static bool vmsg_user_dma_vec(VirtIOMSGBusUser *s, const void *slot,
                              const struct iovec *sg, unsigned int num,
                              size_t len, uint32_t dir,
                              VirtIODMAFallbackReason *reason)
{
    struct virtio_msg_user_dma_seg segs[VIRTIO_MSG_USER_DMA_MAX_SEGS];
    struct virtio_msg_user_dma_vec vec;
    uint8_t *window = memory_region_get_ram_ptr(&s->mr_host);
    size_t pool_off = (const uint8_t *)slot - (uint8_t *)s->pool;
    size_t got = 0;
    unsigned int i;

    if (!s->pool || qatomic_read(&s->pool_dead)) {
        *reason = VIRTIO_DMA_FALLBACK_POOL_UNAVAILABLE;
        return false;
    }
    if (num > VIRTIO_MSG_USER_DMA_MAX_SEGS) {
        *reason = VIRTIO_DMA_FALLBACK_TOO_MANY_SEGS;
        return false;
    }
    if (len > VMSG_USER_SLOT_SIZE) {
        *reason = VIRTIO_DMA_FALLBACK_SLOT_TOO_LARGE;
        return false;
    }

    for (i = 0; i < num; i++) {
        uint8_t *base = sg[i].iov_base;

        /*
         * Decline anything not in the window.  This is not a sanity check
         * that should never fire: a device model is free to splice a buffer
         * of its own into the chain -- virtio-net does exactly that with a
         * byte-swapped header on a stack address -- and the engine cannot
         * reach it.  Falling back is the correct answer, not an error.
         */
        if (base < window || base + sg[i].iov_len > window + s->cfg.mem_size) {
            *reason = VIRTIO_DMA_FALLBACK_UNSUPPORTED_BUFFER;
            return false;
        }

        segs[i].host_off = base - window;
        segs[i].pool_off = pool_off + got;
        segs[i].len = sg[i].iov_len;
        segs[i].reserved = 0;
        got += sg[i].iov_len;
    }

    if (got != len) {
        *reason = VIRTIO_DMA_FALLBACK_UNSUPPORTED_BUFFER;
        return false;
    }

    vec.segs = (uintptr_t)segs;
    vec.nsegs = num;
    vec.dir = dir;
    vec.flags = s->cfg.dma_nowait ? VIRTIO_MSG_USER_DMA_NOWAIT : 0;
    vec.done = 0;

    qatomic_inc(&s->stats.dma_requests);

    if (ioctl(s->fd, VIRTIO_MSG_USER_DMA_VEC, &vec) < 0) {
        if (errno == EHWPOISON) {
            /*
             * The engine would not stop and the driver has given up on it.
             * Retiring the pool here rather than declining this one transfer
             * is what keeps us off bytes it may still write: from now on no
             * slot is handed out, no slot is recycled, and every chain goes
             * over the window with the CPU as it did before there was an
             * engine.  Only a device reset brings it back.
             */
            vmsg_user_pool_retire(s);
            *reason = VIRTIO_DMA_FALLBACK_POOL_UNAVAILABLE;
            error_report("virtio-msg-bus-user: the DMA engine could not be "
                         "stopped; retiring the pool and copying with the CPU");
            return false;
        }

        /*
         * Contention in NOWAIT mode is expected, and the caller's normal CPU
         * path is exactly the low-latency fallback it requested.  The kernel
         * claims a channel before syncing or moving anything, so -EBUSY must
         * report zero completed segments.
         */
        if (errno == EBUSY && s->cfg.dma_nowait && vec.done == 0) {
            *reason = VIRTIO_DMA_FALLBACK_DMA_BUSY;
            return false;
        }

        /*
         * Rate-limited by being a warning nobody should see: the kernel
         * bounds-checks the whole vector before running any of it, so a
         * failure here means the engine itself faulted, and the caller's
         * fallback still produces the right bytes.
         */
        warn_report_once("virtio-msg-bus-user: DMA %s failed (%s); "
                         "falling back to a CPU copy",
                         dir == VIRTIO_MSG_USER_DMA_FROM_HOST ?
                         "gather" : "scatter", strerror(errno));
        *reason = VIRTIO_DMA_FALLBACK_DMA_ERROR;
        return false;
    }

    qatomic_inc(&s->stats.dma_completions);
    qatomic_add(&s->stats.dma_bytes, len);
    qatomic_add(&s->stats.dma_segments, num);
    return true;
}

static bool vmsg_user_gather(void *opaque, void *slot, const struct iovec *sg,
                             unsigned int num, size_t len,
                             VirtIODMAFallbackReason *reason)
{
    return vmsg_user_dma_vec(opaque, slot, sg, num, len,
                             VIRTIO_MSG_USER_DMA_FROM_HOST, reason);
}

static bool vmsg_user_scatter(void *opaque, const void *slot,
                              const struct iovec *sg, unsigned int num,
                              size_t len)
{
    VirtIODMAFallbackReason reason;

    return vmsg_user_dma_vec(opaque, slot, sg, num, len,
                             VIRTIO_MSG_USER_DMA_TO_HOST, &reason);
}

static void vmsg_user_pool_init(VirtIOMSGBusUser *s)
{
    struct virtio_msg_user_pool_info info;

    if (ioctl(s->fd, VIRTIO_MSG_USER_GET_POOL_INFO, &info) < 0 || !info.size) {
        return;
    }

    if (info.size < VMSG_USER_SLOT_SIZE) {
        warn_report("virtio-msg-bus-user: DMA pool is %" PRIu64 " bytes, "
                    "too small for a slot; offload disabled", info.size);
        return;
    }

    /*
     * The pool is a second mapping of the same fd at an offset the driver
     * chooses, far above any window size so the two never collide.  Unlike
     * the window it is ordinary local memory, so nothing here has to care
     * about its cache attributes -- the driver's ioctl does the syncing.
     */
    s->pool = mmap(NULL, info.size, PROT_READ | PROT_WRITE, MAP_SHARED,
                   s->fd, info.offset);
    if (s->pool == MAP_FAILED) {
        s->pool = NULL;
        warn_report("virtio-msg-bus-user: cannot map the DMA pool (%s); "
                    "offload disabled", strerror(errno));
        return;
    }

    s->pool_size = info.size;
    s->pool_slots = info.size / VMSG_USER_SLOT_SIZE;
    s->pool_used = bitmap_new(s->pool_slots);

    s->offload.gather = vmsg_user_gather;
    s->offload.scatter = vmsg_user_scatter;
    s->offload.slot_new = vmsg_user_slot_new;
    s->offload.slot_delete = vmsg_user_slot_delete;
    s->offload.slots_reserve = vmsg_user_slots_reserve;
    s->offload.slots_release = vmsg_user_slots_release;
    s->offload.slot_notifier_add = vmsg_user_slot_notifier_add;
    s->offload.slot_notifier_remove = vmsg_user_slot_notifier_remove;
    s->offload.record_fallback = vmsg_user_record_fallback;
    s->offload.min_len = s->cfg.dma_min;
    s->offload.max_len = VMSG_USER_SLOT_SIZE;
    s->offload.max_segs = VIRTIO_MSG_USER_DMA_MAX_SEGS;
    s->offload.opaque = s;

    virtio_dma_offload_register(&s->as, &s->offload);
}

static void vmsg_user_pool_free(VirtIOMSGBusUser *s)
{
    if (!s->pool) {
        return;
    }

    vmsg_user_pool_retire(s);
    virtio_dma_offload_unregister(&s->as);
    munmap(s->pool, s->pool_size);
    g_free(s->pool_used);

    s->pool = NULL;
    s->pool_used = NULL;
    s->pool_slots = 0;
}

static AddressSpace *
virtio_msg_bus_user_get_remote_as(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusUser *s = VIRTIO_MSG_BUS_USER(bd);

    return &s->as;
}

static void virtio_msg_bus_user_unrealize(DeviceState *dev)
{
    VirtIOMSGBusUser *s = VIRTIO_MSG_BUS_USER(dev);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);
    VmsgUserPending *pending;

    qemu_mutex_lock(&s->tx_lock);
    s->stopping = true;
    qemu_mutex_unlock(&s->tx_lock);

    if (s->tx_bh) {
        qemu_bh_delete(s->tx_bh);
        s->tx_bh = NULL;
    }
    timer_free(s->tx_retry_timer);
    s->tx_retry_timer = NULL;

    vmsg_user_pool_free(s);

    if (s->fd >= 0) {
        qemu_set_fd_handler(s->fd, NULL, NULL, NULL);
        close(s->fd);
        s->fd = -1;
    }

    qemu_mutex_lock(&s->tx_lock);
    while ((pending = QTAILQ_FIRST(&s->tx_pending))) {
        QTAILQ_REMOVE(&s->tx_pending, pending, next);
        g_free(pending);
    }
    qemu_mutex_unlock(&s->tx_lock);

    g_free(s->cfg.dev_path);
    s->cfg.dev_path = NULL;

    if (bdc->parent_unrealize) {
        bdc->parent_unrealize(dev);
    }
}

static void virtio_msg_bus_user_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusUser *s = VIRTIO_MSG_BUS_USER(dev);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);

    if (bdc->parent_realize) {
        bdc->parent_realize(dev, errp);
        if (*errp) {
            return;
        }
    }

    if (!s->cfg.dev_path) {
        s->cfg.dev_path = g_strdup(VMSG_USER_DEFAULT_DEV);
    }

    s->fd = open(s->cfg.dev_path, O_RDWR | O_NONBLOCK);
    if (s->fd < 0) {
        error_setg_errno(errp, errno,
                         "virtio-msg-bus-user: failed to open %s",
                         s->cfg.dev_path);
        return;
    }

    /*
     * Ask the driver how big its window is.  Only fall back to the property
     * if it cannot say -- a stale hardcoded size that disagrees with the
     * driver fails later and much less legibly, inside mmap().
     */
    if (!s->cfg.mem_size) {
        uint64_t mem_size = 0;

        if (ioctl(s->fd, VIRTIO_MSG_USER_GET_MEM_SIZE, &mem_size) < 0) {
            error_setg_errno(errp, errno,
                             "virtio-msg-bus-user: %s cannot report its memory "
                             "window size; set mem-size explicitly",
                             s->cfg.dev_path);
            goto err_close;
        }

        if (!mem_size) {
            error_setg(errp, "virtio-msg-bus-user: %s publishes no memory "
                       "window", s->cfg.dev_path);
            goto err_close;
        }

        s->cfg.mem_size = mem_size;
    }

    s->tx_bh = qemu_bh_new(vmsg_user_enable_write, s);
    s->tx_retry_timer = timer_new_ms(QEMU_CLOCK_REALTIME,
                                     vmsg_user_retry_timer, s);
    qemu_set_fd_handler(s->fd, vmsg_user_read, NULL, s);

    memory_region_init_ram_from_fd(&s->mr_host, OBJECT(s), "mr",
                                     s->cfg.mem_size,
                                     RAM_SHARED | RAM_NORESERVE,
                                     s->fd,
                                     0,
                                     &error_abort);

    memory_region_init_alias(&s->mr_host_ram, OBJECT(s), "mr-host-ram",
                             &s->mr_host,
                             0, s->cfg.mem_size);

    memory_region_init_alias(&s->mr_host_ram_alias, OBJECT(s),
                             "mr-host-ram-alias",
                             &s->mr_host,
                             0, s->cfg.mem_size);

    address_space_init(&s->as, MEMORY_REGION(&s->mr_host_ram), "msg-bus-as");
    memory_region_add_subregion(get_system_memory(), 0, &s->mr_host_ram_alias);

    if (!s->cfg.dma_min) {
        s->cfg.dma_min = VMSG_USER_DMA_MIN;
    }

    /*
     * Last, because it registers against the AddressSpace above.  A driver
     * with no pool, or one too old to know the ioctl, simply leaves nothing
     * registered and every device model reads the window itself.
     */
    vmsg_user_pool_init(s);
    return;

err_close:
    close(s->fd);
    s->fd = -1;
}

static const Property virtio_msg_bus_user_props[] = {
    DEFINE_PROP_STRING("dev", VirtIOMSGBusUser, cfg.dev_path),
    DEFINE_PROP_UINT64("mem-size", VirtIOMSGBusUser, cfg.mem_size, 0),
    /* 0 means the measured default; see VMSG_USER_DMA_MIN. */
    DEFINE_PROP_UINT64("dma-min", VirtIOMSGBusUser, cfg.dma_min, 0),
    DEFINE_PROP_BOOL("dma-nowait", VirtIOMSGBusUser, cfg.dma_nowait, false),
};

static void virtio_msg_bus_user_init(Object *obj)
{
    VirtIOMSGBusUser *s = VIRTIO_MSG_BUS_USER(obj);

    s->fd = -1;
    qemu_mutex_init(&s->tx_lock);
    qemu_mutex_init(&s->pool_lock);
    QTAILQ_INIT(&s->tx_pending);
    notifier_list_init(&s->slot_notifiers);
    object_property_add_str(obj, "stats", vmsg_user_get_stats, NULL);
}

static void virtio_msg_bus_user_finalize(Object *obj)
{
    VirtIOMSGBusUser *s = VIRTIO_MSG_BUS_USER(obj);

    qemu_mutex_destroy(&s->pool_lock);
    qemu_mutex_destroy(&s->tx_lock);
}

static void virtio_msg_bus_user_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_msg_bus_user_props);
    dc->realize = virtio_msg_bus_user_realize;
    dc->unrealize = virtio_msg_bus_user_unrealize;

    bdc->process = virtio_msg_bus_user_process;
    bdc->send = virtio_msg_bus_user_send;
    bdc->get_remote_as = virtio_msg_bus_user_get_remote_as;
}

static const TypeInfo virtio_msg_bus_user_info = {
    .name          = TYPE_VIRTIO_MSG_BUS_USER,
    .parent        = TYPE_VIRTIO_MSG_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGBusUser),
    .instance_init = virtio_msg_bus_user_init,
    .instance_finalize = virtio_msg_bus_user_finalize,
    .class_init    = virtio_msg_bus_user_class_init,
};

static void virtio_msg_bus_user_register_types(void)
{
    type_register_static(&virtio_msg_bus_user_info);
}

type_init(virtio_msg_bus_user_register_types);
