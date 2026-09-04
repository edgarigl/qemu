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
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/log.h"
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
    /*
     * Latched when the driver reports the engine unstoppable.  Read from the
     * iothreads that allocate slots as well as the main loop, hence atomic;
     * it only ever goes false to true, so a racing reader that misses it once
     * simply sees it on the next call.
     */
    bool pool_dead;

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

static int virtio_msg_bus_user_send(VirtIOMSGBusDevice *bd,
                                           VirtIOMSG *msg_req)
{
    VirtIOMSGBusUser *s = VIRTIO_MSG_BUS_USER(bd);
    ssize_t written;

    written = write(s->fd, msg_req, sizeof *msg_req);

    if (written == sizeof *msg_req) {
        return VIRTIO_MSG_NO_ERROR;
    }

    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return VIRTIO_MSG_ERROR_RETRY;
    }

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
static void *vmsg_user_slot_new(void *opaque, size_t len)
{
    VirtIOMSGBusUser *s = opaque;
    unsigned int i;

    if (!s->pool || qatomic_read(&s->pool_dead) ||
        len > VMSG_USER_SLOT_SIZE) {
        return NULL;
    }

    for (i = 0; i < s->pool_slots; i++) {
        if (!test_and_set_bit_atomic(i, s->pool_used)) {
            return (uint8_t *)s->pool + (size_t)i * VMSG_USER_SLOT_SIZE;
        }
    }

    return NULL;
}

static void vmsg_user_slot_delete(void *opaque, void *slot, size_t len)
{
    VirtIOMSGBusUser *s = opaque;
    size_t off;

    /*
     * A dead engine may still be writing this slot, so it is not free and
     * never becomes free again.  Leaking it is the point: the bit stays set
     * so nothing else is ever pointed at these bytes.
     */
    if (!s->pool || !slot || qatomic_read(&s->pool_dead)) {
        return;
    }

    off = (uint8_t *)slot - (uint8_t *)s->pool;
    clear_bit_atomic(off / VMSG_USER_SLOT_SIZE, s->pool_used);
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
                              size_t len, uint32_t dir)
{
    struct virtio_msg_user_dma_seg segs[VIRTIO_MSG_USER_DMA_MAX_SEGS];
    struct virtio_msg_user_dma_vec vec;
    uint8_t *window = memory_region_get_ram_ptr(&s->mr_host);
    size_t pool_off = (const uint8_t *)slot - (uint8_t *)s->pool;
    size_t got = 0;
    unsigned int i;

    if (!s->pool || qatomic_read(&s->pool_dead) ||
        num > VIRTIO_MSG_USER_DMA_MAX_SEGS ||
        len > VMSG_USER_SLOT_SIZE) {
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
            return false;
        }

        segs[i].host_off = base - window;
        segs[i].pool_off = pool_off + got;
        segs[i].len = sg[i].iov_len;
        segs[i].reserved = 0;
        got += sg[i].iov_len;
    }

    if (got != len) {
        return false;
    }

    vec.segs = (uintptr_t)segs;
    vec.nsegs = num;
    vec.dir = dir;
    vec.flags = s->cfg.dma_nowait ? VIRTIO_MSG_USER_DMA_NOWAIT : 0;
    vec.done = 0;

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
            qatomic_set(&s->pool_dead, true);
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
        return false;
    }

    return true;
}

static bool vmsg_user_gather(void *opaque, void *slot, const struct iovec *sg,
                             unsigned int num, size_t len)
{
    return vmsg_user_dma_vec(opaque, slot, sg, num, len,
                             VIRTIO_MSG_USER_DMA_FROM_HOST);
}

static bool vmsg_user_scatter(void *opaque, const void *slot,
                              const struct iovec *sg, unsigned int num,
                              size_t len)
{
    return vmsg_user_dma_vec(opaque, slot, sg, num, len,
                             VIRTIO_MSG_USER_DMA_TO_HOST);
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

    vmsg_user_pool_free(s);

    if (s->fd >= 0) {
        qemu_set_fd_handler(s->fd, NULL, NULL, NULL);
        close(s->fd);
        s->fd = -1;
    }

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
    .class_init    = virtio_msg_bus_user_class_init,
};

static void virtio_msg_bus_user_register_types(void)
{
    type_register_static(&virtio_msg_bus_user_info);
}

type_init(virtio_msg_bus_user_register_types);
