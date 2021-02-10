/*
 * QEMU model of ZynqMP CSU Stream DMA
 *
 * Copyright (c) 2013 Xilinx Inc
 * Copyright (c) 2013 Peter Crosthwaite <peter.crosthwaite@xilinx.com>
 * Copyright (c) 2013 Edgar E. Iglesias <edgar.iglesias@xilinx.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qemu/log.h"
#include "hw/irq.h"
#include "hw/stream.h"
#include "hw/ptimer.h"
#include "qemu/bitops.h"
#include "sysemu/dma.h"
#include "hw/register.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"
#include "migration/vmstate.h"
#include "hw/qdev-properties.h"
#include "hw/dma/xlnx-csu-stream-dma.h"

#ifndef XLNX_CSU_DMA_ERR_DEBUG
#define XLNX_CSU_DMA_ERR_DEBUG 0
#endif

REG32(ADDR, 0x0)
    FIELD(ADDR, ADDR, 2, 30)
REG32(SIZE, 0x4)
    FIELD(SIZE, SIZE, 2, 27)
    FIELD(SIZE, LAST_WORD, 0, 1)
REG32(STATUS, 0x8)
    FIELD(STATUS, CMD_Q_EMPTY, 17, 1)
    FIELD(STATUS, CMD_Q_FULL, 16, 1)
    FIELD(STATUS, DONE_CNT, 13, 3)
    FIELD(STATUS, SRC_FIFO_LEVEL, 5, 8)
    FIELD(STATUS, RD_OUTSTANDING, 1, 4)
    FIELD(STATUS, BUSY, 0, 1)
REG32(CTRL, 0xc)
    FIELD(CTRL, APB_ERR_RESP, 24, 1)
    FIELD(CTRL, ENDIANNESS, 23, 1)
    FIELD(CTRL, AXI_BRST_TYPE, 22, 1)
    FIELD(CTRL, TIMEOUT_VAL, 10, 12)
    FIELD(CTRL, FIFO_THRESH, 2, 8)
    FIELD(CTRL, PAUSE_STRM, 1, 1)
    FIELD(CTRL, PAUSE_MEM, 0, 1)
REG32(CRC0, 0x10)
REG32(INT_STATUS, 0x14)
    FIELD(INT_STATUS, WR_FULL_CMDQ, 7, 1)
    FIELD(INT_STATUS, INVALID_APB, 6, 1)
    FIELD(INT_STATUS, THRESH_HIT, 5, 1)
    FIELD(INT_STATUS, TIMEOUT_MEM, 4, 1)
    FIELD(INT_STATUS, TIMEOUT_STRM, 3, 1)
    FIELD(INT_STATUS, AXI_RDERR, 2, 1)
    FIELD(INT_STATUS, DONE, 1, 1)
    FIELD(INT_STATUS, MEM_DONE, 0, 1)
REG32(INT_ENABLE, 0x18)
    FIELD(INT_ENABLE, WR_FULL_CMDQ, 7, 1)
    FIELD(INT_ENABLE, INVALID_APB, 6, 1)
    FIELD(INT_ENABLE, THRESH_HIT, 5, 1)
    FIELD(INT_ENABLE, TIMEOUT_MEM, 4, 1)
    FIELD(INT_ENABLE, TIMEOUT_STRM, 3, 1)
    FIELD(INT_ENABLE, AXI_RDERR, 2, 1)
    FIELD(INT_ENABLE, DONE, 1, 1)
    FIELD(INT_ENABLE, MEM_DONE, 0, 1)
REG32(INT_DISABLE, 0x1c)
    FIELD(INT_DISABLE, WR_FULL_CMDQ, 7, 1)
    FIELD(INT_DISABLE, INVALID_APB, 6, 1)
    FIELD(INT_DISABLE, THRESH_HIT, 5, 1)
    FIELD(INT_DISABLE, TIMEOUT_MEM, 4, 1)
    FIELD(INT_DISABLE, TIMEOUT_STRM, 3, 1)
    FIELD(INT_DISABLE, AXI_RDERR, 2, 1)
    FIELD(INT_DISABLE, DONE, 1, 1)
    FIELD(INT_DISABLE, MEM_DONE, 0, 1)
REG32(INT_MASK, 0x20)
    FIELD(INT_MASK, WR_FULL_CMDQ, 7, 1)
    FIELD(INT_MASK, INVALID_APB, 6, 1)
    FIELD(INT_MASK, THRESH_HIT, 5, 1)
    FIELD(INT_MASK, TIMEOUT_MEM, 4, 1)
    FIELD(INT_MASK, TIMEOUT_STRM, 3, 1)
    FIELD(INT_MASK, AXI_RDERR, 2, 1)
    FIELD(INT_MASK, DONE, 1, 1)
    FIELD(INT_MASK, MEM_DONE, 0, 1)
REG32(CTRL2, 0x24)
    FIELD(CTRL2, RAM_EMASA, 27, 1)
    FIELD(CTRL2, ARCACHE, 24, 3)
    FIELD(CTRL2, ROUTE_BIT, 23, 1)
    FIELD(CTRL2, TIMEOUT_EN, 22, 1)
    FIELD(CTRL2, RAM_EMAB, 19, 3)
    FIELD(CTRL2, RAM_EMAA, 16, 3)
    FIELD(CTRL2, TIMEOUT_PRE, 4, 12)
    FIELD(CTRL2, MAX_OUTS_CMDS, 0, 4)
REG32(ADDR_MSB, 0x28)
    FIELD(ADDR_MSB, ADDR_MSB, 0, 17)

#define CTRL_RSVD       (~((1 << 25) - 1))

#define INT_RSVD        (~((1 << 8) - 1))
#define INT_ALL_SRC     ((~(INT_RSVD)) & (~(R_INT_STATUS_WR_FULL_CMDQ_MASK)))
#define INT_ALL_DST     ((~(INT_RSVD)) & (~(R_INT_STATUS_MEM_DONE_MASK)))

#define CTRL2_RSVD      (~((1 << 28) - 1))
#define SIZE_MASK       ((1 << 29) - 1)

static bool dmach_is_paused(XlnxCSUDMA *s)
{
    bool paused;

    paused = !!(s->regs[R_CTRL] & R_CTRL_PAUSE_STRM_MASK);
    paused |= !!(s->regs[R_CTRL] & R_CTRL_PAUSE_MEM_MASK);
    return paused;
}

static bool dmach_get_eop(XlnxCSUDMA *s)
{
    return !!(s->regs[R_SIZE] & s->r_size_last_word_mask);
}

static uint32_t dmach_get_size(XlnxCSUDMA *s)
{
    uint32_t ret;

    if (s->byte_align) {
        ret = s->regs[R_SIZE];
    } else {
        ret = s->regs[R_SIZE] & ~3;
    }

    ret &= SIZE_MASK;
    return ret;
}

static void dmach_set_size(XlnxCSUDMA *s, uint32_t size)
{
    size &= SIZE_MASK;
    if (!s->byte_align) {
        assert((size & 3) == 0);
    }
    s->regs[R_SIZE] &= s->r_size_last_word_mask;
    s->regs[R_SIZE] |= size;
}

static bool dmach_burst_is_fixed(XlnxCSUDMA *s)
{
    return !!(s->regs[R_CTRL] & R_CTRL_AXI_BRST_TYPE_MASK);
}

static bool dmach_timeout_enabled(XlnxCSUDMA *s)
{
    return s->regs[R_CTRL2] & R_CTRL2_TIMEOUT_EN_MASK;
}

static inline void dmach_update_dma_cnt(XlnxCSUDMA *s, int a)
{
    int cnt;

    /* Increase dma_cnt.  */
    cnt = ARRAY_FIELD_EX32(s->regs, STATUS, DONE_CNT) + a;
    ARRAY_FIELD_DP32(s->regs, STATUS, DONE_CNT, cnt);
}

static void dmach_done(XlnxCSUDMA *s)
{
    dmach_update_dma_cnt(s, 1);
    s->regs[R_STATUS] &= ~R_STATUS_BUSY_MASK;

    s->regs[R_INT_STATUS] |= R_INT_STATUS_DONE_MASK;
    if (!s->is_dst) {
        s->regs[R_INT_STATUS] |= R_INT_STATUS_MEM_DONE_MASK;
    }
}

static void dmach_advance(XlnxCSUDMA *s, unsigned int len)
{
    uint32_t size = dmach_get_size(s);

    if (!s->byte_align) {
        /* Has to be 32bit aligned.  */
        assert((len & 3) == 0);
    }
    assert(len <= size);

    if (!dmach_burst_is_fixed(s)) {
        s->regs[R_ADDR] += len;
    }

    size -= len;
    dmach_set_size(s, size);

    if (size == 0) {
        dmach_done(s);
    }
}

static void dmach_data_process(XlnxCSUDMA *s, uint8_t *buf,
                               unsigned int len)
{
    unsigned int bswap;
    unsigned int i;

    /* Xor only for src channel.  */
    bswap = s->regs[R_CTRL] & R_CTRL_ENDIANNESS_MASK;
    if (s->is_dst && !bswap) {
        /* Fast!  */
        return;
    }

    if (!s->byte_align) {
        /* buf might not be 32bit aligned... slooow.  */
        assert((len & 3) == 0);
    }

    for (i = 0; i < len; i += 4) {
        uint8_t *b = &buf[i];
        union {
            uint8_t u8[4];
            uint32_t u32;
        } v = {
            .u8 = { b[0], b[1], b[2], b[3] }
        };

        if (!s->is_dst) {
            s->regs[R_CRC0] += v.u32;
        }
        if (bswap) {
            /*
             * No point using bswap, we need to writeback
             * into a potentially unaligned pointer.
             */
            b[0] = v.u8[3];
            b[1] = v.u8[2];
            b[2] = v.u8[1];
            b[3] = v.u8[0];
        }
    }
}

static inline uint64_t dmach_addr(XlnxCSUDMA *s)
{
    uint64_t addr;

    addr = s->regs[R_ADDR];
    addr |= (uint64_t) s->regs[R_ADDR_MSB] << 32;
    return addr;
}

/* len is in bytes.  */
static void dmach_write(XlnxCSUDMA *s, uint8_t *buf, unsigned int len)
{
    uint64_t addr = dmach_addr(s);

    dmach_data_process(s, buf, len);
    if (dmach_burst_is_fixed(s)) {
        unsigned int i;

        for (i = 0; i < len; i += s->width) {
            unsigned int wlen = MIN(len - i, s->width);

            address_space_rw(s->dma_as, addr, s->attr, buf, wlen, true);
            buf += wlen;
        }
    } else {
        address_space_rw(s->dma_as, addr, s->attr, buf, len, true);
    }
}

/* len is in bytes.  */
static inline void dmach_read(XlnxCSUDMA *s, uint8_t *buf,
                              unsigned int len)
{
    uint64_t addr = dmach_addr(s);

    if (dmach_burst_is_fixed(s)) {
        unsigned int i;

        for (i = 0; i < len; i += s->width) {
            unsigned int rlen = MIN(len - i, s->width);

            address_space_rw(s->dma_as, addr, s->attr, buf + i, rlen, false);
        }
    } else {
        address_space_rw(s->dma_as, addr, s->attr, buf, len, false);
    }
    dmach_data_process(s, buf, len);
}

static void zynqmp_csu_dma_update_irq(XlnxCSUDMA *s)
{
    qemu_set_irq(s->irq, !!(s->regs[R_INT_STATUS] & ~s->regs[R_INT_MASK]));
}

static void zynqmp_csu_dma_reset(DeviceState *dev)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(dev);
    int i;

    for (i = 0; i < XLNX_CSU_DMA_R_MAX; i++) {
        register_reset(&s->regs_info[i]);
    }
}

static size_t zynqmp_csu_dma_stream_push(StreamSink *obj, uint8_t *buf,
                                          size_t len, bool eop)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(obj);
    uint32_t size = dmach_get_size(s);
    uint32_t btt = MIN(size, len);

    assert(s->is_dst);
    if (len && (dmach_is_paused(s) || btt == 0)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "csu-dma: DST channel dropping %zd b of data.\n", len);
        s->regs[R_INT_STATUS] |= R_INT_STATUS_WR_FULL_CMDQ_MASK;
        return len;
    }

    if (!btt) {
        return 0;
    }

    /* DMA transfer.  */
    dmach_write(s, buf, btt);
    dmach_advance(s, btt);
    zynqmp_csu_dma_update_irq(s);
    return btt;
}

static bool zynqmp_csu_dma_stream_can_push(StreamSink *obj,
                                            StreamCanPushNotifyFn notify,
                                            void *notify_opaque)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(obj);

    if (dmach_get_size(s) != 0) {
        return true;
    } else {
        s->notify = notify;
        s->notify_opaque = notify_opaque;
        return false;
    }
}

static void zynqmp_csu_dma_src_notify(void *opaque)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(opaque);
    unsigned char buf[4 * 1024];

    ptimer_transaction_begin(s->src_timer);
    /* Stop the backpreassure timer.  */
    ptimer_stop(s->src_timer);

    while (dmach_get_size(s) && !dmach_is_paused(s) &&
           stream_can_push(s->tx_dev, zynqmp_csu_dma_src_notify, s)) {
        uint32_t size = dmach_get_size(s);
        unsigned int plen = MIN(size, sizeof buf);
        bool eop = false;
        size_t ret;

        /* Did we fit it all?  */
        if (size == plen && dmach_get_eop(s)) {
            eop = true;
        }

        /* DMA transfer.  */
        dmach_read(s, buf, plen);
        ret = stream_push(s->tx_dev, buf, plen, eop);
        dmach_advance(s, ret);
    }

    if (dmach_timeout_enabled(s) && dmach_get_size(s)
        && !stream_can_push(s->tx_dev, zynqmp_csu_dma_src_notify, s)) {
        unsigned int timeout = ARRAY_FIELD_EX32(s->regs, CTRL, TIMEOUT_VAL);
        unsigned int div = extract32(s->regs[R_CTRL2], 4, 12) + 1;
        unsigned int freq = 400 * 1000 * 1000;

        freq /= div;
        ptimer_set_freq(s->src_timer, freq);
        ptimer_set_count(s->src_timer, timeout);
        ptimer_run(s->src_timer, 1);
    }

    ptimer_transaction_commit(s->src_timer);
    zynqmp_csu_dma_update_irq(s);
}

static void r_ctrl_post_write(RegisterInfo *reg, uint64_t val)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(reg->opaque);

    if (!s->is_dst) {
        if (!dmach_is_paused(s)) {
            zynqmp_csu_dma_src_notify(s);
        }
    } else {
        if (!dmach_is_paused(s) && s->notify) {
            s->notify(s->notify_opaque);
        }
    }
}

static uint64_t size_pre_write(RegisterInfo *reg, uint64_t val)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(reg->opaque);
    if (dmach_get_size(s) != 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "csu-dma: Starting DMA while already running.\n");
    }
    return val;
}

static void size_post_write(RegisterInfo *reg, uint64_t val)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(reg->opaque);

    s->regs[R_STATUS] |= R_STATUS_BUSY_MASK;
    /*
     * When starting the DMA channel with a zero length, it signals
     * done immediately.
     */
    if (dmach_get_size(s) == 0) {
        dmach_done(s);
        zynqmp_csu_dma_update_irq(s);
        return;
    }

    if (!s->is_dst) {
        zynqmp_csu_dma_src_notify(s);
    } else {
        if (s->notify) {
            s->notify(s->notify_opaque);
        }
    }
}

static uint64_t int_status_pre_write(RegisterInfo *reg, uint64_t val)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(reg->opaque);

    /* DMA counter decrements on interrupt clear */
    if (~val & s->regs[R_INT_STATUS] & R_INT_STATUS_DONE_MASK) {
        dmach_update_dma_cnt(s, -1);
    }

    return val;
}

static void int_status_post_write(RegisterInfo *reg, uint64_t val)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(reg->opaque);

    zynqmp_csu_dma_update_irq(s);
}

static uint64_t int_enable_pre_write(RegisterInfo *reg, uint64_t val)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(reg->opaque);
    uint32_t v32 = val;

    s->regs[R_INT_MASK] &= ~v32;
    zynqmp_csu_dma_update_irq(s);
    return 0;
}

static uint64_t int_disable_pre_write(RegisterInfo *reg, uint64_t val)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(reg->opaque);
    uint32_t v32 = val;

    s->regs[R_INT_MASK] |= v32;
    zynqmp_csu_dma_update_irq(s);
    return 0;
}

static void src_timeout_hit(void *opaque)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(opaque);

    /* Ignore if the timeout is masked.  */
    if (!dmach_timeout_enabled(s)) {
        return;
    }

    s->regs[R_INT_STATUS] |= R_INT_STATUS_TIMEOUT_STRM_MASK;
    zynqmp_csu_dma_update_irq(s);
}

static const RegisterAccessInfo *zynqmp_csu_dma_regs_info[] = {
#define DMACH_REGINFO(NAME, snd)                                              \
(const RegisterAccessInfo []) {                                               \
    {   .name = #NAME "_ADDR",          .addr = A_ADDR,                       \
    },{ .name = #NAME "_SIZE",          .addr = A_SIZE,                       \
        .pre_write = size_pre_write,                                          \
        .post_write = size_post_write                                         \
    },{ .name = #NAME "_STATUS",        .addr = A_STATUS,                     \
        .w1c = R_STATUS_DONE_CNT_MASK                                         \
    },{ .name = #NAME "_CTRL",          .addr = A_CTRL,                       \
        .ro = snd ? CTRL_RSVD : 0,                                            \
        .reset = (snd ? 0 : 0x40 << R_CTRL_FIFO_THRESH_SHIFT) |               \
                     R_CTRL_TIMEOUT_VAL_MASK |                                \
                     0x80 << R_CTRL_FIFO_THRESH_SHIFT,                        \
        .post_write = r_ctrl_post_write                                       \
    },{ .name =  #NAME "_CRC0",          .addr = A_CRC0,                      \
    },{ .name =  #NAME "_INT_STATUS",   .addr = A_INT_STATUS,                 \
        .w1c = ~0,                                                            \
        .pre_write = int_status_pre_write,                                    \
        .post_write = int_status_post_write                                   \
    },{ .name =  #NAME "_INT_ENABLE",   .addr = A_INT_ENABLE,                 \
        .pre_write = int_enable_pre_write                                     \
    },{ .name =  #NAME "_INT_DISABLE",  .addr = A_INT_DISABLE,                \
        .pre_write = int_disable_pre_write                                    \
    },{ .name =  #NAME "_INT_MASK",     .addr = A_INT_MASK,                   \
        .ro = ~0,                                                             \
        .reset = snd ? INT_ALL_SRC : INT_ALL_DST,                             \
    },{ .name =  #NAME "_CTRL2",        .addr = A_CTRL2,                      \
        .ro = CTRL2_RSVD,                                                     \
        .reset = 0x8 << R_CTRL2_MAX_OUTS_CMDS_SHIFT |                         \
                     0xFFF << R_CTRL2_TIMEOUT_PRE_SHIFT | 0x081b0000,         \
    },{ .name =  #NAME "_ADDR_MSB",     .addr = A_ADDR_MSB,                   \
    }                                                                         \
}
    DMACH_REGINFO(DMA_SRC, true),
    DMACH_REGINFO(DMA_DST, false)
};

static const MemoryRegionOps zynqmp_csu_dma_ops = {
    .read = register_read_memory,
    .write = register_write_memory,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    }
};

static void zynqmp_csu_dma_realize(DeviceState *dev, Error **errp)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    RegisterInfoArray *reg_array;

    reg_array =
        register_init_block32(dev, zynqmp_csu_dma_regs_info[!!s->is_dst],
                              XLNX_CSU_DMA_R_MAX,
                              s->regs_info, s->regs,
                              &zynqmp_csu_dma_ops,
                              XLNX_CSU_DMA_ERR_DEBUG,
                              XLNX_CSU_DMA_R_MAX * 4);
    memory_region_add_subregion(&s->iomem,
                                0x0,
                                &reg_array->mem);
    sysbus_init_mmio(sbd, &s->iomem);

    if (!s->is_dst && !s->tx_dev) {
        error_setg(errp, "zynqmp.csu-dma: Stream not connected");
        return;
    }
    s->src_timer = ptimer_init(src_timeout_hit, s, PTIMER_POLICY_DEFAULT);

    if (s->dma_mr) {
        s->dma_as = g_malloc0(sizeof(AddressSpace));
        address_space_init(s->dma_as, s->dma_mr, NULL);
    } else {
        s->dma_as = &address_space_memory;
    }

    s->attr = MEMTXATTRS_UNSPECIFIED;

    /*
     * If byte alignment is enabled last word control bit is moved
     * to bit 29.
     */
    s->r_size_last_word_mask = 1 << (s->byte_align ? 29 : 0);
}

static void zynqmp_csu_dma_init(Object *obj)
{
    XlnxCSUDMA *s = XLNX_CSU_DMA(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init(&s->iomem, obj, "zynqmp.csu-dma",
                       XLNX_CSU_DMA_R_MAX * 4);

    sysbus_init_irq(sbd, &s->irq);

    object_property_add_link(obj, "stream-connected-dma", TYPE_STREAM_SINK,
                             (Object **)&s->tx_dev,
                             qdev_prop_allow_set_link_before_realize,
                             OBJ_PROP_LINK_STRONG);
    object_property_add_link(obj, "dma", TYPE_MEMORY_REGION,
                             (Object **)&s->dma_mr,
                             qdev_prop_allow_set_link_before_realize,
                             OBJ_PROP_LINK_STRONG);
}

static const VMStateDescription vmstate_zynqmp_csu_dma = {
    .name = "zynqmp_csu_dma",
    .version_id = 2,
    .minimum_version_id = 2,
    .minimum_version_id_old = 2,
    .fields = (VMStateField[]) {
        VMSTATE_PTIMER(src_timer, XlnxCSUDMA),
        VMSTATE_UINT32_ARRAY(regs, XlnxCSUDMA, XLNX_CSU_DMA_R_MAX),
        VMSTATE_END_OF_LIST(),
    }
};

static Property zynqmp_csu_dma_properties[] = {
    DEFINE_PROP_BOOL("is-dst", XlnxCSUDMA, is_dst, true),
    DEFINE_PROP_UINT16("dma-width", XlnxCSUDMA, width, 4),
    DEFINE_PROP_BOOL("byte-align", XlnxCSUDMA, byte_align, false),
    DEFINE_PROP_END_OF_LIST(),
};

static void zynqmp_csu_dma_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    StreamSinkClass *ssc = STREAM_SINK_CLASS(klass);

    dc->reset = zynqmp_csu_dma_reset;
    dc->realize = zynqmp_csu_dma_realize;
    dc->vmsd = &vmstate_zynqmp_csu_dma;
    device_class_set_props(dc, zynqmp_csu_dma_properties);

    ssc->push = zynqmp_csu_dma_stream_push;
    ssc->can_push = zynqmp_csu_dma_stream_can_push;
}

static const TypeInfo zynqmp_csu_dma_info = {
    .name          = TYPE_XLNX_CSU_DMA,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(XlnxCSUDMA),
    .class_init    = zynqmp_csu_dma_class_init,
    .instance_init = zynqmp_csu_dma_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_STREAM_SINK },
        { }
    }
};

static void zynqmp_csu_dma_register_types(void)
{
    type_register_static(&zynqmp_csu_dma_info);
}

type_init(zynqmp_csu_dma_register_types)
