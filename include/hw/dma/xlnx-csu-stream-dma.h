/*
 * QEMU model of the ZynqMP generic DMA
 *
 * Copyright (c) 2013 Xilinx Inc
 *
 * Written by Edgar E. Iglesias <edgar.iglesias@xilinx.com>
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

#ifndef XLNX_CSU_STREAM_DMA_H
#define XLNX_CSU_STREAM_DMA_H

#include "hw/sysbus.h"
#include "hw/register.h"
#include "sysemu/dma.h"
#include "qom/object.h"

#define TYPE_XLNX_CSU_DMA "xlnx.csu-dma"

#define XLNX_CSU_DMA(obj) \
     OBJECT_CHECK(XlnxCSUDMA, (obj), TYPE_XLNX_CSU_DMA)

#define XLNX_CSU_DMA_R_MAX (0x2c / 4)

typedef struct XlnxCSUDMA {
    SysBusDevice busdev;
    MemoryRegion iomem;
    MemTxAttrs attr;
    MemoryRegion *dma_mr;
    AddressSpace *dma_as;
    qemu_irq irq;
    StreamSink *tx_dev;  /* Used as generic StreamSink */
    ptimer_state *src_timer;

    bool is_dst;
    bool byte_align;
    uint16_t width;
    uint32_t r_size_last_word_mask;

    StreamCanPushNotifyFn notify;
    void *notify_opaque;

    uint32_t regs[XLNX_CSU_DMA_R_MAX];
    RegisterInfo regs_info[XLNX_CSU_DMA_R_MAX];
} XlnxCSUDMA;

#endif /* XLNX_CSU_STREAM_DMA_H */
