/*
 * VirtIO MSG bus for sapphire board with an attached vek280.
 * This uses switchboards underlying queue's (mmap) to transfer message.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <linux/vfio.h>
#include "qemu/units.h"
#include "qemu/event_notifier.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"

#include "hw/virtio/virtio-msg-bus-sapphire.h"
#include "hw/virtio/pagemap.h"

#ifdef CONFIG_XEN
#include "hw/xen/xen_native.h"
#include "sysemu/xen.h"
#endif

#include <sys/mman.h>

#define PTIMER_POLICY                       \
    (PTIMER_POLICY_WRAP_AFTER_ONE_PERIOD |  \
     PTIMER_POLICY_CONTINUOUS_TRIGGER    |  \
     PTIMER_POLICY_NO_IMMEDIATE_TRIGGER  |  \
     PTIMER_POLICY_NO_IMMEDIATE_RELOAD   |  \
     PTIMER_POLICY_NO_COUNTER_ROUND_DOWN)

#define BAR2_DOORBELL  0x0

static inline void sapphire_write32(void *p, uint32_t val) {
        intptr_t addr = (intptr_t) p;

        assert((addr % sizeof val) == 0);
        *(volatile uint32_t *)p = val;
}

static inline uint32_t sapphire_read32(void *p) {
        intptr_t addr = (intptr_t) p;
        uint32_t val;

        assert((addr % sizeof val) == 0);
        val = *(volatile uint32_t *)p;
        return val;
}

static void virtio_msg_bus_sapphire_send_notify(VirtIOMSGBusSapphire *s)
{
    /* Issue a pulse.  */
    sapphire_write32(s->msg.doorbell + BAR2_DOORBELL,  1);
    usleep(10);
    sapphire_write32(s->msg.doorbell + BAR2_DOORBELL,  0);
    usleep(10);
}

static void virtio_msg_bus_sapphire_process(VirtIOMSGBusDevice *bd) {
    VirtIOMSGBusSapphire *s = VIRTIO_MSG_BUS_SAPPHIRE(bd);
    spsc_queue *q;
    VirtIOMSG msg;
    bool r;

    /*
     * We process the opposite queue, i.e, a driver will want to receive
     * messages on the backend queue (and send messages on the driver queue).
     */
    q = bd->peer->is_driver ? s->shm_queues.device : s->shm_queues.driver;
    do {
        r = spsc_recv(q, &msg, sizeof msg);
        if (r) {
            virtio_msg_bus_receive(bd, &msg);
        }
    } while (r);
}

static void sapphire_intx_interrupt(void *opaque)
{
    VirtIOMSGBusSapphire *s = VIRTIO_MSG_BUS_SAPPHIRE(opaque);
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(opaque);

    if (!event_notifier_test_and_clear(&s->notifier)) {
        return;
    }

    /* ACK the interrupt.  */
    virtio_msg_bus_process(bd);
    qemu_vfio_pci_unmask_irq(s->msg.dev, VFIO_PCI_INTX_IRQ_INDEX);
}

static void sapphire_timer_tick(void *opaque)
{
    VirtIOMSGBusSapphire *s = VIRTIO_MSG_BUS_SAPPHIRE(opaque);
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(opaque);

    virtio_msg_bus_process(bd);
    timer_mod_ns(&s->timer,
                 qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + 1000 * 1000);
}

static int virtio_msg_bus_sapphire_send(VirtIOMSGBusDevice *bd, VirtIOMSG *msg_req,
                                          VirtIOMSG *msg_resp)
{
    VirtIOMSGBusSapphire *s = VIRTIO_MSG_BUS_SAPPHIRE(bd);
    spsc_queue *q_tx;
    spsc_queue *q_rx;
    bool sent;
    int i;

    q_tx = bd->peer->is_driver ? s->shm_queues.driver : s->shm_queues.device;
    q_rx = bd->peer->is_driver ? s->shm_queues.device : s->shm_queues.driver;

    virtio_msg_bus_sapphire_send_notify(s);
    do {
        sent = spsc_send(q_tx, msg_req, sizeof *msg_req);
    } while (!sent);

    virtio_msg_bus_sapphire_send_notify(s);

    if (msg_resp) {
        bool r = false;

        for (i = 0; !r && i < 1024 * 10000; i++){
            r = spsc_recv(q_rx, msg_resp, sizeof *msg_resp);

            if (!r) {
                /* No message available, keep going with some delay.  */
                if (i > 128) {
                    if (!s->shm_queues.flowing) {
                        virtio_msg_bus_sapphire_send_notify(s);
                    }
                    usleep(i / 128);
                }
            }

            if (r && !virtio_msg_is_resp(msg_req, msg_resp)) {
                /* Let the virtio-msg stack handle this.  */
                virtio_msg_bus_ooo_receive(bd, msg_req, msg_resp);
                /* Keep going.  */
                r = 0;
            }
        }
        if (!r) {
            /*
             * FIXME: Devices/backends need to be able to recover from
             * errors like this. Think a QEMU instance serving multiple
             * guests via multiple virtio-msg devs. Can't allow one of
             * them to bring down the entire QEMU.
             */
            printf("ERROR: %s: timed out!!\n", __func__);
            abort();
        }

        s->shm_queues.flowing = true;

        /*
         * We've got our response. Unpack it and return back to the caller.
         */
        virtio_msg_unpack(msg_resp);
    }

    return VIRTIO_MSG_NO_ERROR;
}

static void virtio_msg_bus_sapphire_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusSapphire *s = VIRTIO_MSG_BUS_SAPPHIRE(dev);
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(dev);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);
    uint64_t iova;
    int ret;

    bdc->parent_realize(dev, errp);
    if (*errp) {
        return;
    }

    if (s->cfg.dev == NULL) {
        error_setg(errp, "property 'dev' not specified.");
        return;
    }

    ret = event_notifier_init(&s->notifier, 0);
    if (ret) {
        error_setg(errp, "Failed to init event notifier");
        return;
    }

    if (s->cfg.iommu) {
        if (!strcmp(s->cfg.iommu, "xen-gfn2mfn")) {
            bd->iommu_translate = virtio_msg_bus_xen_gfn2mfn_translate;
        } else if (!strcmp(s->cfg.iommu, "xen-virt2gfn")) {
            bd->iommu_translate = virtio_msg_bus_xen_virt2gfn_translate;
        } else if (!strcmp(s->cfg.iommu, "linux-proc-pagemap")) {
            bd->iommu_translate = virtio_msg_bus_pagemap_translate;
        }
    }

    s->msg.dev = qemu_vfio_open_pci(s->cfg.dev, &error_fatal);

    s->msg.doorbell = qemu_vfio_pci_map_bar(s->msg.dev, 2, 0, 4 * KiB,
                                            PROT_READ | PROT_WRITE,
                                            &error_fatal);

    s->msg.cfg_bram = qemu_vfio_pci_map_bar(s->msg.dev, 1, 0x4000, 4 * KiB,
                                            PROT_READ | PROT_WRITE,
                                            &error_fatal);

    if (0) {
        qemu_vfio_pci_init_irq(s->msg.dev, &s->notifier,
                VFIO_PCI_INTX_IRQ_INDEX, &error_fatal);
        qemu_set_fd_handler(event_notifier_get_fd(&s->notifier),
                sapphire_intx_interrupt, NULL, s);
    }

#if 0
    memory_region_init_ram(&s->shm_queues.mr, NULL, "spsc-ram",
                           4 * 2 * 1024, &error_fatal);

    s->msg.driver = memory_region_get_ram_ptr(&s->shm_queues.mr);
    s->msg.device = s->msg.driver + 4 * 1024;
#else
    s->msg.driver = mmap(NULL, 8 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
    s->msg.device = s->msg.driver + 4 * 1024;
#endif

    if (s->cfg.reset_queues) {
        memset(s->msg.driver, 0, 4 * KiB);
        memset(s->msg.device, 0, 4 * KiB);
    }

    s->shm_queues.driver = spsc_open_mem("queue-driver",
                                         spsc_capacity(4 * KiB), s->msg.driver);
    s->shm_queues.device = spsc_open_mem("queue-device",
                                         spsc_capacity(4 * KiB), s->msg.device);

    printf("map spsc queues\n");
    if (1) {
        iova = pagemap_virt_to_phys(s->msg.driver);
    } else {
        qemu_vfio_dma_map(s->msg.dev, s->msg.driver, 8 * 1024, false,
                &iova, &error_warn);
    }
    printf("spsc va=%p iova=%lx\n", s->msg.driver, iova);
    s->msg.cfg_bram[1] = iova;
    s->msg.cfg_bram[2] = iova >> 32;
    smp_wmb();
    s->msg.cfg_bram[0] = 1;
    smp_wmb();

    timer_init_ns(&s->timer, QEMU_CLOCK_REALTIME, sapphire_timer_tick, s);
    timer_mod_ns(&s->timer,
                 qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + 1000 * 1000);

    mlockall(MCL_CURRENT | MCL_FUTURE);
}

static Property virtio_msg_bus_sapphire_props[] = {
    DEFINE_PROP_STRING("dev", VirtIOMSGBusSapphire, cfg.dev),
    DEFINE_PROP_BOOL("reset-queues", VirtIOMSGBusSapphire,
                     cfg.reset_queues, false),
    DEFINE_PROP_STRING("iommu", VirtIOMSGBusSapphire, cfg.iommu),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_bus_sapphire_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    bdc->process = virtio_msg_bus_sapphire_process;
    bdc->send = virtio_msg_bus_sapphire_send;

    device_class_set_parent_realize(dc, virtio_msg_bus_sapphire_realize,
                                    &bdc->parent_realize);
    device_class_set_props(dc, virtio_msg_bus_sapphire_props);
}

static const TypeInfo virtio_msg_bus_sapphire_info = {
    .name = TYPE_VIRTIO_MSG_BUS_SAPPHIRE,
    .parent = TYPE_VIRTIO_MSG_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGBusSapphire),
    .class_init = virtio_msg_bus_sapphire_class_init,
};

static void virtio_msg_bus_sapphire_register_types(void)
{
    type_register_static(&virtio_msg_bus_sapphire_info);
}

type_init(virtio_msg_bus_sapphire_register_types)
