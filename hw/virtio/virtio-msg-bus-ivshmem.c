/*
 * VirtIO MSG bus over IVSHMEM devices.
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

#include "hw/virtio/virtio-msg-bus-ivshmem.h"

#define IVD_BAR0_INTR_MASK    0x0
#define IVD_BAR0_INTR_STATUS  0x4
#define IVD_BAR0_IV_POSITION  0x8
#define IVD_BAR0_DOORBELL     0xc

static inline void ivshmem_write32(void *p, uint32_t val) {
        intptr_t addr = (intptr_t) p;

        assert((addr % sizeof val) == 0);
        *(volatile uint32_t *)p = val;
}

static inline uint32_t ivshmem_read32(void *p) {
        intptr_t addr = (intptr_t) p;
        uint32_t val;

        assert((addr % sizeof val) == 0);
        val = *(volatile uint32_t *)p;
        return val;
}

static void virtio_msg_bus_ivshmem_send_notify(VirtIOMSGBusIVSHMEM *s)
{
    ivshmem_write32(s->msg.doorbell + IVD_BAR0_DOORBELL,
                    s->cfg.remote_vmid << 16);
}

static void virtio_msg_bus_ivshmem_process(VirtIOMSGBusDevice *bd) {
    VirtIOMSGBusIVSHMEM *s = VIRTIO_MSG_BUS_IVSHMEM(bd);
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
            assert(bd->peer->receive);
            bd->peer->receive(bd, &msg);
        }
    } while (r);
}

static void ivshmem_intx_interrupt(void *opaque)
{
    VirtIOMSGBusIVSHMEM *s = VIRTIO_MSG_BUS_IVSHMEM(opaque);

    if (!event_notifier_test_and_clear(&s->notifier)) {
        return;
    }

    /* ACK the interrupt.  */
    ivshmem_read32(s->msg.doorbell + IVD_BAR0_INTR_STATUS);
    virtio_msg_bus_ivshmem_process(opaque);
    qemu_vfio_pci_unmask_irq(s->msg.dev, VFIO_PCI_INTX_IRQ_INDEX);
}

static int virtio_msg_bus_ivshmem_send(VirtIOMSGBusDevice *bd, VirtIOMSG *msg_req,
                                          VirtIOMSG *msg_resp)
{
    VirtIOMSGBusIVSHMEM *s = VIRTIO_MSG_BUS_IVSHMEM(bd);
    spsc_queue *q_tx;
    spsc_queue *q_rx;
    bool sent;
    int i;

    q_tx = bd->peer->is_driver ? s->shm_queues.driver : s->shm_queues.device;
    q_rx = bd->peer->is_driver ? s->shm_queues.device : s->shm_queues.driver;

    do {
        sent = spsc_send(q_tx, msg_req, sizeof *msg_req);
    } while (!sent);

    virtio_msg_bus_ivshmem_send_notify(s);

    if (msg_resp) {
        bool r = false;

        for (i = 0; !r && i < 100; i++){
            r = spsc_recv(q_rx, msg_resp, sizeof *msg_resp);

            if (!r) {
                /* No message available, keep going with some delay.  */
                usleep(i);
            }

            if (r && msg_resp->type != msg_req->type) {
                /*
                 * We've got a message but it's not the response we're
                 * expecting. Forward it to the receiver logic.
                 *
                 * This should only happen for notifications.
                 */
                assert(bd->peer->receive);
                bd->peer->receive(bd, msg_resp);
                /* Keep going.  */
                r = 0;
            }
        }
        if (!r) {
            printf("ERROR: %s: timed out!!\n", __func__);
            abort();
        }
    }

    return VIRTIO_MSG_NO_ERROR;
}

static void virtio_msg_bus_ivshmem_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusIVSHMEM *s = VIRTIO_MSG_BUS_IVSHMEM(dev);
    int ret;

    if (s->cfg.msg_dev == NULL) {
        error_setg(errp, "property 'msg-dev' not specified.");
        return;
    }

    if (s->cfg.mem_dev == NULL) {
        error_setg(errp, "property 'mem-dev' not specified.");
        return;
    }

    if (s->cfg.mem_dev == 0) {
        error_setg(errp, "property 'mem-size' not specified.");
        return;
    }

    ret = event_notifier_init(&s->notifier, 0);
    if (ret) {
        error_setg(errp, "Failed to init event notifier");
        return;
    }

    s->msg.dev = qemu_vfio_open_pci(s->cfg.msg_dev, &error_fatal);
    s->mem.dev = qemu_vfio_open_pci(s->cfg.mem_dev, &error_fatal);

    s->msg.doorbell = qemu_vfio_pci_map_bar(s->msg.dev, 0, 0, 4 * KiB,
                                            PROT_READ | PROT_WRITE,
                                            &error_fatal);

    s->msg.driver = qemu_vfio_pci_map_bar(s->msg.dev, 2, 0, 4 * KiB,
                                          PROT_READ | PROT_WRITE,
                                          &error_fatal);
    s->msg.device = qemu_vfio_pci_map_bar(s->msg.dev, 2, 4 * KiB, 4 * KiB,
                                          PROT_READ | PROT_WRITE,
                                          &error_fatal);

    s->mem.mem = qemu_vfio_pci_map_bar(s->mem.dev, 2, 0, s->cfg.mem_size,
                                       PROT_READ | PROT_WRITE,
                                       &error_fatal);

    qemu_vfio_pci_init_irq(s->msg.dev, &s->notifier,
                           VFIO_PCI_INTX_IRQ_INDEX, &error_fatal);

    qemu_set_fd_handler(event_notifier_get_fd(&s->notifier),
                        ivshmem_intx_interrupt, NULL, s);

    s->shm_queues.driver = spsc_open_mem("queue-driver",
                                         spsc_capacity(4 * KiB), s->msg.driver);
    s->shm_queues.device = spsc_open_mem("queue-device",
                                         spsc_capacity(4 * KiB), s->msg.device);

    /* Unmask interrupts.  */
    ivshmem_write32(s->msg.doorbell + IVD_BAR0_INTR_MASK, 0xffffffff);
}

static Property virtio_msg_bus_ivshmem_props[] = {
    DEFINE_PROP_STRING("msg-dev", VirtIOMSGBusIVSHMEM, cfg.msg_dev),
    DEFINE_PROP_STRING("mem-dev", VirtIOMSGBusIVSHMEM, cfg.mem_dev),
    DEFINE_PROP_SIZE("mem-size", VirtIOMSGBusIVSHMEM, cfg.mem_size, 0),
    DEFINE_PROP_UINT32("remote-vmid", VirtIOMSGBusIVSHMEM, cfg.remote_vmid, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_bus_ivshmem_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    bdc->process = virtio_msg_bus_ivshmem_process;
    bdc->send = virtio_msg_bus_ivshmem_send;

    dc->realize = virtio_msg_bus_ivshmem_realize;
    device_class_set_props(dc, virtio_msg_bus_ivshmem_props);
}

static const TypeInfo virtio_msg_bus_ivshmem_info = {
    .name = TYPE_VIRTIO_MSG_BUS_IVSHMEM,
    .parent = TYPE_VIRTIO_MSG_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGBusIVSHMEM),
    .class_init = virtio_msg_bus_ivshmem_class_init,
};

static void virtio_msg_bus_ivshmem_register_types(void)
{
    type_register_static(&virtio_msg_bus_ivshmem_info);
}

type_init(virtio_msg_bus_ivshmem_register_types)
