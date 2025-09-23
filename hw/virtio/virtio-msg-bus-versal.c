/*
 * Virtio-msg bus for Xilinx versal designs.
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
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

#include "hw/virtio/virtio-msg-bus-versal.h"

#define VEK280_INTR_STATUS    0x0

static inline void reg_write32(void *p, uint32_t val) {
        intptr_t addr = (intptr_t) p;

        assert((addr % sizeof val) == 0);
        *(volatile uint32_t *)p = val;
}

static inline uint32_t reg_read32(void *p) {
        intptr_t addr = (intptr_t) p;
        uint32_t val;

        assert((addr % sizeof val) == 0);
        val = *(volatile uint32_t *)p;
        return val;
}

static void virtio_msg_bus_versal_send_notify(VirtIOMSGBusVersal *s)
{
    reg_write32(s->msg.doorbell, 0x0);
    reg_write32(s->msg.doorbell, 0x1);
}

static AddressSpace *virtio_msg_bus_versal_get_remote_as(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusVersal *s = VIRTIO_MSG_BUS_VERSAL(bd);

    return &s->as;
}

static void virtio_msg_bus_versal_process(VirtIOMSGBusDevice *bd) {
    VirtIOMSGBusVersal *s = VIRTIO_MSG_BUS_VERSAL(bd);
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

static void virtio_msg_bus_versal_setup_queues(VirtIOMSGBusVersal *s)
{
    if (s->msg.cfg_bram[0] == 0) {
        return;
    }

    printf("cfg-bram: %x %x %x\n",
            s->msg.cfg_bram[0],
            s->msg.cfg_bram[1],
            s->msg.cfg_bram[2]);
    smp_rmb();
    s->cfg.spsc_base = s->msg.cfg_bram[2];
    s->cfg.spsc_base <<= 32;
    s->cfg.spsc_base |= s->msg.cfg_bram[1];
    smp_mb();
    s->msg.cfg_bram[0] = 0;

    printf("Found queue at %lx\n", s->cfg.spsc_base);

    s->msg.driver = s->msg.host + s->cfg.spsc_base;
    s->msg.device = s->msg.driver + 4 * 1024;

    virtio_msg_bus_versal_send_notify(s);

    s->shm_queues.driver = spsc_open_mem("queue-driver",
                                         spsc_capacity(4 * KiB), s->msg.driver);
    s->shm_queues.device = spsc_open_mem("queue-device",
                                         spsc_capacity(4 * KiB), s->msg.device);
}

static void versal_mask_interrupt(VirtIOMSGBusVersal *s, bool mask)
{
    uint32_t info = !mask;
    ssize_t nb;

    assert(info == 1);
    nb = write(s->msg.fd, &info, sizeof(info));
    if (nb != (ssize_t) sizeof(info)) {
        perror("versal_unmask_interrupt: write");
    }
}

static void versal_interrupt(void *opaque)
{
    VirtIOMSGBusVersal *s = VIRTIO_MSG_BUS_VERSAL(opaque);
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(opaque);
    uint32_t r;

    do {
        /* ACK the interrupt.  */
        reg_write32(s->msg.irq, 0x0);
        smp_mb();

        if (s->shm_queues.driver) {
            virtio_msg_bus_process(bd);
        } else {
            virtio_msg_bus_versal_setup_queues(s);
        }

        r = reg_read32(s->msg.irq);
    } while (r & 1);
    versal_mask_interrupt(s, false);
}

static int virtio_msg_bus_versal_send(VirtIOMSGBusDevice *bd, VirtIOMSG *msg_req,
                                          VirtIOMSG *msg_resp)
{
    VirtIOMSGBusVersal *s = VIRTIO_MSG_BUS_VERSAL(bd);
    spsc_queue *q_tx;
    spsc_queue *q_rx;
    bool sent;
    int i;

    q_tx = bd->peer->is_driver ? s->shm_queues.driver : s->shm_queues.device;
    q_rx = bd->peer->is_driver ? s->shm_queues.device : s->shm_queues.driver;

    do {
        sent = spsc_send(q_tx, msg_req, sizeof *msg_req);
    } while (!sent);

    virtio_msg_bus_versal_send_notify(s);

    if (msg_resp) {
        bool r = false;

        for (i = 0; !r && i < 1024; i++){
            r = spsc_recv(q_rx, msg_resp, sizeof *msg_resp);

            if (!r) {
                /* No message available, keep going with some delay.  */
                if (i > 128) {
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

        /*
         * We've got our response. Unpack it and return back to the caller.
         */
        virtio_msg_unpack(msg_resp);
    }

    return VIRTIO_MSG_NO_ERROR;
}

static void virtio_msg_bus_versal_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusVersal *s = VIRTIO_MSG_BUS_VERSAL(dev);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);
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

    s->msg.fd = open(s->cfg.dev, O_RDWR);
    s->msg.fd_devmem = open("/dev/mem", O_RDWR);

    qemu_set_fd_handler(s->msg.fd, versal_interrupt, NULL, s);

    if (s->cfg.reset_queues) {
        memset(s->msg.driver, 0, 4 * KiB);
        memset(s->msg.device, 0, 4 * KiB);
    }

    memory_region_init_ram_from_fd(&s->mr_host, OBJECT(s), "mr-host",
                                     s->cfg.mem_size,
                                     RAM_SHARED | RAM_NORESERVE,
                                     s->msg.fd,
                                     0,
                                     &error_abort);

    memory_region_init_alias(&s->mr_host_ram, OBJECT(s), "mr-host-ram",
                             &s->mr_host,
                             s->cfg.mem_offset, s->cfg.mem_size);

    memory_region_init_alias(&s->mr_host_ram_alias, OBJECT(s),
                             "mr-host-ram-alias",
                             &s->mr_host,
                             s->cfg.mem_offset, s->cfg.mem_size);

    address_space_init(&s->as, MEMORY_REGION(&s->mr_host_ram), "msg-bus-as");
    memory_region_add_subregion(get_system_memory(), 0, &s->mr_host_ram_alias);

    s->msg.host = memory_region_get_ram_ptr(&s->mr_host);

    s->msg.doorbell = mmap(0, 4 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED,
                           s->msg.fd_devmem, s->cfg.doorbell_base);
    assert(s->msg.doorbell != MAP_FAILED);

    s->msg.cfg_bram = mmap(0, 8 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED,
                           s->msg.fd_devmem, s->cfg.bram_base);
    assert(s->msg.cfg_bram != MAP_FAILED);

    s->msg.irq = mmap(0, 4 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED,
                           s->msg.fd_devmem, s->cfg.irq_base);
    assert(s->msg.irq != MAP_FAILED);

    /* Lower doorbell reg.  */
    reg_write32(s->msg.doorbell, 0x0);
}

static Property virtio_msg_bus_versal_props[] = {
    DEFINE_PROP_STRING("dev", VirtIOMSGBusVersal, cfg.dev),
    DEFINE_PROP_UINT64("spsc-base", VirtIOMSGBusVersal, cfg.spsc_base,
                       UINT64_MAX),
    DEFINE_PROP_UINT64("doorbell-base", VirtIOMSGBusVersal, cfg.doorbell_base,
                       0x20180000000ULL),
    DEFINE_PROP_UINT64("bram-base", VirtIOMSGBusVersal, cfg.bram_base,
                       0x020100004000ULL),
    DEFINE_PROP_UINT64("irq-base", VirtIOMSGBusVersal, cfg.irq_base,
                       0x020100050000ULL),
    DEFINE_PROP_UINT64("mem-offset", VirtIOMSGBusVersal, cfg.mem_offset, 0),
    DEFINE_PROP_UINT64("mem-size", VirtIOMSGBusVersal, cfg.mem_size,
                       0x860000000ULL),
    DEFINE_PROP_BOOL("reset-queues", VirtIOMSGBusVersal,
                     cfg.reset_queues, false),
    DEFINE_PROP_STRING("iommu", VirtIOMSGBusVersal, cfg.iommu),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_bus_versal_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    bdc->process = virtio_msg_bus_versal_process;
    bdc->send = virtio_msg_bus_versal_send;
    bdc->get_remote_as = virtio_msg_bus_versal_get_remote_as;

    device_class_set_parent_realize(dc, virtio_msg_bus_versal_realize,
                                    &bdc->parent_realize);
    device_class_set_props(dc, virtio_msg_bus_versal_props);
}

static const TypeInfo virtio_msg_bus_versal_info = {
    .name = TYPE_VIRTIO_MSG_BUS_VERSAL,
    .parent = TYPE_VIRTIO_MSG_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGBusVersal),
    .class_init = virtio_msg_bus_versal_class_init,
};

static void virtio_msg_bus_versal_register_types(void)
{
    type_register_static(&virtio_msg_bus_versal_info);
}

type_init(virtio_msg_bus_versal_register_types)
