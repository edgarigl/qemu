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

static AddressSpace *virtio_msg_bus_ivshmem_get_remote_as(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusIVSHMEM *s = VIRTIO_MSG_BUS_IVSHMEM(bd);

    if (!s->cfg.memdev) {
        return NULL;
    }
    return &s->as;
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
            virtio_msg_bus_receive(bd, &msg);
        }
    } while (r);
}

static void ivshmem_intx_interrupt(void *opaque)
{
    VirtIOMSGBusIVSHMEM *s = VIRTIO_MSG_BUS_IVSHMEM(opaque);
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(opaque);

    if (!event_notifier_test_and_clear(&s->notifier)) {
        return;
    }

    /* ACK the interrupt.  */
    ivshmem_read32(s->msg.doorbell + IVD_BAR0_INTR_STATUS);
    virtio_msg_bus_process(bd);
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

static void virtio_msg_bus_ivshmem_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusIVSHMEM *s = VIRTIO_MSG_BUS_IVSHMEM(dev);
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(dev);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);
    uint64_t mem_size;
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
            bd->iommu_translate = virtio_msg_bus_xen_translate;
        } else if (!strcmp(s->cfg.iommu, "pagemap")) {
            bd->iommu_translate = virtio_msg_bus_pagemap_translate;
        }
    }

    s->msg.dev = qemu_vfio_open_pci(s->cfg.dev, &error_fatal);

    s->msg.doorbell = qemu_vfio_pci_map_bar(s->msg.dev, 0, 0, 4 * KiB,
                                            PROT_READ | PROT_WRITE,
                                            &error_fatal);

    s->msg.driver = qemu_vfio_pci_map_bar(s->msg.dev, 2, 0, 4 * KiB,
                                          PROT_READ | PROT_WRITE,
                                          &error_fatal);
    s->msg.device = qemu_vfio_pci_map_bar(s->msg.dev, 2, 4 * KiB, 4 * KiB,
                                          PROT_READ | PROT_WRITE,
                                          &error_fatal);

    qemu_vfio_pci_init_irq(s->msg.dev, &s->notifier,
                           VFIO_PCI_INTX_IRQ_INDEX, &error_fatal);

    qemu_set_fd_handler(event_notifier_get_fd(&s->notifier),
                        ivshmem_intx_interrupt, NULL, s);

    if (s->cfg.reset_queues) {
        memset(s->msg.driver, 0, 4 * KiB);
        memset(s->msg.device, 0, 4 * KiB);
    }

    s->shm_queues.driver = spsc_open_mem("queue-driver",
                                         spsc_capacity(4 * KiB), s->msg.driver);
    s->shm_queues.device = spsc_open_mem("queue-device",
                                         spsc_capacity(4 * KiB), s->msg.device);

    /* Unmask interrupts.  */
    ivshmem_write32(s->msg.doorbell + IVD_BAR0_INTR_MASK, 0xffffffff);

    if (s->cfg.memdev == NULL) {
        /* No memory mappings needed.  */
        return;
    }

    s->mr_memdev = host_memory_backend_get_memory(s->cfg.memdev);
    memory_region_init(&s->mr, OBJECT(s), "mr", UINT64_MAX);

    mem_size = memory_region_size(s->mr_memdev);
    if (s->cfg.mem_hole > 0) {
        uint64_t lowmem_end = s->cfg.mem_offset + s->cfg.mem_low_size;
        uint64_t highmem_start = lowmem_end + s->cfg.mem_hole;

        memory_region_init_alias(&s->mr_lowmem, OBJECT(s), "lowmem",
                                 s->mr_memdev, 0, s->cfg.mem_low_size);
        memory_region_init_alias(&s->mr_highmem, OBJECT(s), "highmem",
                                 s->mr_memdev, s->cfg.mem_low_size,
                                 mem_size - s->cfg.mem_low_size);

        memory_region_add_subregion(&s->mr, s->cfg.mem_offset, &s->mr_lowmem);
        memory_region_add_subregion(&s->mr, highmem_start, &s->mr_highmem);
    } else {
        memory_region_init_alias(&s->mr_lowmem, OBJECT(s), "mem",
                                 s->mr_memdev, 0, mem_size);
        memory_region_add_subregion(&s->mr, s->cfg.mem_offset, &s->mr_lowmem);
    }

    address_space_init(&s->as, MEMORY_REGION(&s->mr), "msg-bus-as");
}

static Property virtio_msg_bus_ivshmem_props[] = {
    DEFINE_PROP_STRING("dev", VirtIOMSGBusIVSHMEM, cfg.dev),
    DEFINE_PROP_UINT32("remote-vmid", VirtIOMSGBusIVSHMEM, cfg.remote_vmid, 0),
    DEFINE_PROP_BOOL("reset-queues", VirtIOMSGBusIVSHMEM,
                     cfg.reset_queues, false),
    DEFINE_PROP_LINK("memdev", VirtIOMSGBusIVSHMEM, cfg.memdev,
                     TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_UINT64("mem-offset", VirtIOMSGBusIVSHMEM, cfg.mem_offset, 0),
    DEFINE_PROP_UINT64("mem-low-size", VirtIOMSGBusIVSHMEM,
                       cfg.mem_low_size, 0),
    DEFINE_PROP_UINT64("mem-hole", VirtIOMSGBusIVSHMEM,
                       cfg.mem_hole, 0),
    DEFINE_PROP_STRING("iommu", VirtIOMSGBusIVSHMEM, cfg.iommu),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_bus_ivshmem_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    bdc->process = virtio_msg_bus_ivshmem_process;
    bdc->send = virtio_msg_bus_ivshmem_send;
    bdc->get_remote_as = virtio_msg_bus_ivshmem_get_remote_as;

    device_class_set_parent_realize(dc, virtio_msg_bus_ivshmem_realize,
                                    &bdc->parent_realize);
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
