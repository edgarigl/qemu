/*
 * VirtIO MSG bus on Linux user.
 * This uses switchboards underlying queue's (mmap) to transfer messages
 * and unix sockets to signal notifications.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"

#include "hw/virtio/virtio-msg-bus-linux-user.h"

static void virtio_msg_bus_linux_user_send_notify(VirtIOMSGBusLinuxUser *s)
{
    uint8_t c = 0xed;

    qemu_chr_fe_write_all(&s->cfg.chr, &c, sizeof c);
}

static AddressSpace *
virtio_msg_bus_linux_user_get_remote_as(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusLinuxUser *s = VIRTIO_MSG_BUS_LINUX_USER(bd);

    if (!s->cfg.memdev) {
        return NULL;
    }
    return &s->as;
}

static IOMMUTLBEntry
virtio_msg_bus_linux_user_iommu_translate(VirtIOMSGBusDevice *bd,
                                          uint64_t va,
                                          uint8_t prot)
{
    IOMMUTLBEntry ret;

    ret = virtio_msg_bus_pagemap_translate(bd, va, prot);
    return ret;
}

static void virtio_msg_bus_linux_user_process(VirtIOMSGBusDevice *bd) {
    VirtIOMSGBusLinuxUser *s = VIRTIO_MSG_BUS_LINUX_USER(bd);
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

static int virtio_msg_bus_linux_user_send(VirtIOMSGBusDevice *bd,
                                          VirtIOMSG *msg_req,
                                          VirtIOMSG *msg_resp)
{
    VirtIOMSGBusLinuxUser *s = VIRTIO_MSG_BUS_LINUX_USER(bd);
    spsc_queue *q_tx;
    spsc_queue *q_rx;
    bool sent;
    int i;

    q_tx = bd->peer->is_driver ? s->shm_queues.driver : s->shm_queues.device;
    q_rx = bd->peer->is_driver ? s->shm_queues.device : s->shm_queues.driver;

    do {
        sent = spsc_send(q_tx, msg_req, sizeof *msg_req);
    } while (!sent);

    virtio_msg_bus_linux_user_send_notify(s);

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
                r = false;
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

static int virtio_msg_bus_linux_user_can_receive(void *opaque)
{
    /* Consume multiple piled up notifications.  */
    return 128;
}

static void virtio_msg_bus_linux_user_receive(void *opaque,
                                              const uint8_t *buf, int size)
{
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(opaque);

    virtio_msg_bus_process(bd);
}

static void virtio_msg_bus_linux_user_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusLinuxUser *s = VIRTIO_MSG_BUS_LINUX_USER(dev);
    g_autofree char *name_driver = NULL;
    g_autofree char *name_device = NULL;
    uint64_t mem_size;

    if (s->cfg.name == NULL) {
        error_setg(errp, "property 'name' not specified.");
        return;
    }

    name_driver = g_strdup_printf("queue-%s-driver", s->cfg.name);
    name_device = g_strdup_printf("queue-%s-device", s->cfg.name);

    s->shm_queues.driver = spsc_open(name_driver, 4096);
    s->shm_queues.device = spsc_open(name_device, 4096);

    qemu_chr_fe_set_handlers(&s->cfg.chr,
                             virtio_msg_bus_linux_user_can_receive,
                             virtio_msg_bus_linux_user_receive,
                             NULL, NULL, s, NULL, true);

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

static Property virtio_msg_bus_linux_user_props[] = {
    DEFINE_PROP_STRING("name", VirtIOMSGBusLinuxUser, cfg.name),
    DEFINE_PROP_LINK("memdev", VirtIOMSGBusLinuxUser, cfg.memdev,
                     TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_UINT64("mem-offset", VirtIOMSGBusLinuxUser, cfg.mem_offset, 0),
    DEFINE_PROP_UINT64("mem-low-size", VirtIOMSGBusLinuxUser,
                       cfg.mem_low_size, 0),
    DEFINE_PROP_UINT64("mem-hole", VirtIOMSGBusLinuxUser,
                       cfg.mem_hole, 0),
    DEFINE_PROP_CHR("chardev", VirtIOMSGBusLinuxUser, cfg.chr),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_bus_linux_user_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    bdc->process = virtio_msg_bus_linux_user_process;
    bdc->send = virtio_msg_bus_linux_user_send;
    bdc->get_remote_as = virtio_msg_bus_linux_user_get_remote_as;
    bdc->iommu_translate = virtio_msg_bus_linux_user_iommu_translate;

    dc->realize = virtio_msg_bus_linux_user_realize;
    device_class_set_props(dc, virtio_msg_bus_linux_user_props);
}

static const TypeInfo virtio_msg_bus_linux_user_info = {
    .name = TYPE_VIRTIO_MSG_BUS_LINUX_USER,
    .parent = TYPE_VIRTIO_MSG_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGBusLinuxUser),
    .class_init = virtio_msg_bus_linux_user_class_init,
};

static void virtio_msg_bus_linux_user_register_types(void)
{
    type_register_static(&virtio_msg_bus_linux_user_info);
}

type_init(virtio_msg_bus_linux_user_register_types)
