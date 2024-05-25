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
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"

#include "hw/virtio/virtio-msg-bus-linux-user.h"

static void virtio_msg_bus_linux_user_send_notify(VirtIOMSGBusLinuxUser *s)
{
    uint8_t c = 0xed;

    qemu_chr_fe_write_all(&s->cfg.chr, &c, sizeof c);
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
            assert(bd->peer->receive);
            bd->peer->receive(bd, &msg);
        }
    } while (r);
}

static int virtio_msg_bus_linux_user_send(VirtIOMSGBusDevice *bd, VirtIOMSG *msg_req,
                                          VirtIOMSG *msg_resp)
{
    VirtIOMSGBusLinuxUser *s = VIRTIO_MSG_BUS_LINUX_USER(bd);
    VirtIOMSG msg_little_endian;
    spsc_queue *q_tx;
    spsc_queue *q_rx;
    bool sent;
    int i;

    q_tx = bd->peer->is_driver ? s->shm_queues.driver : s->shm_queues.device;
    q_rx = bd->peer->is_driver ? s->shm_queues.device : s->shm_queues.driver;

    /* FIXME: endian convert header here or distributed? */
    memcpy(&msg_little_endian, msg_req, sizeof *msg_req);

    do {
        sent = spsc_send(q_tx, &msg_little_endian, sizeof *msg_req);
    } while (!sent);

    virtio_msg_bus_linux_user_send_notify(s);

    if (msg_resp) {
        bool r = false;

        for (i = 0; !r && i < 40; i++){
            r = spsc_recv(q_rx, msg_resp, sizeof *msg_resp);
            usleep(1);
        }
        if (!r) {
            printf("ERROR: %s: timed out!!\n", __func__);
            abort();
        }
    }

    return VIRTIO_MSG_NO_ERROR;
}

static int virtio_msg_bus_linux_user_can_receive(void *opaque)
{
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(opaque);

    return bd->peer != NULL;
}

static void virtio_msg_bus_linux_user_receive(void *opaque,
                                              const uint8_t *buf, int size)
{
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(opaque);

    virtio_msg_bus_linux_user_process(bd);
}

static void virtio_msg_bus_linux_user_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusLinuxUser *s = VIRTIO_MSG_BUS_LINUX_USER(dev);
    g_autofree char *name_driver = NULL;
    g_autofree char *name_device = NULL;

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
}

static Property virtio_msg_bus_linux_user_props[] = {
    DEFINE_PROP_STRING("name", VirtIOMSGBusLinuxUser, cfg.name),
    DEFINE_PROP_CHR("chardev", VirtIOMSGBusLinuxUser, cfg.chr),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_bus_linux_user_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    bdc->process = virtio_msg_bus_linux_user_process;
    bdc->send = virtio_msg_bus_linux_user_send;

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
