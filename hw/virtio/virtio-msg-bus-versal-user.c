/*
 * Virtio-msg bus backend using the versal-virtio-msg kernel driver
 * userspace interface.
 *
 * This provides a lightweight bridge that opens a /dev/virtio-msg-* misc
 * device exposed by the kernel module and forwards messages between QEMU's
 * virtio-msg core and the kernel transport.
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/log.h"
#include "hw/qdev-properties.h"

#include "hw/virtio/virtio-msg-prot.h"
#include "hw/virtio/virtio-msg-bus.h"

#define TYPE_VIRTIO_MSG_BUS_VERSAL_USER "virtio-msg-bus-versal-user"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGBusVersalUser,
                           VIRTIO_MSG_BUS_VERSAL_USER)

typedef struct VirtIOMSGBusVersalUser {
    VirtIOMSGBusDevice parent_obj;

    char *dev_path;
    int fd;
} VirtIOMSGBusVersalUser;

#define VERSAL_USER_DEFAULT_DEV "/dev/virtio-msg-0"
#define VERSAL_USER_WIRE_MIN    50
#define VERSAL_USER_WIRE_MAX    64

static bool versal_user_recv_once(VirtIOMSGBusVersalUser *s)
{
    VirtIOMSG msg = {0};
    ssize_t len;

    len = read(s->fd, &msg, sizeof(msg));
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false;
        }
        warn_report("virtio-msg-versal-user: read failed on %s: %s",
                    s->dev_path ? s->dev_path : "<unknown>", strerror(errno));
        return false;
    }

    if (len == 0) {
        /* EOF. Treat as no more data. */
        return false;
    }

    if (len < VERSAL_USER_WIRE_MIN) {
        warn_report("virtio-msg-versal-user: short message (%zd bytes) dropped", len);
        return true;
    }

    virtio_msg_unpack(&msg);
    virtio_msg_bus_receive(VIRTIO_MSG_BUS_DEVICE(s), &msg);
    return len >= 0;
}

static void virtio_msg_bus_versal_user_process(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusVersalUser *s = VIRTIO_MSG_BUS_VERSAL_USER(bd);

    versal_user_recv_once(s);
}

static void versal_user_read(void *opaque)
{
    VirtIOMSGBusDevice *bd = opaque;

    virtio_msg_bus_versal_user_process(bd);
}

static int virtio_msg_bus_versal_user_send(VirtIOMSGBusDevice *bd,
                                           VirtIOMSG *msg_req)
{
    VirtIOMSGBusVersalUser *s = VIRTIO_MSG_BUS_VERSAL_USER(bd);
    size_t msg_size;
    ssize_t written;

    msg_size = le16_to_cpu(msg_req->msg_size);
    if (!msg_size) {
        msg_size = virtio_msg_header_size();
    }

    written = write(s->fd, msg_req, msg_size);

    if (written == msg_size) {
        return VIRTIO_MSG_NO_ERROR;
    }

    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return VIRTIO_MSG_ERROR_RETRY;
    }

    warn_report("virtio-msg-versal-user: write failed on %s: %s",
                s->dev_path ? s->dev_path : "<unknown>", strerror(errno));
    return VIRTIO_MSG_ERROR_MEMORY;
}

static void virtio_msg_bus_versal_user_unrealize(DeviceState *dev)
{
    VirtIOMSGBusVersalUser *s = VIRTIO_MSG_BUS_VERSAL_USER(dev);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);

    if (s->fd >= 0) {
        qemu_set_fd_handler(s->fd, NULL, NULL, NULL);
        close(s->fd);
        s->fd = -1;
    }

    g_free(s->dev_path);
    s->dev_path = NULL;

    if (bdc->parent_unrealize) {
        bdc->parent_unrealize(dev);
    }
}

static void virtio_msg_bus_versal_user_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusVersalUser *s = VIRTIO_MSG_BUS_VERSAL_USER(dev);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);

    if (bdc->parent_realize) {
        bdc->parent_realize(dev, errp);
        if (*errp) {
            return;
        }
    }

    if (!s->dev_path) {
        s->dev_path = g_strdup(VERSAL_USER_DEFAULT_DEV);
    }

    s->fd = open(s->dev_path, O_RDWR | O_NONBLOCK);
    if (s->fd < 0) {
        error_setg_errno(errp, errno,
                         "virtio-msg-versal-user: failed to open %s",
                         s->dev_path);
        return;
    }

    qemu_set_fd_handler(s->fd, versal_user_read, NULL, s);
}

static Property virtio_msg_bus_versal_user_props[] = {
    DEFINE_PROP_STRING("dev", VirtIOMSGBusVersalUser, dev_path),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_bus_versal_user_init(Object *obj)
{
    VirtIOMSGBusVersalUser *s = VIRTIO_MSG_BUS_VERSAL_USER(obj);

    s->fd = -1;
}

static void virtio_msg_bus_versal_user_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_msg_bus_versal_user_props);
    dc->realize = virtio_msg_bus_versal_user_realize;
    dc->unrealize = virtio_msg_bus_versal_user_unrealize;

    bdc->process = virtio_msg_bus_versal_user_process;
    bdc->send = virtio_msg_bus_versal_user_send;
}

static const TypeInfo virtio_msg_bus_versal_user_info = {
    .name          = TYPE_VIRTIO_MSG_BUS_VERSAL_USER,
    .parent        = TYPE_VIRTIO_MSG_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGBusVersalUser),
    .instance_init = virtio_msg_bus_versal_user_init,
    .class_init    = virtio_msg_bus_versal_user_class_init,
};

static void virtio_msg_bus_versal_user_register_types(void)
{
    type_register_static(&virtio_msg_bus_versal_user_info);
}

type_init(virtio_msg_bus_versal_user_register_types);
