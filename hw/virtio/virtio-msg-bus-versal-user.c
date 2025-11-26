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

    int fd;
    AddressSpace as;
    MemoryRegion mr_host;
    MemoryRegion mr_host_ram;
    MemoryRegion mr_host_ram_alias;

    struct {
        char *dev_path;
        uint64_t mem_size;
    } cfg;
} VirtIOMSGBusVersalUser;

#define VERSAL_USER_DEFAULT_DEV "/dev/virtio-msg-0"
#define VERSAL_USER_WIRE_MIN    50
#define VERSAL_USER_WIRE_MAX    64

static bool versal_user_recv_once(VirtIOMSGBusVersalUser *s)
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
        warn_report("virtio-msg-versal-user: read failed on %s: %s",
                    s->cfg.dev_path ?
                    s->cfg.dev_path : "<unknown>", strerror(errno));
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

    virtio_msg_unpack(&msg.msg);
    virtio_msg_bus_receive(VIRTIO_MSG_BUS_DEVICE(s), &msg.msg);
    return len >= 0;
}

static void virtio_msg_bus_versal_user_process(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusVersalUser *s = VIRTIO_MSG_BUS_VERSAL_USER(bd);
    bool r;

    do {
        r = versal_user_recv_once(s);
    } while (r);
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
    ssize_t written;

    written = write(s->fd, msg_req, sizeof *msg_req);

    if (written == sizeof *msg_req) {
        return VIRTIO_MSG_NO_ERROR;
    }

    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return VIRTIO_MSG_ERROR_RETRY;
    }

    warn_report("virtio-msg-versal-user: write failed on %s: %s",
                s->cfg.dev_path ? s->cfg.dev_path : "<unknown>", strerror(errno));
    return VIRTIO_MSG_ERROR_MEMORY;
}

static AddressSpace *
virtio_msg_bus_versal_user_get_remote_as(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusVersalUser *s = VIRTIO_MSG_BUS_VERSAL_USER(bd);

    return &s->as;
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

    g_free(s->cfg.dev_path);
    s->cfg.dev_path = NULL;

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

    if (!s->cfg.dev_path) {
        s->cfg.dev_path = g_strdup(VERSAL_USER_DEFAULT_DEV);
    }

    s->fd = open(s->cfg.dev_path, O_RDWR | O_NONBLOCK);
    if (s->fd < 0) {
        error_setg_errno(errp, errno,
                         "virtio-msg-versal-user: failed to open %s",
                         s->cfg.dev_path);
        return;
    }

    qemu_set_fd_handler(s->fd, versal_user_read, NULL, s);

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
}

static Property virtio_msg_bus_versal_user_props[] = {
    DEFINE_PROP_STRING("dev", VirtIOMSGBusVersalUser, cfg.dev_path),
    DEFINE_PROP_UINT64("mem-size", VirtIOMSGBusVersalUser, cfg.mem_size,
                       0x860000000ULL),
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
    bdc->get_remote_as = virtio_msg_bus_versal_user_get_remote_as;
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
