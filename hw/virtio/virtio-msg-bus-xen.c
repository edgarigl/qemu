/*
 * virtio-msg bus on top Xen.
 *
 * Uses either grant or foreign mappings for the shared queues.
 * Uses event channels for notifications both ways.
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
#include "hw/xen/xen_native.h"
#include "hw/xen/xen-bus-helper.h"

#include "hw/virtio/virtio-msg-bus-xen.h"
#include "hw/virtio/pagemap.h"

static void virtio_msg_bus_xen_send_notify(VirtIOMSGBusXen *s)
{
    qemu_xen_evtchn_notify(s->xen.eh, s->xen.local_port);
}

static void virtio_msg_bus_xen_recv(VirtIOMSGBusDevice *bd,
                                    VirtIOMSG *msg)
{
    /* Need to unpack xen bus messages.  */
    virtio_msg_unpack(msg);

    /* We don't have any bus specific messages.  */
}

static void virtio_msg_bus_xen_process(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(bd);
    spsc_queue *q;
    VirtIOMSG msg;
    bool r;

    if (!bd->peer) {
        return;
    }

    /*
     * We process the opposite queue, i.e, a driver will want to receive
     * messages on the backend queue (and send messages on the driver queue).
     */
    q = bd->peer->is_driver ? &s->shm_queues.device : &s->shm_queues.driver;
    do {
        r = spsc_recv(q, &msg, sizeof msg);
        if (r) {
            if (msg.type & VIRTIO_MSG_TYPE_BUS) {
                virtio_msg_bus_xen_recv(bd, &msg);
            } else {
                virtio_msg_bus_receive(bd, &msg);
            }
        }
    } while (r);
}

static int virtio_msg_bus_xen_send(VirtIOMSGBusDevice *bd, VirtIOMSG *msg_req)
{
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(bd);
    spsc_queue *q_tx;
    bool sent;

    q_tx = bd->peer->is_driver ? &s->shm_queues.driver : &s->shm_queues.device;

    /* TODO: Add a way to handle retries. */
    sent = spsc_send(q_tx, msg_req, sizeof *msg_req);

    if (sent) {
        virtio_msg_bus_xen_send_notify(s);
    }

    return sent ? VIRTIO_MSG_NO_ERROR : VIRTIO_MSG_ERROR_RETRY;
}

static void virtio_msg_bus_xen_event(void *opaque)
{
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(opaque);
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(opaque);
    int port;

    port = qemu_xen_evtchn_pending(s->xen.eh);
    if (port != s->xen.local_port) {
        return;
    }

    qemu_xen_evtchn_unmask(s->xen.eh, port);
    virtio_msg_bus_xen_process(bd);
}

static bool virtio_msg_bus_xen_connect_evtchn(VirtIOMSGBusXen *s, int port)
{
    xenevtchn_port_or_error_t lp;
    int fd;

    lp = qemu_xen_evtchn_bind_interdomain(s->xen.eh, xen_domid, port);
    if (lp < 0) {
        return false;
    }

    /* Register with main loop.  */
    fd = qemu_xen_evtchn_fd(s->xen.eh);
    if (fd < 0) {
        qemu_xen_evtchn_unbind(s->xen.eh, lp);
        return false;
    }

    qemu_set_fd_handler(fd, virtio_msg_bus_xen_event, NULL, s);
    s->xen.local_port = lp;
    return true;
}

static void virtio_msg_bus_xen_connect(VirtIOMSGBusXen *s, Error **errp)
{
    uint32_t port = 0;
    uint64_t gfn;
    uint64_t pa;
    void *user_va;
    int rc;

    /* Map shm page.  */
    user_va = mmap(NULL, XEN_PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (user_va == MAP_FAILED) {
        error_setg(errp, "Failed to map shm page");
        return;
    }

    /* Pin and populate pages.  */
    if (mlock(user_va, XEN_PAGE_SIZE) != 0) {
        warn_report_once("virtio-msg: mlock failed; continuing without pin");
    }
    memset(user_va, 0, XEN_PAGE_SIZE);

    pa = pagemap_virt_to_phys(user_va);
    if (pa == PAGEMAP_FAILED) {
        error_setg(errp, "Failed to get gfn of shm page");
        munmap(user_va, XEN_PAGE_SIZE);
        return;
    }

    gfn = pa >> XEN_PAGE_SHIFT;

    /* Now connect to the virtio-msg bus.  */
    rc = xendevicemodel_virtio_msg_bus_xen_connect(xen_dmod, xen_domid,
                                                   s->cfg.bus_id,
                                                   s->cfg.dev_num,
                                                   gfn, &port);
    if (rc < 0) {
        error_setg_errno(errp, errno, "virtio-msg-bus-xen: connect failed");
        munmap(user_va, XEN_PAGE_SIZE);
        return;
    }

    /* Done.  */
    s->xen.shm = user_va;
    s->xen.port = port;
}

static void virtio_msg_bus_xen_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(dev);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);
    g_autofree char *name_driver = NULL;
    g_autofree char *name_device = NULL;

    if (bdc->parent_realize) {
        bdc->parent_realize(dev, errp);
        if (*errp) {
            return;
        }
    }

    s->xen.eh = qemu_xen_evtchn_open();
    if (!s->xen.eh) {
        error_setg_errno(errp, errno, "failed xenevtchn_open");
        return;
    }

    virtio_msg_bus_xen_connect(s, errp);
    if (*errp) {
        qemu_xen_evtchn_close(s->xen.eh);
        return;
    }

    spsc_init(&s->shm_queues.driver, "driver", spsc_capacity(1 * KiB),
              s->xen.shm);
    spsc_init(&s->shm_queues.device, "device", spsc_capacity(1 * KiB),
              s->xen.shm + 1 * KiB);

    if (!virtio_msg_bus_xen_connect_evtchn(s, s->xen.port)) {
        error_setg_errno(errp, errno, "Failed to connect to event channel!");
        qemu_xen_evtchn_close(s->xen.eh);
        munmap(s->xen.shm, XEN_PAGE_SIZE);
    }
}

static void virtio_msg_bus_xen_unrealize(DeviceState *dev)
{
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(dev);
    int fd;

    if (bdc->parent_unrealize) {
        bdc->parent_unrealize(dev);
    }

    /* Since realize() succeeded, s->xen.eh is valid and needs teardown.  */
    assert(s->xen.eh);
    fd = qemu_xen_evtchn_fd(s->xen.eh);
    if (fd >= 0) {
        qemu_set_fd_handler(fd, NULL, NULL, NULL);
    }
    qemu_xen_evtchn_unbind(s->xen.eh, s->xen.local_port);
    qemu_xen_evtchn_close(s->xen.eh);

    /* Since realize() succeeded, s->xen.shm needs unmapping.  */
    assert(s->xen.shm != MAP_FAILED);
    munmap(s->xen.shm, XEN_PAGE_SIZE);
}

static Property virtio_msg_bus_xen_props[] = {
    DEFINE_PROP_UINT32("bus-id", VirtIOMSGBusXen, cfg.bus_id, 0),
    DEFINE_PROP_UINT16("dev-num", VirtIOMSGBusXen, cfg.dev_num, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_bus_xen_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    bdc->process = virtio_msg_bus_xen_process;
    bdc->send = virtio_msg_bus_xen_send;

    device_class_set_parent_realize(dc, virtio_msg_bus_xen_realize,
                                    &bdc->parent_realize);
    device_class_set_parent_unrealize(dc, virtio_msg_bus_xen_unrealize,
                                      &bdc->parent_unrealize);
    device_class_set_props(dc, virtio_msg_bus_xen_props);
}

static const TypeInfo virtio_msg_bus_xen_info = {
    .name = TYPE_VIRTIO_MSG_BUS_XEN,
    .parent = TYPE_VIRTIO_MSG_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGBusXen),
    .class_init = virtio_msg_bus_xen_class_init,
};

static void virtio_msg_bus_xen_register_types(void)
{
    type_register_static(&virtio_msg_bus_xen_info);
}

type_init(virtio_msg_bus_xen_register_types)
