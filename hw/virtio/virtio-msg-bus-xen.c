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

#include <xengnttab.h>

static void virtio_msg_bus_xen_connect_evtchn(VirtIOMSGBusXen *s, int port);

static xengnttab_handle *xen_region_gnttabdev;

static void virtio_msg_bus_xen_send_notify(VirtIOMSGBusXen *s)
{
    qemu_xen_evtchn_notify(s->xen.eh, s->xen.local_port);
}

static AddressSpace *
virtio_msg_bus_xen_get_remote_as(VirtIOMSGBusDevice *bd)
{
    return &address_space_memory;
}

static void virtio_msg_bus_xen_recv(VirtIOMSGBusDevice *bd,
                                    VirtIOMSG *msg)
{
    /* Need to unpack xen bus messages.  */
    virtio_msg_unpack(msg);

#if 0
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(bd);

    if (msg->id == VIRTIO_MSG_CONNECT) {
        LE_TO_CPU(msg->connect_bus_xen.event_channel_port);
        virtio_msg_bus_xen_connect_evtchn(s,
                                   msg->connect_bus_xen.event_channel_port);
    }
#endif
}

static void virtio_msg_bus_xen_process(VirtIOMSGBusDevice *bd) {
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(bd);
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
            if (msg.type & VIRTIO_MSG_TYPE_BUS) {
                virtio_msg_bus_xen_recv(bd, &msg);
            } else {
                virtio_msg_bus_receive(bd, &msg);
            }
        }
    } while (r);
}

static void virtio_msg_bus_xen_connect(VirtIOMSGBusDevice *bd)
{
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(bd);

    while (!s->xen.connected) {
        virtio_msg_bus_xen_process(bd);
        if (!s->xen.connected) {
            usleep(200 * 1000);
        }
    }
}

static int virtio_msg_bus_xen_send(VirtIOMSGBusDevice *bd,
                                          VirtIOMSG *msg_req,
                                          VirtIOMSG *msg_resp)
{
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(bd);
    spsc_queue *q_tx;
    spsc_queue *q_rx;
    bool sent;
    int i;

    q_tx = bd->peer->is_driver ? s->shm_queues.driver : s->shm_queues.device;
    q_rx = bd->peer->is_driver ? s->shm_queues.device : s->shm_queues.driver;

    do {
        sent = spsc_send(q_tx, msg_req, sizeof *msg_req);
    } while (!sent);

    virtio_msg_bus_xen_send_notify(s);

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

static void virtio_msg_bus_xen_event(void *opaque)
{
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(opaque);
    VirtIOMSGBusDevice *bd = VIRTIO_MSG_BUS_DEVICE(opaque);
    int port;

    port = qemu_xen_evtchn_pending(s->xen.eh);
    if (port != s->xen.local_port) {
        return;
    }

    virtio_msg_bus_xen_process(bd);
    qemu_xen_evtchn_unmask(s->xen.eh, port);
}

static void virtio_msg_bus_xen_connect_evtchn(VirtIOMSGBusXen *s, int port)
{
    int evtchn_fd;

    s->xen.local_port = qemu_xen_evtchn_bind_interdomain(s->xen.eh,
                                                         xen_domid,
                                                         port);
    /* Register with main loop.  */
    evtchn_fd = qemu_xen_evtchn_fd(s->xen.eh);
    if (evtchn_fd != -1) {
        qemu_set_fd_handler(evtchn_fd, virtio_msg_bus_xen_event, NULL, s);
    }
    s->xen.connected = true;
}

static void virtio_msg_bus_xen_map_shm(VirtIOMSGBusXen *s, Error **errp)
{
    uint32_t grant_ref;
    xen_pfn_t pfn;
    int nb_pfn = 1;

    grant_ref = s->cfg.shm_base;

    /* Try grants first.  */
    if (xen_region_gnttabdev) {
        s->xen.shm = xengnttab_map_domain_grant_refs(xen_region_gnttabdev,
                                                     nb_pfn,
                                                     xen_domid, &grant_ref,
                                                     PROT_READ | PROT_WRITE);
        if (s->xen.shm) {
            return;
        }
    }

    /* Grants failed, fall back to foreign mappings.  */
    pfn = s->cfg.shm_base >> XC_PAGE_SHIFT;
    s->xen.shm = xenforeignmemory_map2(xen_fmem, xen_domid, NULL,
                                       PROT_READ | PROT_WRITE,
                                       /* No flags  */ 0,
                                       nb_pfn, &pfn, NULL);

    if (!s->xen.shm) {
        error_setg(errp, "Failed to map shm-base %lx", s->cfg.shm_base);
    }
}

static void virtio_msg_bus_xen_realize(DeviceState *dev, Error **errp)
{
    VirtIOMSGBusXen *s = VIRTIO_MSG_BUS_XEN(dev);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_GET_CLASS(dev);

    g_autofree char *name_driver = NULL;
    g_autofree char *name_device = NULL;

    bdc->parent_realize(dev, errp);
    if (*errp) {
        return;
    }

    if (s->cfg.shm_base == UINT64_MAX) {
        error_setg(errp, "shm-base not set!");
        return;
    }

    if (!xen_region_gnttabdev) {
        xen_region_gnttabdev = xengnttab_open(NULL, 0);
        if (!xen_region_gnttabdev) {
            error_setg(errp, "Failed to open gnttab device");
            return;
        }
    }

    virtio_msg_bus_xen_map_shm(s, errp);
    if (*errp) {
        return;
    }

    s->shm_queues.driver = spsc_open_mem("queue-driver",
                                         spsc_capacity(1 * KiB),
                                         s->xen.shm);
    s->shm_queues.device = spsc_open_mem("queue-device",
                                         spsc_capacity(1 * KiB),
                                         s->xen.shm + 1 * KiB);
    assert(s->shm_queues.driver);
    assert(s->shm_queues.device);

    s->xen.eh = qemu_xen_evtchn_open();
    if (!s->xen.eh) {
        error_setg_errno(errp, errno, "failed xenevtchn_open");
        return;
    }

    if (s->cfg.port) {
        virtio_msg_bus_xen_connect_evtchn(s, s->cfg.port);
    }

    printf("%s: DONE\n", __func__);
}

static Property virtio_msg_bus_xen_props[] = {
    DEFINE_PROP_UINT64("shm-base", VirtIOMSGBusXen, cfg.shm_base, UINT64_MAX),
    DEFINE_PROP_UINT16("port", VirtIOMSGBusXen, cfg.port, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_bus_xen_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOMSGBusDeviceClass *bdc = VIRTIO_MSG_BUS_DEVICE_CLASS(klass);

    bdc->process = virtio_msg_bus_xen_process;
    bdc->connect = virtio_msg_bus_xen_connect;
    bdc->send = virtio_msg_bus_xen_send;
    bdc->get_remote_as = virtio_msg_bus_xen_get_remote_as;

    device_class_set_parent_realize(dc, virtio_msg_bus_xen_realize,
                                    &bdc->parent_realize);
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
