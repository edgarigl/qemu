#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/virtio-msg.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "trace.h"

static void vmsg_device_info(VirtIOMSGProxy *proxy,
                               VirtIOMSG *msg,
                               VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtIOMSG msg_resp;

    virtio_msg_pack_get_device_info_resp(&msg_resp,
                                         VIRTIO_MSG_DEVICE_VERSION,
                                         vdev->device_id,
                                         VIRTIO_MSG_VENDOR_ID);
    virtio_msg_bus_send(&proxy->msg_bus, &msg_resp, NULL);
}

static void vmsg_get_device_feat(VirtIOMSGProxy *proxy,
                                   VirtIOMSG *msg,
                                   VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_GET_CLASS(vdev);
    VirtIOMSG msg_resp;
    uint64_t features = mp->get_device_feat.features;

    features = vdc->get_features(vdev, features, &error_abort);

    virtio_msg_pack_get_device_feat_resp(&msg_resp, 0, features);
    virtio_msg_bus_send(&proxy->msg_bus, &msg_resp, NULL);
}

static void vmsg_set_device_feat(VirtIOMSGProxy *proxy,
                                   VirtIOMSG *msg,
                                   VirtIOMSGPayload *mp)
{
    proxy->guest_features = mp->set_device_feat.features;
}

static void virtio_msg_pb_soft_reset(VirtIOMSGProxy *proxy)
{
    virtio_bus_reset(&proxy->bus);
    proxy->guest_features = 0;
}

static void vmsg_set_device_status(VirtIOMSGProxy *proxy,
                                     VirtIOMSG *msg,
                                     VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    uint32_t status = mp->set_device_status.status;

    printf("set_device_status: %x %x\n", status, vdev->status);

    if (!(status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        virtio_bus_stop_ioeventfd(&proxy->bus);
    }

    if (status & VIRTIO_CONFIG_S_FEATURES_OK) {
        virtio_set_features(vdev, proxy->guest_features);
    }

    virtio_set_status(vdev, status);
    assert(vdev->status == status);

    if (status & VIRTIO_CONFIG_S_DRIVER_OK) {
        virtio_bus_start_ioeventfd(&proxy->bus);
    }

    if (status == 0) {
        virtio_msg_pb_soft_reset(proxy);
    }
}

static void vmsg_get_device_status(VirtIOMSGProxy *proxy,
                                     VirtIOMSG *msg,
                                     VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtIOMSG msg_resp;

    virtio_msg_pack_get_device_status_resp(&msg_resp, vdev->status);
    virtio_msg_print(&msg_resp, true);
    virtio_msg_bus_send(&proxy->msg_bus, &msg_resp, NULL);
}

static void vmsg_get_device_conf(VirtIOMSGProxy *proxy,
                                   VirtIOMSG *msg,
                                   VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    uint32_t size = mp->get_device_conf.size;
    uint32_t offset = mp->get_device_conf.offset;
    uint32_t data;
    VirtIOMSG msg_resp;

    switch (size) {
    case 4:
        data = virtio_config_modern_readl(vdev, offset);
        break;
    case 2:
        data = virtio_config_modern_readw(vdev, offset);
        break;
    case 1:
        data = virtio_config_modern_readb(vdev, offset);
        break;
    default:
        g_assert_not_reached();
        break;
    }

    virtio_msg_pack_get_device_conf_resp(&msg_resp, size, offset, data);
    virtio_msg_bus_send(&proxy->msg_bus, &msg_resp, NULL);
}

static void vmsg_set_device_conf(VirtIOMSGProxy *proxy,
                                   VirtIOMSG *msg,
                                   VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    uint32_t size = mp->set_device_conf.size;
    uint32_t offset = mp->set_device_conf.offset;
    uint32_t data = mp->set_device_conf.data;

    switch (size) {
    case 4:
        virtio_config_modern_writel(vdev, offset, data);
        break;
    case 2:
        virtio_config_modern_writew(vdev, offset, data);
        break;
    case 1:
        virtio_config_modern_writeb(vdev, offset, data);
        break;
    default:
        g_assert_not_reached();
        break;
    }
}

static void vmsg_get_vqueue(VirtIOMSGProxy *proxy,
                              VirtIOMSG *msg,
                              VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtIOMSG msg_resp;
    uint32_t max_size = VIRTQUEUE_MAX_SIZE;
    uint32_t index = mp->get_vqueue.index;

    if (!virtio_queue_get_num(vdev, index)) {
        max_size = 0;
    }

    virtio_msg_pack_get_vqueue_resp(&msg_resp, index, max_size);
    virtio_msg_bus_send(&proxy->msg_bus, &msg_resp, NULL);
}

static void vmsg_set_vqueue(VirtIOMSGProxy *proxy,
                              VirtIOMSG *msg,
                              VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);

    virtio_queue_set_num(vdev, mp->set_vqueue.index, mp->set_vqueue.size);
    virtio_queue_set_rings(vdev, mp->set_vqueue.index,
                           mp->set_vqueue.descriptor_addr,
                           mp->set_vqueue.driver_addr,
                           mp->set_vqueue.device_addr);
    virtio_queue_enable(vdev, vdev->queue_sel);
}

static void vmsg_event_driver(VirtIOMSGProxy *proxy,
                                VirtIOMSG *msg,
                                VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);

    //printf("%s: %d\n", __func__, mp->event_driver.index);
    virtio_queue_notify(vdev, mp->event_driver.index);
}

typedef void (*VirtIOMSGHandler)(VirtIOMSGProxy *proxy,
                                 VirtIOMSG *msg,
                                 VirtIOMSGPayload *mp);

static const VirtIOMSGHandler msg_handlers[VIRTIO_MSG_MAX] = {
    [VIRTIO_MSG_DEVICE_INFO] = vmsg_device_info,
    [VIRTIO_MSG_GET_DEVICE_FEAT] = vmsg_get_device_feat,
    [VIRTIO_MSG_SET_DEVICE_FEAT] = vmsg_set_device_feat,
    [VIRTIO_MSG_GET_DEVICE_STATUS] = vmsg_get_device_status,
    [VIRTIO_MSG_SET_DEVICE_STATUS] = vmsg_set_device_status,
    [VIRTIO_MSG_GET_DEVICE_CONF] = vmsg_get_device_conf,
    [VIRTIO_MSG_SET_DEVICE_CONF] = vmsg_set_device_conf,
    [VIRTIO_MSG_GET_VQUEUE] = vmsg_get_vqueue,
    [VIRTIO_MSG_SET_VQUEUE] = vmsg_set_vqueue,
    [VIRTIO_MSG_EVENT_DRIVER] = vmsg_event_driver,
};

static int vmsg_receive_msg(VirtIOMSGBusDevice *bd, VirtIOMSG *msg)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(bd->opaque);
    VirtIOMSGPayload mp;
    VirtIOMSGHandler handler;

    if (msg->type > ARRAY_SIZE(msg_handlers)) {
        return VIRTIO_MSG_ERROR_UNSUPPORTED_PACKET_TYPE;
    }

    handler = msg_handlers[msg->type];
    virtio_msg_unpack(msg, &mp);

    if (handler) {
        handler(proxy, msg, &mp);
        return VIRTIO_MSG_NO_ERROR;
    }

    return VIRTIO_MSG_NO_ERROR;
}

static const VirtIOMSGBusPort vmsg_port = {
    .receive = vmsg_receive_msg,
    .is_driver = false
};

static void virtio_msg_pb_notify_queue(DeviceState *opaque, uint16_t index)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(opaque);
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtIOMSG msg;

    if (!vdev || !virtio_msg_bus_connected(&proxy->msg_bus)) {
        return;
    }

    virtio_msg_pack_event_device(&msg, index);
    virtio_msg_bus_send(&proxy->msg_bus, &msg, NULL);
}

static const VMStateDescription vmstate_virtio_msg_pb_state_sub = {
    .name = "virtio_msg_device",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(guest_features, VirtIOMSGProxy),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_virtio_msg = {
    .name = "virtio_msg_proxy_backend",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_virtio_msg_pb_state_sub,
        NULL
    }
};

static void virtio_msg_pb_save_extra_state(DeviceState *opaque, QEMUFile *f)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(opaque);

    vmstate_save_state(f, &vmstate_virtio_msg, proxy, NULL);
}

static int virtio_msg_pb_load_extra_state(DeviceState *opaque, QEMUFile *f)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(opaque);

    return vmstate_load_state(f, &vmstate_virtio_msg, proxy, 1);
}

static bool virtio_msg_pb_has_extra_state(DeviceState *opaque)
{
    return true;
}

static void virtio_msg_pb_reset_hold(Object *obj, ResetType type)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(obj);

    virtio_msg_pb_soft_reset(proxy);

    virtio_msg_bus_connect(&proxy->msg_bus, &vmsg_port, proxy);
}

static int virtio_msg_pb_set_guest_notifier(DeviceState *d, int n, bool assign,
                                          bool with_irqfd)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(d);
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_GET_CLASS(vdev);
    VirtQueue *vq = virtio_get_queue(vdev, n);
    EventNotifier *notifier = virtio_queue_get_guest_notifier(vq);

    if (assign) {
        int r = event_notifier_init(notifier, 0);
        if (r < 0) {
            return r;
        }
        virtio_queue_set_guest_notifier_fd_handler(vq, true, with_irqfd);
    } else {
        virtio_queue_set_guest_notifier_fd_handler(vq, false, with_irqfd);
        event_notifier_cleanup(notifier);
    }

    if (vdc->guest_notifier_mask && vdev->use_guest_notifier_mask) {
        vdc->guest_notifier_mask(vdev, n, !assign);
    }

    return 0;
}
static int virtio_msg_pb_set_config_guest_notifier(DeviceState *d, bool assign,
                                                 bool with_irqfd)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(d);
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_GET_CLASS(vdev);
    EventNotifier *notifier = virtio_config_get_guest_notifier(vdev);
    int r = 0;

    if (assign) {
        r = event_notifier_init(notifier, 0);
        if (r < 0) {
            return r;
        }
        virtio_config_set_guest_notifier_fd_handler(vdev, assign, with_irqfd);
    } else {
        virtio_config_set_guest_notifier_fd_handler(vdev, assign, with_irqfd);
        event_notifier_cleanup(notifier);
    }
    if (vdc->guest_notifier_mask && vdev->use_guest_notifier_mask) {
        vdc->guest_notifier_mask(vdev, VIRTIO_CONFIG_IRQ_IDX, !assign);
    }
    return r;
}
static int virtio_msg_pb_set_guest_notifiers(DeviceState *d, int nvqs,
                                           bool assign)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(d);
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    /* TODO: need to check if kvm-arm supports irqfd */
    bool with_irqfd = false;
    int r, n;

    nvqs = MIN(nvqs, VIRTIO_QUEUE_MAX);

    for (n = 0; n < nvqs; n++) {
        if (!virtio_queue_get_num(vdev, n)) {
            break;
        }

        r = virtio_msg_pb_set_guest_notifier(d, n, assign, with_irqfd);
        if (r < 0) {
            goto assign_error;
        }
    }
    r = virtio_msg_pb_set_config_guest_notifier(d, assign, with_irqfd);
    if (r < 0) {
        goto assign_error;
    }

    return 0;

assign_error:
    /* We get here on assignment failure. Recover by undoing for VQs 0 .. n. */
    assert(assign);
    while (--n >= 0) {
        virtio_msg_pb_set_guest_notifier(d, n, !assign, false);
    }
    return r;
}

static void virtio_msg_pb_pre_plugged(DeviceState *d, Error **errp)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(d);
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);

    virtio_add_feature(&vdev->host_features, VIRTIO_F_VERSION_1);
}

static Property virtio_msg_pb_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_pb_realize(DeviceState *d, Error **errp)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(d);

    qbus_init(&proxy->bus, sizeof(proxy->bus),
              TYPE_VIRTIO_MSG_PROXY_BUS, d, NULL);
    qbus_init(&proxy->msg_bus, sizeof(proxy->msg_bus),
              TYPE_VIRTIO_MSG_BUS, d, NULL);
}

static void virtio_msg_pb_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    dc->realize = virtio_msg_pb_realize;
    dc->user_creatable = true;
    rc->phases.hold  = virtio_msg_pb_reset_hold;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, virtio_msg_pb_properties);
}

static const TypeInfo virtio_msg_pb_info = {
    .name          = TYPE_VIRTIO_MSG,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGProxy),
    .class_init    = virtio_msg_pb_class_init,
};

static char *virtio_msg_pb_bus_get_dev_path(DeviceState *dev)
{
    BusState *virtio_msg_pb_bus;
    VirtIOMSGProxy *virtio_msg_pb_proxy;
    char *proxy_path;

    virtio_msg_pb_bus = qdev_get_parent_bus(dev);
    virtio_msg_pb_proxy = VIRTIO_MSG(virtio_msg_pb_bus->parent);
    proxy_path = qdev_get_dev_path(DEVICE(virtio_msg_pb_proxy));

    return proxy_path;
}

static void virtio_msg_pb_bus_class_init(ObjectClass *klass, void *data)
{
    BusClass *bus_class = BUS_CLASS(klass);
    VirtioBusClass *k = VIRTIO_BUS_CLASS(klass);

    k->notify_queue = virtio_msg_pb_notify_queue;
    k->save_extra_state = virtio_msg_pb_save_extra_state;
    k->load_extra_state = virtio_msg_pb_load_extra_state;
    k->has_extra_state = virtio_msg_pb_has_extra_state;
    k->set_guest_notifiers = virtio_msg_pb_set_guest_notifiers;
#if 0
    k->ioeventfd_enabled = virtio_msg_pb_ioeventfd_enabled;
    k->ioeventfd_assign = virtio_msg_pb_ioeventfd_assign;
#endif
    k->pre_plugged = virtio_msg_pb_pre_plugged;
    k->has_variable_vring_alignment = true;
    bus_class->max_dev = 1;
    bus_class->get_dev_path = virtio_msg_pb_bus_get_dev_path;
}

static const TypeInfo virtio_msg_pb_bus_info = {
    .name          = TYPE_VIRTIO_MSG_PROXY_BUS,
    .parent        = TYPE_VIRTIO_BUS,
    .instance_size = sizeof(VirtioBusState),
    .class_init    = virtio_msg_pb_bus_class_init,
};

static void virtio_msg_pb_register_types(void)
{
    type_register_static(&virtio_msg_pb_bus_info);
    type_register_static(&virtio_msg_pb_info);
}

type_init(virtio_msg_pb_register_types)
