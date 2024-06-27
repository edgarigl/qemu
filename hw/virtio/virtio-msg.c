#include "qemu/osdep.h"
#include "qemu/units.h"
#include "sysemu/dma.h"
#include "qapi/error.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-msg-bus.h"
#include "hw/virtio/virtio-msg.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "trace.h"

#define TYPE_VIRTIO_MSG_IOMMU_MEMORY_REGION "virtio-msg-iommu-memory-region"

static void virtio_msg_device_info(VirtIOMSGProxy *proxy,
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

static void virtio_msg_get_device_feat(VirtIOMSGProxy *proxy,
                                       VirtIOMSG *msg,
                                       VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_GET_CLASS(vdev);
    VirtIOMSG msg_resp;
    uint64_t features;

    /*
     * The peer's host_features shouldn't matter here. When we're
     * connected to a QEMU proxy, we need to advertise our local
     * host features and not anything provided by the proxy.
     */
    features = vdc->get_features(vdev, vdev->host_features, &error_abort);

    virtio_msg_pack_get_device_feat_resp(&msg_resp, 0, features);
    virtio_msg_bus_send(&proxy->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_set_device_feat(VirtIOMSGProxy *proxy,
                                       VirtIOMSG *msg,
                                       VirtIOMSGPayload *mp)
{
    proxy->guest_features = mp->set_device_feat.features;
}

static void virtio_msg_soft_reset(VirtIOMSGProxy *proxy)
{
    virtio_bus_reset(&proxy->bus);
    proxy->guest_features = 0;
}

static void virtio_msg_set_device_status(VirtIOMSGProxy *proxy,
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
        virtio_msg_soft_reset(proxy);
    }
}

static void virtio_msg_get_device_status(VirtIOMSGProxy *proxy,
                                         VirtIOMSG *msg,
                                         VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtIOMSG msg_resp;

    virtio_msg_pack_get_device_status_resp(&msg_resp, vdev->status);
    virtio_msg_print(&msg_resp);
    virtio_msg_bus_send(&proxy->msg_bus, &msg_resp, NULL);
}

static void virtio_msg_get_device_conf(VirtIOMSGProxy *proxy,
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

static void virtio_msg_set_device_conf(VirtIOMSGProxy *proxy,
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

static void virtio_msg_get_vqueue(VirtIOMSGProxy *proxy,
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

static void virtio_msg_set_vqueue(VirtIOMSGProxy *proxy,
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

static void virtio_msg_event_avail(VirtIOMSGProxy *proxy,
                                   VirtIOMSG *msg_unused,
                                   VirtIOMSGPayload *mp)
{
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);

    if (!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        VirtIOMSG msg;

        virtio_error(vdev, "Notification while driver not OK?");
        virtio_msg_pack_event_conf(&msg);
        virtio_msg_bus_send(&proxy->msg_bus, &msg, NULL);
        return;
    }
    virtio_queue_notify(vdev, mp->event_avail.index);
}

typedef void (*VirtIOMSGHandler)(VirtIOMSGProxy *proxy,
                                 VirtIOMSG *msg,
                                 VirtIOMSGPayload *mp);

static const VirtIOMSGHandler msg_handlers[VIRTIO_MSG_MAX] = {
    [VIRTIO_MSG_DEVICE_INFO] = virtio_msg_device_info,
    [VIRTIO_MSG_GET_DEVICE_FEAT] = virtio_msg_get_device_feat,
    [VIRTIO_MSG_SET_DEVICE_FEAT] = virtio_msg_set_device_feat,
    [VIRTIO_MSG_GET_DEVICE_STATUS] = virtio_msg_get_device_status,
    [VIRTIO_MSG_SET_DEVICE_STATUS] = virtio_msg_set_device_status,
    [VIRTIO_MSG_GET_DEVICE_CONF] = virtio_msg_get_device_conf,
    [VIRTIO_MSG_SET_DEVICE_CONF] = virtio_msg_set_device_conf,
    [VIRTIO_MSG_GET_VQUEUE] = virtio_msg_get_vqueue,
    [VIRTIO_MSG_SET_VQUEUE] = virtio_msg_set_vqueue,
    [VIRTIO_MSG_EVENT_AVAIL] = virtio_msg_event_avail,
};

static int virtio_msg_receive_msg(VirtIOMSGBusDevice *bd, VirtIOMSG *msg)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(bd->opaque);
    VirtIOMSGHandler handler;

    virtio_msg_print(msg);
    if (msg->id > ARRAY_SIZE(msg_handlers)) {
        return VIRTIO_MSG_ERROR_UNSUPPORTED_MESSAGE_ID;
    }

    handler = msg_handlers[msg->id];
    virtio_msg_unpack(msg);

    if (handler) {
        handler(proxy, msg, &msg->payload);
    }

    return VIRTIO_MSG_NO_ERROR;
}

static const VirtIOMSGBusPort virtio_msg_port = {
    .receive = virtio_msg_receive_msg,
    .is_driver = false
};

static void virtio_msg_notify_queue(DeviceState *opaque, uint16_t index)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(opaque);
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtIOMSG msg;

    if (!vdev || !virtio_msg_bus_connected(&proxy->msg_bus)) {
        return;
    }

    virtio_msg_pack_event_used(&msg, index);
    virtio_msg_bus_send(&proxy->msg_bus, &msg, NULL);
}

static const VMStateDescription vmstate_virtio_msg_state_sub = {
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
        &vmstate_virtio_msg_state_sub,
        NULL
    }
};

static void virtio_msg_save_extra_state(DeviceState *opaque, QEMUFile *f)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(opaque);

    vmstate_save_state(f, &vmstate_virtio_msg, proxy, NULL);
}

static int virtio_msg_load_extra_state(DeviceState *opaque, QEMUFile *f)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(opaque);

    return vmstate_load_state(f, &vmstate_virtio_msg, proxy, 1);
}

static bool virtio_msg_has_extra_state(DeviceState *opaque)
{
    return true;
}

static void virtio_msg_reset_hold(Object *obj, ResetType type)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(obj);
    bool r;

    virtio_msg_soft_reset(proxy);

    r = virtio_msg_bus_connect(&proxy->msg_bus, &virtio_msg_port, proxy);
    if (r) {
        proxy->bus_as = virtio_msg_bus_get_remote_as(&proxy->msg_bus);
    }
}

static void virtio_msg_pre_plugged(DeviceState *d, Error **errp)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(d);
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);

    virtio_add_feature(&vdev->host_features, VIRTIO_F_VERSION_1);
}

static AddressSpace *virtio_msg_get_dma_as(DeviceState *d)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(d);

    return &proxy->dma_as;
}

static Property virtio_msg_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_msg_realize(DeviceState *d, Error **errp)
{
    VirtIOMSGProxy *proxy = VIRTIO_MSG(d);

    qbus_init(&proxy->bus, sizeof(proxy->bus),
              TYPE_VIRTIO_MSG_PROXY_BUS, d, NULL);
    qbus_init(&proxy->msg_bus, sizeof(proxy->msg_bus),
              TYPE_VIRTIO_MSG_BUS, d, NULL);

    memory_region_init_iommu(&proxy->mr_iommu, sizeof(proxy->mr_iommu),
                             TYPE_VIRTIO_MSG_IOMMU_MEMORY_REGION,
                             OBJECT(d), "virtio-msg-iommu", UINT64_MAX);
    address_space_init(&proxy->dma_as, MEMORY_REGION(&proxy->mr_iommu), "dma");
}

static void virtio_msg_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    dc->realize = virtio_msg_realize;
    dc->user_creatable = true;
    rc->phases.hold  = virtio_msg_reset_hold;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, virtio_msg_properties);
}

static const TypeInfo virtio_msg_info = {
    .name          = TYPE_VIRTIO_MSG,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(VirtIOMSGProxy),
    .class_init    = virtio_msg_class_init,
};

#define VIRTIO_MSG_PAGE_SIZE (4 * KiB)

static IOMMUTLBEntry virtio_msg_iommu_translate(IOMMUMemoryRegion *iommu,
                                                hwaddr addr,
                                                IOMMUAccessFlags flags,
                                                int iommu_idx)
{
    VirtIOMSGProxy *s = VIRTIO_MSG(container_of(iommu,
                                                VirtIOMSGProxy, mr_iommu));

    IOMMUTLBEntry ret = {
        .iova = addr & ~(VIRTIO_MSG_PAGE_SIZE - 1),
        .translated_addr = addr & ~(VIRTIO_MSG_PAGE_SIZE - 1),
        .addr_mask = VIRTIO_MSG_PAGE_SIZE - 1,
        .perm = IOMMU_RW,
        .target_as = s->bus_as,
    };

    printf("%s: addr 0x%lx\n", __func__, addr);
    return ret;
}

static char *virtio_msg_bus_get_dev_path(DeviceState *dev)
{
    BusState *virtio_msg_bus;
    VirtIOMSGProxy *virtio_msg_proxy;
    char *proxy_path;

    virtio_msg_bus = qdev_get_parent_bus(dev);
    virtio_msg_proxy = VIRTIO_MSG(virtio_msg_bus->parent);
    proxy_path = qdev_get_dev_path(DEVICE(virtio_msg_proxy));

    return proxy_path;
}

static void virtio_msg_bus_class_init(ObjectClass *klass, void *data)
{
    BusClass *bus_class = BUS_CLASS(klass);
    VirtioBusClass *k = VIRTIO_BUS_CLASS(klass);

    k->notify_queue = virtio_msg_notify_queue;
    k->save_extra_state = virtio_msg_save_extra_state;
    k->load_extra_state = virtio_msg_load_extra_state;
    k->has_extra_state = virtio_msg_has_extra_state;
    k->pre_plugged = virtio_msg_pre_plugged;
    k->has_variable_vring_alignment = true;
    k->get_dma_as = virtio_msg_get_dma_as;
    bus_class->max_dev = 1;
    bus_class->get_dev_path = virtio_msg_bus_get_dev_path;
}

static const TypeInfo virtio_msg_bus_info = {
    .name          = TYPE_VIRTIO_MSG_PROXY_BUS,
    .parent        = TYPE_VIRTIO_BUS,
    .instance_size = sizeof(VirtioBusState),
    .class_init    = virtio_msg_bus_class_init,
};

static void virtio_msg_iommu_memory_region_class_init(ObjectClass *klass,
                                                      void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = virtio_msg_iommu_translate;
}

static const TypeInfo virtio_msg_iommu_info = {
    .name = TYPE_VIRTIO_MSG_IOMMU_MEMORY_REGION,
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .class_init = virtio_msg_iommu_memory_region_class_init,
};

static void virtio_msg_register_types(void)
{
    type_register_static(&virtio_msg_iommu_info);
    type_register_static(&virtio_msg_bus_info);
    type_register_static(&virtio_msg_info);
}

type_init(virtio_msg_register_types)
