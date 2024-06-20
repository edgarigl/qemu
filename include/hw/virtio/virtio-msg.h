#ifndef HW_VIRTIO_MSG_PROXY_BACKEND_H
#define HW_VIRTIO_MSG_PROXY_BACKEND_H

#include "hw/sysbus.h"
#include "hw/virtio/virtio-bus.h"

#define TYPE_VIRTIO_MSG_PROXY_BUS "virtio-msg-proxy-bus"
/* This is reusing the VirtioBusState typedef from TYPE_VIRTIO_BUS */
DECLARE_OBJ_CHECKERS(VirtioBusState, VirtioBusClass,
                     VIRTIO_MSG_PROXY_BUS, TYPE_VIRTIO_MSG_PROXY_BUS)

#define TYPE_VIRTIO_MSG "virtio-msg"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGProxy, VIRTIO_MSG)

struct VirtIOMSGProxy {
    SysBusDevice parent_obj;

    /* virtio-bus */
    VirtioBusState bus;
    /* virtio-msg-bus.  */
    BusState msg_bus;

    /* Fields only used for non-legacy (v2) devices */
    uint64_t guest_features;
};
#endif
