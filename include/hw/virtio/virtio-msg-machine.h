#ifndef HW_VIRTIO_VIRTIO_MSG_MACHINE_H
#define HW_VIRTIO_VIRTIO_MSG_MACHINE_H

#include "qom/object.h"
#include "hw/boards.h"
#include "hw/virtio/virtio-msg.h"

#define TYPE_VIRTIO_MSG_SYSBUS_DEV "virtio-msg-sysbus-dev"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGSysBusDev, VIRTIO_MSG_SYSBUS_DEV)

struct VirtIOMSGSysBusDev {
    SysBusDevice parent_obj;

    BusState bus;
    VirtIOMSGProxy dev;
};

struct VirtIOMSGMachineState {
    MachineState parent_obj;

    struct {
        VirtIOMSGSysBusDev dev;
    } backends[1];
};

#define TYPE_VIRTIO_MSG_MACHINE "x-virtio-msg-machine"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGMachineState, VIRTIO_MSG_MACHINE)
#endif
