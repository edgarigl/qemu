#ifndef HW_VIRTIO_VIRTIO_MSG_MACHINE_H
#define HW_VIRTIO_VIRTIO_MSG_MACHINE_H

#include "qom/object.h"
#include "hw/boards.h"
#include "hw/virtio/virtio-msg.h"

struct VirtIOMSGMachineState {
    MachineState parent_obj;

    BusState bus;
    VirtIOMSGProxy backends[4];
};

#define TYPE_VIRTIO_MSG_MACHINE "x-virtio-msg-machine"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOMSGMachineState, VIRTIO_MSG_MACHINE)
#endif
