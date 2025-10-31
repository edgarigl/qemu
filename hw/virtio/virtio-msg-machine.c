#include "qemu/osdep.h"

#include "exec/memory.h"
#include "qapi/error.h"
#include "hw/qdev-core.h"
#include "sysemu/dma.h"
#include "hw/virtio/virtio-msg-machine.h"

static void virtio_msg_machine_init(MachineState *machine)
{
    VirtIOMSGMachineState *s = VIRTIO_MSG_MACHINE(machine);
    int i;

    for (i = 0; i < ARRAY_SIZE(s->backends); i++) {
        g_autofree char *name = g_strdup_printf("backend%d", i);

        object_initialize_child(OBJECT(s), "dev", &s->backends[i].dev,
                                TYPE_VIRTIO_MSG_SYSBUS_DEV);
        sysbus_realize(SYS_BUS_DEVICE(&s->backends[i].dev), &error_fatal);
    }
}

static void virtio_msg_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->init = virtio_msg_machine_init;
    mc->desc = "Experimental virtio-msg machine";
}

static const TypeInfo virtio_msg_machine = {
    .name = TYPE_VIRTIO_MSG_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(VirtIOMSGMachineState),
    .class_init = virtio_msg_machine_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_HOTPLUG_HANDLER },
        { }
    }
};

static void virtio_msg_machine_register_types(void)
{
    type_register_static(&virtio_msg_machine);
}

type_init(virtio_msg_machine_register_types);
