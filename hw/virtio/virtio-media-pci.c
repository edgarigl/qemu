/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Virtio media PCI device
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/pci/pci.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-media.h"
#include "qom/object.h"

typedef struct VirtIOMediaPCI VirtIOMediaPCI;

#define TYPE_VIRTIO_MEDIA_PCI "virtio-media-pci"
DECLARE_INSTANCE_CHECKER(VirtIOMediaPCI, VIRTIO_MEDIA_PCI,
                         TYPE_VIRTIO_MEDIA_PCI)

struct VirtIOMediaPCI {
    VirtIOPCIProxy parent_obj;
    VirtIOMedia vdev;
};

static void vmedia_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOMediaPCI *dev = VIRTIO_MEDIA_PCI(vpci_dev);
    VirtIOMedia *mdev = &dev->vdev;
    DeviceState *vdev = DEVICE(mdev);

    vpci_dev->msix_bar_idx = 1;
    vpci_dev->modern_mem_bar_idx = 2;
    /*
     * Default to one MSI-X vector per virtqueue (commandq + eventq) plus one
     * for the config change interrupt. Without MSI-X the device falls back to
     * legacy INTx, whose emulated IO-APIC EOI round-trip under Xen adds
     * milliseconds of latency to every command.
     */
    if (vpci_dev->nvectors == DEV_NVECTORS_UNSPECIFIED) {
        vpci_dev->nvectors = 3;
    }
    virtio_pci_force_virtio_1(vpci_dev);

    if (!qdev_realize(vdev, BUS(&vpci_dev->bus), errp)) {
        return;
    }

    if (!mdev->use_grefs) {
        pci_register_bar(&vpci_dev->pci_dev, 4,
                         PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_PREFETCH |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                         &mdev->hostmem);
        virtio_pci_add_shm_cap(vpci_dev, 4, 0, mdev->hostmem_size, 0);
    }
}

static void vmedia_initfn(Object *obj)
{
    VirtIOMediaPCI *dev = VIRTIO_MEDIA_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_MEDIA);
}

static const Property vmedia_pci_properties[] = {
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors,
                       DEV_NVECTORS_UNSPECIFIED),
};

static void vmedia_pci_class_init(ObjectClass *klass, const void *data)
{
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    k->realize = vmedia_pci_realize;
    pcidev_k->class_id = PCI_CLASS_MULTIMEDIA_VIDEO;
    device_class_set_props(dc, vmedia_pci_properties);
}

static const VirtioPCIDeviceTypeInfo virtio_media_pci_info = {
    .generic_name = TYPE_VIRTIO_MEDIA_PCI,
    .parent = TYPE_VIRTIO_PCI,
    .instance_size = sizeof(VirtIOMediaPCI),
    .instance_init = vmedia_initfn,
    .class_init = vmedia_pci_class_init,
};

static void vmedia_pci_register_types(void)
{
    virtio_pci_types_register(&virtio_media_pci_info);
}

type_init(vmedia_pci_register_types)
