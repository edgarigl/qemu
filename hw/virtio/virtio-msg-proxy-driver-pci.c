/*
 * Virtio msg driver PCI Bindings
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-msg-proxy-driver.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qom/object.h"

typedef struct VirtIOMSGProxyDriverPCI VirtIOMSGProxyDriverPCI;

#define TYPE_VIRTIO_MSG_PROXY_DRIVER_PCI "virtio-msg-proxy-driver-base"
DECLARE_INSTANCE_CHECKER(VirtIOMSGProxyDriverPCI, VIRTIO_MSG_PROXY_DRIVER_PCI,
                         TYPE_VIRTIO_MSG_PROXY_DRIVER_PCI)

struct VirtIOMSGProxyDriverPCI {
    VirtIOPCIProxy parent_obj;
    VirtIOMSGProxyDriver vdev;
};

static const Property virtio_mpd_properties[] = {
    DEFINE_PROP_BIT("ioeventfd", VirtIOPCIProxy, flags,
                    VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors,
                       DEV_NVECTORS_UNSPECIFIED),
};

static void virtio_mpd_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOMSGProxyDriverPCI *vrng = VIRTIO_MSG_PROXY_DRIVER_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&vrng->vdev);

    if (vpci_dev->nvectors == DEV_NVECTORS_UNSPECIFIED) {
        vpci_dev->nvectors = 2;
    }

    if (!qdev_realize(vdev, BUS(&vpci_dev->bus), errp)) {
        return;
    }
}

static void virtio_mpd_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    k->realize = virtio_mpd_pci_realize;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    pcidev_k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    /* FIXME!!!! */
    pcidev_k->device_id = PCI_DEVICE_ID_VIRTIO_NET;
    pcidev_k->revision = VIRTIO_PCI_ABI_VERSION;
    pcidev_k->class_id = PCI_CLASS_OTHERS;
    device_class_set_props(dc, virtio_mpd_properties);
}

static void virtio_mpd_initfn(Object *obj)
{
    VirtIOMSGProxyDriverPCI *dev = VIRTIO_MSG_PROXY_DRIVER_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_MSG_PROXY_DRIVER);
}

static const VirtioPCIDeviceTypeInfo virtio_mpd_pci_info = {
    .base_name             = TYPE_VIRTIO_MSG_PROXY_DRIVER_PCI,
    .generic_name          = "virtio-msg-proxy-driver-pci",
    .transitional_name     = "virtio-msg-proxy-driver-pci-transitional",
    .non_transitional_name = "virtio-msg-proxy-driver-pci-non-transitional",
    .instance_size = sizeof(VirtIOMSGProxyDriverPCI),
    .instance_init = virtio_mpd_initfn,
    .class_init    = virtio_mpd_pci_class_init,
};

static void virtio_mpd_pci_register(void)
{
    virtio_pci_types_register(&virtio_mpd_pci_info);
}

type_init(virtio_mpd_pci_register)
