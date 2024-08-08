/*
 * Common Xen PVH code.
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "sysemu/sysemu.h"
#include "sysemu/tpm.h"
#include "sysemu/tpm_backend.h"
#include "hw/xen/xen-pvh-common.h"
#include "trace.h"

static const MemoryListener xen_memory_listener = {
    .region_add = xen_region_add,
    .region_del = xen_region_del,
    .log_start = NULL,
    .log_stop = NULL,
    .log_sync = NULL,
    .log_global_start = NULL,
    .log_global_stop = NULL,
    .priority = MEMORY_LISTENER_PRIORITY_ACCEL,
};

static void xen_pvh_init_ram(XenPVHCommonState *s,
                             MemoryRegion *sysmem)
{
    ram_addr_t block_len, ram_size[2];

    if (s->cfg.ram_size <= s->cfg.ram_low.size) {
        ram_size[0] = s->cfg.ram_size;
        ram_size[1] = 0;
        block_len = s->cfg.ram_low.base + ram_size[0];
    } else {
        ram_size[0] = s->cfg.ram_low.size;
        ram_size[1] = s->cfg.ram_size - s->cfg.ram_low.size;
        block_len = s->cfg.ram_high.base + ram_size[1];
    }

    memory_region_init_ram(&xen_memory, NULL, "xen.ram", block_len,
                           &error_fatal);

    memory_region_init_alias(&s->ram.low, NULL, "xen.ram.lo", &xen_memory,
                             s->cfg.ram_low.base, ram_size[0]);
    memory_region_add_subregion(sysmem, s->cfg.ram_low.base, &s->ram.low);
    if (ram_size[1] > 0) {
        memory_region_init_alias(&s->ram.high, NULL, "xen.ram.hi", &xen_memory,
                                 s->cfg.ram_high.base, ram_size[1]);
        memory_region_add_subregion(sysmem, s->cfg.ram_high.base, &s->ram.high);
    }

    /* Setup support for grants.  */
    memory_region_init_ram(&xen_grants, NULL, "xen.grants", block_len,
                           &error_fatal);
    memory_region_add_subregion(sysmem, XEN_GRANT_ADDR_OFF, &xen_grants);
}

static void xen_set_irq(void *opaque, int irq, int level)
{
    if (xendevicemodel_set_irq_level(xen_dmod, xen_domid, irq, level)) {
        error_report("xendevicemodel_set_irq_level failed");
    }
}

static void xen_create_virtio_mmio_devices(XenPVHCommonState *s)
{
    int i;

    for (i = 0; i < s->cfg.virtio_mmio_num; i++) {
        hwaddr base = s->cfg.virtio_mmio.base + i * s->cfg.virtio_mmio.size;
        qemu_irq irq = qemu_allocate_irq(xen_set_irq, NULL,
                                         s->cfg.virtio_mmio_irq_base + i);

        sysbus_create_simple("virtio-mmio", base, irq);

        trace_xen_create_virtio_mmio_devices(i,
                                             s->cfg.virtio_mmio_irq_base + i,
                                             base);
    }
}

#ifdef CONFIG_TPM
static void xen_enable_tpm(XenPVHCommonState *s)
{
    Error *errp = NULL;
    DeviceState *dev;
    SysBusDevice *busdev;

    TPMBackend *be = qemu_find_tpm_be("tpm0");
    if (be == NULL) {
        error_report("Couldn't find tmp0 backend");
        return;
    }
    dev = qdev_new(TYPE_TPM_TIS_SYSBUS);
    object_property_set_link(OBJECT(dev), "tpmdev", OBJECT(be), &errp);
    object_property_set_str(OBJECT(dev), "tpmdev", be->id, &errp);
    busdev = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(busdev, &error_fatal);
    sysbus_mmio_map(busdev, 0, s->cfg.tpm.base);

    trace_xen_enable_tpm(s->cfg.tpm.base);
}
#endif

static void xen_pvh_realize(DeviceState *dev, Error **errp)
{
    XenPVHCommonState *s = XEN_PVH_COMMON(dev);
    MemoryRegion *sysmem = get_system_memory();

    if (s->cfg.ram_size == 0) {
        /* FIXME: Prefix with object path and consider bailing out.  */
        warn_report("non-zero ram size not specified. QEMU machine started"
                    " without IOREQ (no emulated devices including virtio)");
        return;
    }

    if (s->cfg.max_cpus == 0) {
        /* FIXME: Prefix with object path and bail out.  */
        warn_report("max-cpus not specified. QEMU machine started");
        return;
    }

    xen_pvh_init_ram(s, sysmem);
    xen_register_ioreq(&s->ioreq, s->cfg.max_cpus, &xen_memory_listener);

    if (s->cfg.virtio_mmio_num) {
        xen_create_virtio_mmio_devices(s);
    }

#ifdef CONFIG_TPM
    if (s->cfg.tpm.base) {
        xen_enable_tpm(s);
    } else {
        warn_report("tpm-base-addr is not provided. TPM will not be enabled");
    }
#endif
}

#define DEFINE_PROP_MEMMAP(n, f) \
    DEFINE_PROP_UINT64(n "-base", XenPVHCommonState, cfg.f.base, 0), \
    DEFINE_PROP_UINT64(n "-size", XenPVHCommonState, cfg.f.size, 0)

static Property xen_pvh_properties[] = {
    DEFINE_PROP_UINT32("max-cpus", XenPVHCommonState, cfg.max_cpus, 0),
    DEFINE_PROP_UINT64("ram-size", XenPVHCommonState, cfg.ram_size, 0),
    DEFINE_PROP_MEMMAP("ram-low", ram_low),
    DEFINE_PROP_MEMMAP("ram-high", ram_high),
    DEFINE_PROP_MEMMAP("virtio-mmio", virtio_mmio),
    DEFINE_PROP_MEMMAP("tpm", tpm),
    DEFINE_PROP_UINT32("virtio-mmio-num", XenPVHCommonState,
                       cfg.virtio_mmio_num, 0),
    DEFINE_PROP_UINT32("virtio-mmio-irq-base", XenPVHCommonState,
                       cfg.virtio_mmio_irq_base, 0),
    DEFINE_PROP_END_OF_LIST()
};

static void xen_pvh_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = xen_pvh_realize;
    device_class_set_props(dc, xen_pvh_properties);
    /* No VMSD since we haven't got any top-level SoC state to save.  */
}

static const TypeInfo xen_pvh_info = {
    .name = TYPE_XEN_PVH_COMMON,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(XenPVHCommonState),
    .class_init = xen_pvh_class_init,
};

static void xen_pvh_register_types(void)
{
    type_register_static(&xen_pvh_info);
}

type_init(xen_pvh_register_types);
