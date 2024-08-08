/*
 * QEMU Xen PVH x86 Machine
 *
 * Copyright (c) 2024 Advanced Micro Devices, Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/error-report.h"
#include "hw/boards.h"
#include "sysemu/sysemu.h"
#include "hw/xen/arch_hvm.h"
#include "hw/xen/xen.h"
#include "hw/xen/xen-pvh-common.h"

#define TYPE_XEN_PVH_X86  MACHINE_TYPE_NAME("xenpvh")
OBJECT_DECLARE_SIMPLE_TYPE(XenPVHx86State, XEN_PVH_X86)

#define PVH_MAX_CPUS 128

struct XenPVHx86State {
    /*< private >*/
    MachineState parent;

    DeviceState *cpu[PVH_MAX_CPUS];
    XenPVHCommonState pvh;

    /*
     * We provide these properties to allow Xen to move things to other
     * addresses for example when users need to accomodate the memory-map
     * for 1:1 mapped devices/memory.
     */
    struct {
        MemMapEntry ram_low, ram_high;
        MemMapEntry pci_ecam, pci_mmio, pci_mmio_high;
    } cfg;
};

static void xenpvh_cpu_new(MachineState *ms,
                           XenPVHx86State *xp,
                           int cpu_idx,
                           int64_t apic_id)
{
    Object *cpu = object_new(ms->cpu_type);

    object_property_add_child(OBJECT(ms), "cpu[*]", cpu);
    object_property_set_uint(cpu, "apic-id", apic_id, &error_fatal);
    qdev_realize(DEVICE(cpu), NULL, &error_fatal);
    object_unref(cpu);

    xp->cpu[cpu_idx] = DEVICE(cpu);
}

static void xenpvh_init(MachineState *ms)
{
    XenPVHx86State *xp = XEN_PVH_X86(ms);
    const struct {
        const char *name;
        MemMapEntry *map;
    } map[] = {
        { "ram-low", &xp->cfg.ram_low },
        { "ram-high", &xp->cfg.ram_high },
        { "pci-ecam", &xp->cfg.pci_ecam },
        { "pci-mmio", &xp->cfg.pci_mmio },
        { "pci-mmio-high", &xp->cfg.pci_mmio_high },
    };
    int i;

    object_initialize_child(OBJECT(ms), "pvh", &xp->pvh, TYPE_XEN_PVH_COMMON);
    object_property_set_int(OBJECT(&xp->pvh), "max-cpus", ms->smp.max_cpus,
                            &error_abort);
    object_property_set_int(OBJECT(&xp->pvh), "ram-size", ms->ram_size,
                            &error_abort);

    for (i = 0; i < ARRAY_SIZE(map); i++) {
        g_autofree char *base_name = g_strdup_printf("%s-base", map[i].name);
        g_autofree char *size_name = g_strdup_printf("%s-size", map[i].name);

        object_property_set_int(OBJECT(&xp->pvh), base_name, map[i].map->base,
                                 &error_abort);
        object_property_set_int(OBJECT(&xp->pvh), size_name, map[i].map->size,
                                 &error_abort);
    }

    /* GSI's 16 - 20 are used for legacy PCIe INTX IRQs.  */
    object_property_set_int(OBJECT(&xp->pvh), "pci-intx-irq-base", 16,
                            &error_abort);

    sysbus_realize(SYS_BUS_DEVICE(&xp->pvh), &error_abort);

    /* Create dummy cores. This will indirectly create the APIC MSI window.  */
    for (i = 0; i < ms->smp.cpus; i++) {
        xenpvh_cpu_new(ms, xp, i, i);
    }
}

#define XENPVH_PROP_MEMMAP_SETTER(n, f)                                    \
static void xenpvh_set_ ## n ## _ ## f(Object *obj, Visitor *v,            \
                                       const char *name, void *opaque,     \
                                       Error **errp)                       \
{                                                                          \
    XenPVHx86State *xp = XEN_PVH_X86(obj);                                 \
    uint64_t value;                                                        \
                                                                           \
    if (!visit_type_size(v, name, &value, errp)) {                         \
        return;                                                            \
    }                                                                      \
    xp->cfg.n.f = value;                                                   \
}

#define XENPVH_PROP_MEMMAP_GETTER(n, f)                                    \
static void xenpvh_get_ ## n ## _ ## f(Object *obj, Visitor *v,            \
                                       const char *name, void *opaque,     \
                                       Error **errp)                       \
{                                                                          \
    XenPVHx86State *xp = XEN_PVH_X86(obj);                                 \
    uint64_t value = xp->cfg.n.f;                                          \
                                                                           \
    visit_type_uint64(v, name, &value, errp);                              \
}

#define XENPVH_PROP_MEMMAP(n)              \
    XENPVH_PROP_MEMMAP_SETTER(n, base)     \
    XENPVH_PROP_MEMMAP_SETTER(n, size)     \
    XENPVH_PROP_MEMMAP_GETTER(n, base)     \
    XENPVH_PROP_MEMMAP_GETTER(n, size)


XENPVH_PROP_MEMMAP(ram_low)
XENPVH_PROP_MEMMAP(ram_high)
XENPVH_PROP_MEMMAP(pci_ecam)
XENPVH_PROP_MEMMAP(pci_mmio)
XENPVH_PROP_MEMMAP(pci_mmio_high)

static void xenpvh_instance_init(Object *obj)
{
    XenPVHx86State *xp = XEN_PVH_X86(obj);

    /* Default memmap.  */
    xp->cfg.ram_low.base = 0x0;
    xp->cfg.ram_low.size = 0x80000000U;
    xp->cfg.ram_high.base = 0xC000000000ULL;
    xp->cfg.ram_high.size = 0x4000000000ULL;
}

static void xenpvh_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Xen PVH x86 machine";
    mc->init = xenpvh_init;
    mc->max_cpus = PVH_MAX_CPUS;
    mc->default_cpu_type = TARGET_DEFAULT_CPU_TYPE;
    mc->default_machine_opts = "accel=xen";
    /* Set explicitly here to make sure that real ram_size is passed */
    mc->default_ram_size = 0;

#define OC_MEMMAP_PROP(c, prop_name, name)                               \
do {                                                                     \
    object_class_property_add(c, prop_name "-base", "uint64_t",          \
                              xenpvh_get_ ## name ## _base,              \
                              xenpvh_set_ ## name ## _base, NULL, NULL); \
    object_class_property_set_description(oc, prop_name "-base",         \
                              prop_name " base address");                \
    object_class_property_add(c, prop_name "-size", "uint64_t",          \
                              xenpvh_get_ ## name ## _size,              \
                              xenpvh_set_ ## name ## _size, NULL, NULL); \
    object_class_property_set_description(oc, prop_name "-size",         \
                              prop_name " size of memory region");       \
} while (0)

    OC_MEMMAP_PROP(oc, "ram-low", ram_low);
    OC_MEMMAP_PROP(oc, "ram-high", ram_high);
    OC_MEMMAP_PROP(oc, "pci-ecam", pci_ecam);
    OC_MEMMAP_PROP(oc, "pci-mmio", pci_mmio);
    OC_MEMMAP_PROP(oc, "pci-mmio-high", pci_mmio_high);
}

static const TypeInfo xenpvh_machine_type = {
    .name = TYPE_XEN_PVH_X86,
    .parent = TYPE_MACHINE,
    .class_init = xenpvh_machine_class_init,
    .instance_init = xenpvh_instance_init,
    .instance_size = sizeof(XenPVHx86State),
};

static void xenpvh_machine_register_types(void)
{
    type_register_static(&xenpvh_machine_type);
}

type_init(xenpvh_machine_register_types)
