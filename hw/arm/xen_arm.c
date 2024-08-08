/*
 * QEMU ARM Xen PVH Machine
 *
 * SPDX-License-Identifier: MIT
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/qapi-commands-migration.h"
#include "qapi/visitor.h"
#include "hw/boards.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "sysemu/block-backend.h"
#include "sysemu/sysemu.h"
#include "hw/xen/xen-pvh-common.h"
#include "sysemu/tpm.h"
#include "hw/xen/arch_hvm.h"

#define TYPE_XEN_ARM  MACHINE_TYPE_NAME("xenpvh")
OBJECT_DECLARE_SIMPLE_TYPE(XenArmState, XEN_ARM)

struct XenArmState {
    /*< private >*/
    MachineState parent;

    XenPVHCommonState pvh;

    struct {
        uint64_t tpm_base_addr;
    } cfg;
};

/*
 * VIRTIO_MMIO_DEV_SIZE is imported from tools/libs/light/libxl_arm.c under Xen
 * repository.
 *
 * Origin: git://xenbits.xen.org/xen.git 2128143c114c
 */
#define VIRTIO_MMIO_DEV_SIZE   0x200

#define NR_VIRTIO_MMIO_DEVICES   \
   (GUEST_VIRTIO_MMIO_SPI_LAST - GUEST_VIRTIO_MMIO_SPI_FIRST)

void arch_handle_ioreq(XenIOState *state, ioreq_t *req)
{
    hw_error("Invalid ioreq type 0x%x\n", req->type);

    return;
}

void arch_xen_set_memory(XenIOState *state, MemoryRegionSection *section,
                         bool add)
{
}

void xen_hvm_modified_memory(ram_addr_t start, ram_addr_t length)
{
}

void qmp_xen_set_global_dirty_log(bool enable, Error **errp)
{
}

static void xen_arm_init(MachineState *ms)
{
    XenArmState *xam = XEN_ARM(ms);
    const struct {
        const char *name;
        MemMapEntry map;
    } map[] = {
        { "ram-low", { GUEST_RAM0_BASE, GUEST_RAM0_SIZE } },
        { "ram-high", { GUEST_RAM1_BASE, GUEST_RAM1_SIZE } },
        { "virtio-mmio", { GUEST_VIRTIO_MMIO_BASE, VIRTIO_MMIO_DEV_SIZE } },
        { "tpm", { xam->cfg.tpm_base_addr, 0x1000 } },
    };
    int i;

    object_initialize_child(OBJECT(ms), "pvh", &xam->pvh, TYPE_XEN_PVH_COMMON);

    object_property_set_int(OBJECT(&xam->pvh), "max-cpus", ms->smp.max_cpus,
                            &error_abort);
    object_property_set_int(OBJECT(&xam->pvh), "ram-size", ms->ram_size,
                            &error_abort);
    object_property_set_int(OBJECT(&xam->pvh), "virtio-mmio-num",
                            NR_VIRTIO_MMIO_DEVICES, &error_abort);
    object_property_set_int(OBJECT(&xam->pvh), "virtio-mmio-irq-base",
                            GUEST_VIRTIO_MMIO_SPI_FIRST, &error_abort);

    for (i = 0; i < ARRAY_SIZE(map); i++) {
        g_autofree char *base_name = g_strdup_printf("%s-base", map[i].name);
        g_autofree char *size_name = g_strdup_printf("%s-size", map[i].name);

        object_property_set_int(OBJECT(&xam->pvh), base_name, map[i].map.base,
                                &error_abort);
        object_property_set_int(OBJECT(&xam->pvh), size_name, map[i].map.size,
                                &error_abort);
    }

    sysbus_realize(SYS_BUS_DEVICE(&xam->pvh), &error_abort);
}

#ifdef CONFIG_TPM
static void xen_arm_get_tpm_base_addr(Object *obj, Visitor *v,
                                      const char *name, void *opaque,
                                      Error **errp)
{
    XenArmState *xam = XEN_ARM(obj);
    uint64_t value = xam->cfg.tpm_base_addr;

    visit_type_uint64(v, name, &value, errp);
}

static void xen_arm_set_tpm_base_addr(Object *obj, Visitor *v,
                                      const char *name, void *opaque,
                                      Error **errp)
{
    XenArmState *xam = XEN_ARM(obj);
    uint64_t value;

    if (!visit_type_uint64(v, name, &value, errp)) {
        return;
    }

    xam->cfg.tpm_base_addr = value;
}
#endif

static void xen_arm_machine_class_init(ObjectClass *oc, void *data)
{

    MachineClass *mc = MACHINE_CLASS(oc);
    mc->desc = "Xen PVH ARM machine";
    mc->init = xen_arm_init;
    /* MAX number of vcpus supported by Xen.  */
    mc->max_cpus = GUEST_MAX_VCPUS;
    mc->default_machine_opts = "accel=xen";
    /* Set explicitly here to make sure that real ram_size is passed */
    mc->default_ram_size = 0;

#ifdef CONFIG_TPM
    object_class_property_add(oc, "tpm-base-addr", "uint64_t",
                              xen_arm_get_tpm_base_addr,
                              xen_arm_set_tpm_base_addr,
                              NULL, NULL);
    object_class_property_set_description(oc, "tpm-base-addr",
                                          "Set Base address for TPM device.");

    machine_class_allow_dynamic_sysbus_dev(mc, TYPE_TPM_TIS_SYSBUS);
#endif
}

static const TypeInfo xen_arm_machine_type = {
    .name = TYPE_XEN_ARM,
    .parent = TYPE_MACHINE,
    .class_init = xen_arm_machine_class_init,
    .instance_size = sizeof(XenArmState),
};

static void xen_arm_machine_register_types(void)
{
    type_register_static(&xen_arm_machine_type);
}

type_init(xen_arm_machine_register_types)
