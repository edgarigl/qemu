/*
 * QEMU ARM Xen PVH Machine
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/qapi-commands-migration.h"
#include "qapi/visitor.h"
#include "hw/boards.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "sysemu/block-backend.h"
#include "sysemu/tpm_backend.h"
#include "sysemu/sysemu.h"
#include "hw/xen/xen-pvh-common.h"
#include "sysemu/tpm.h"
#include "hw/xen/arch_hvm.h"
#include "trace.h"

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

static void xen_set_irq(void *opaque, int irq, int level)
{
    if (xendevicemodel_set_irq_level(xen_dmod, xen_domid, irq, level)) {
        error_report("xendevicemodel_set_irq_level failed");
    }
}

static void xen_create_virtio_mmio_devices(XenArmState *xam)
{
    int i;

    for (i = 0; i < NR_VIRTIO_MMIO_DEVICES; i++) {
        hwaddr base = GUEST_VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_DEV_SIZE;
        qemu_irq irq = qemu_allocate_irq(xen_set_irq, NULL,
                                         GUEST_VIRTIO_MMIO_SPI_FIRST + i);

        sysbus_create_simple("virtio-mmio", base, irq);

        trace_xen_create_virtio_mmio_devices(i,
                                             GUEST_VIRTIO_MMIO_SPI_FIRST + i,
                                             base);
    }
}

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

#ifdef CONFIG_TPM
static void xen_enable_tpm(XenArmState *xam)
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
    sysbus_mmio_map(busdev, 0, xam->cfg.tpm_base_addr);

    trace_xen_enable_tpm(xam->cfg.tpm_base_addr);
}
#endif

static void xen_arm_init(MachineState *machine)
{
    MemoryRegion *sysmem = get_system_memory();
    XenArmState *xam = XEN_ARM(machine);

    xam->pvh.cfg.ram_low.base = GUEST_RAM0_BASE;
    xam->pvh.cfg.ram_low.size = GUEST_RAM0_SIZE;
    xam->pvh.cfg.ram_high.base = GUEST_RAM1_BASE;
    xam->pvh.cfg.ram_high.size = GUEST_RAM1_SIZE;

    xen_pvh_common_init(machine, &xam->pvh, sysmem);
    xen_create_virtio_mmio_devices(xam);

#ifdef CONFIG_TPM
    if (xam->cfg.tpm_base_addr) {
        xen_enable_tpm(xam);
    } else {
        warn_report("tpm-base-addr is not provided. TPM will not be enabled");
    }
#endif
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
    mc->desc = "Xen Para-virtualized PC";
    mc->init = xen_arm_init;
    mc->max_cpus = 1;
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
