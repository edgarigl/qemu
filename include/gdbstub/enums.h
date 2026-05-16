/*
 * gdbstub enums
 *
 * Copyright (c) 2024 Linaro Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef GDBSTUB_ENUMS_H
#define GDBSTUB_ENUMS_H

#define DEFAULT_GDBSTUB_PORT "1234"

/* GDB breakpoint/watchpoint types */
#define GDB_BREAKPOINT_SW        0
#define GDB_BREAKPOINT_HW        1
#define GDB_WATCHPOINT_WRITE     2
#define GDB_WATCHPOINT_READ      3
#define GDB_WATCHPOINT_ACCESS    4

/*
 * QEMU vendor flag.  ORed onto GDB_WATCHPOINT_* by the qemu.PhyWatch
 * packets to request a watchpoint keyed on guest physical addresses.
 */
#define GDB_PHY_WATCHPOINT_FLAG  0x10
#define GDB_TYPE_PHYS(t)         ((t) & GDB_PHY_WATCHPOINT_FLAG)
#define GDB_TYPE_BASE(t)         ((t) & ~GDB_PHY_WATCHPOINT_FLAG)

#endif /* GDBSTUB_ENUMS_H */
