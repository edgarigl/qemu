/*
 * ARM physical SError delivery helpers.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_SERROR_H
#define HW_ARM_SERROR_H

#include "hw/core/cpu.h"

void arm_cpu_set_serror(CPUState *cs, uint64_t esr, bool has_esr);

#endif
