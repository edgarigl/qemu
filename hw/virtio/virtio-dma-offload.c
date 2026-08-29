/*
 * Offload for bulk reads out of a transport's remote address space.
 *
 * See include/hw/virtio/virtio-dma-offload.h for what this is for.  All that
 * lives here is the registry, which is a hash table keyed by AddressSpace
 * rather than a field on one because AddressSpace is core memory-API state
 * and this is a property of the transport that happens to own it.
 *
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "hw/virtio/virtio-dma-offload.h"

/*
 * Not locked, and the reason is narrower than it first looks.  Lookup is *not*
 * confined to the BQL -- virtio-blk calls it per request from its iothread, so
 * several threads read this table concurrently.  Concurrent readers are fine;
 * a reader running while the table is mutated would not be, because an insert
 * may rehash.
 *
 * The invariant is therefore that mutation happens only while no dataplane can
 * be looking.  That holds today because the sole registrant is a transport
 * which registers at its own realize -- before any device on it exists -- and
 * unregisters at unrealize.  The assertions below check the part that is cheap
 * to check, and would catch a future registrant mutating from an iothread.  A
 * transport that could come or go while devices are running needs this table
 * made RCU, not merely BQL-locked.
 */
static GHashTable *virtio_dma_offloads;

void virtio_dma_offload_register(AddressSpace *as, const VirtIODMAOffload *o)
{
    assert(bql_locked());

    if (!virtio_dma_offloads) {
        virtio_dma_offloads = g_hash_table_new(NULL, NULL);
    }

    g_hash_table_insert(virtio_dma_offloads, as, (gpointer)o);
}

void virtio_dma_offload_unregister(AddressSpace *as)
{
    assert(bql_locked());

    if (virtio_dma_offloads) {
        g_hash_table_remove(virtio_dma_offloads, as);
    }
}

const VirtIODMAOffload *virtio_dma_offload_get(AddressSpace *as)
{
    if (!virtio_dma_offloads || !as) {
        return NULL;
    }

    return g_hash_table_lookup(virtio_dma_offloads, as);
}
