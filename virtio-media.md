# virtio-media Xen grant MMAP and brokered sharing

This document describes local out-of-tree extensions implemented in this tree
for virtio-media.

## Scope

Implemented extensions:

1. Xen grant-based MMAP to avoid IOREQ BAR access.
2. Brokered export/import handles for inter-guest sharing (Option 1 control
   plane).
3. Guest-side DMABUF fd integration for exported/imported handles.

Not implemented yet:

- Full generic DMABUF attach/map backing for non-virtio-media consumers.
- Explicit fence payload semantics.

## 1. Xen grant MMAP extension

### Feature bit

- `VIRTIO_MEDIA_F_GNTREF` = bit `63`.

### Protocol deviation

`VIRTIO_MEDIA_CMD_MMAP` response is extended with:

- `gref_count`
- `gref_page_size`
- `gref_domid`
- `gref_ids[]`

### Behavior

- On Xen, QEMU allocates backing pages via `gntalloc` and returns grant refs.
- Guest maps these refs as RAM in VMA paths.
- BAR/SHM MMAP path is bypassed when this feature is negotiated.

## 2. Brokered sharing extension (Option 1)

### Feature bits

- `VIRTIO_MEDIA_F_EXPORT_IMPORT` = bit `62`.
- `VIRTIO_MEDIA_F_SHARE_FENCE` = bit `61`.

`F_SHARE_FENCE` is currently a negotiated placeholder for forward compatibility.

### New commands

- `VIRTIO_MEDIA_CMD_EXPORT_BUFFER` (`6`)
- `VIRTIO_MEDIA_CMD_IMPORT_BUFFER` (`7`)
- `VIRTIO_MEDIA_CMD_RELEASE_HANDLE` (`8`)

### Command model

#### EXPORT_BUFFER

Input:

- `session_id`
- `queue_type`
- `buffer_index`
- `plane_index`
- `flags`

Output:

- `handle_id` (opaque `u64`)
- `len`
- `plane_count`

#### IMPORT_BUFFER

Input:

- `session_id`
- `handle_id`
- `flags`

Output:

- `driver_addr`
- `len`
- optional grant metadata (`gref_count/gref_page_size/gref_domid/gref_ids[]`)

When grefs are enabled, import returns the corresponding grant refs for the
shared range.

#### RELEASE_HANDLE

Input:

- `handle_id`

Output:

- status only

### Backend behavior

- QEMU keeps a per-device handle table (`handle_id -> buffer plane metadata`).
- Handles are opaque and backend-scoped.
- Closing an owner session removes handles exported by that session.
- Release command removes an existing handle explicitly.

## 3. Current guest driver userspace API (prototype)

The guest driver exposes private ioctls (out-of-tree prototype API):

- `VIDIOC_VIRTIO_MEDIA_EXPORT_BUFFER`
- `VIDIOC_VIRTIO_MEDIA_IMPORT_BUFFER`
- `VIDIOC_VIRTIO_MEDIA_RELEASE_HANDLE`

These ioctls pass handle/mapping metadata between userspace and backend.

Additionally implemented:

- `VIDIOC_EXPBUF` now exports a DMABUF fd backed by an exported handle.
- Private export/import ioctls also return DMABUF fds in
  `virtio_media_ioc_export_buffer.dmabuf_fd` and
  `virtio_media_ioc_import_buffer.dmabuf_fd`.
- `VIDIOC_QBUF` with `V4L2_MEMORY_DMABUF` is accepted when the fd belongs to a
  DMABUF previously exported by this driver for the same queue type. The driver
  translates it to its internal MMAP queueing model.

Current limitation:

- Generic DMA attachment/map is implemented for imported DMABUFs backed by Xen
  grant refs.
- Exported handle-based DMABUFs are still control-plane objects unless they are
  imported from grant-backed mappings.
- Fence synchronization across guests is not implemented yet
  (`VIRTIO_MEDIA_F_SHARE_FENCE` is reserved only).

## 4. Compatibility and deviations

### Compatibility when features are not negotiated

- Base virtio-media behavior remains unchanged.
- New commands are not required and should not be issued.

### Deviations from current virtio-media draft

- New feature bits: `F_GNTREF`, `F_EXPORT_IMPORT`, `F_SHARE_FENCE`.
- Extended MMAP response payload with grant refs.
- New command set for export/import/release handles.
- Xen-specific grant semantics in backend implementation.

These are local protocol extensions and not part of upstream virtio-media yet.

## 5. Source locations

### QEMU

- `hw/virtio/virtio-media.c`
- `hw/virtio/virtio-media-pci.c`
- `include/hw/virtio/virtio-media.h`

### Guest driver

- `driver/protocol.h`
- `driver/virtio_media_driver.c`
- `driver/virtio_media_ioctls.c`
- `driver/virtio_media.h`
