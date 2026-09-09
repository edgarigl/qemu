<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Dom0-owned camera buffer experiment

This prototype tests the storage-import leg of multi-VM camera sharing:
one dom0 dma-buf pool becomes a set of virtio-gpu resources in each guest.
The producer keeps its pool alive before, during, and after guest consumption.
The native and guest probes use Vulkan GPU readback to verify the contents.
That diagnostic readback copies pixels; importing the source storage does not.

The V4L2 path uses one v4l2loopback node per consumer and needs no QMP fd
transport. The older fdset harness below remains a diagnostic alternative.
Neither path implements an Android camera HAL or switches a physical display.
Continuous V4L2 reuse still needs consumer-coupled loopback completion and
GPU/display release coordination.

## V4L2 export into the guest GPU

Configure one virtio-media and one virtio-gpu device per guest:

```text
-device virtio-gpu-gl-pci,blob=on,hostmem=256M,venus=on,x-blob-import-media=on
-device virtio-media-pci,host-device=/dev/video11,max-buffers=9,host-v4l2-memory=export-gpu,xen-grants=off
-display egl-headless,rendernode=/dev/dri/renderD128
```

Use a separate loopback node for each QEMU. Before guest REQBUFS, bind the
producer's pool to stable OUTPUT slots using the dma-buf pass-through support
in [v4l2loopback PR #665](https://github.com/v4l2loopback/v4l2loopback/pull/665).
QEMU acquires each slot with host CAPTURE EXPBUF and registers its fd in a
process-local media/GPU registry. It neither maps nor regrants the media pages.
The GPU duplicates the fd when importing a blob. Tokens begin at
0xfffe000000000000 and are never reused within that QEMU. Queue teardown
removes tokens; already imported GPU resources retain their storage references.

The guest requires the companion virtio-media changes and optional virtio-gpu
helper in
[fanout-gpu-export](https://github.com/edgarigl/virtio-media/tree/fanout-gpu-export/guest-kernel).
Guest VIDIOC_EXPBUF requests a token and allocation length, then the GPU helper
exports a real virtio-gpu GEM dma-buf. Applications use ordinary V4L2 EXPBUF
and Vulkan import; they do not create blobs or exchange host fd numbers.
Feature bit 58 and command 10 are private experimental protocol additions.

REQBUFS(MMAP), QUERYBUF and QBUF/DQBUF select indexed V4L2 queues; they do not
imply a CPU mapping. In this mode mmap of the video node returns EOPNOTSUPP.
An exported GPU fd uses virtio-gpu's mapping path, including Xen HMEM. The
helper currently supports exactly one bound virtio-gpu device per guest.
The media-import and fdset-import properties are mutually exclusive. Both
require the virgl/Venus backend and block migration.

For a finite pool whose producer will not reuse any slot, run on dom0 and
both guests using their respective video nodes and hardware Vulkan ICDs:

```sh
make -C contrib/virtio-media-handover
contrib/virtio-media-handover/blob-check v4l2 /dev/video0 9
```

The checker exports all slots, closes the video node, then GPU-reads each fd.
READ lines report checksums; compare them across consumers. Compare host
dma-buf inodes from native EXPORT lines with QEMU GPU_EXPORT diagnostics
enabled by -d guest_errors. Guest inode numbers are in a different namespace.
This is a storage/lifetime check, not a streaming reader: it deliberately
does not DQBUF a frame before inspecting the frozen pool.

On 5050a, native RADV and two Linux/Venus guests read nine matching slots with
both GBM and system dma-heap allocations, xen-grants=off, and no QMP. A guest
QBUF/DQBUF plus EXPBUF mapping check and a native GStreamer DMABUF smoke test
also passed for the retained final frame. The camera source was vivid;
Android/gfxstream and visible handover remain unvalidated.

## Diagnostic QMP fdset interface

Use a virgl/Venus GPU with these additional properties:

```
x-blob-import-fdset=42,x-blob-import-count=4
```

The default import blob ID base is `0xffff000000000000`, configurable with
`x-blob-import-id`. A guest's HOST3D CREATE_BLOB at `base + slot` imports the
dma-buf installed in fdset `42 + slot`. The size must equal the dma-buf size and
USE_SHAREABLE must be set. Ordinary blob IDs keep their existing behavior.
The feature is disabled unless an fdset base is configured, and blocks migration.
The host must authorize the buffers for this VM; this is an experimental local
interface, not an addition to the virtio specification.

Rutabaga/gfxstream is not supported by this experiment. Passing the external fd
to Rutabaga created a guest handle, but gfxstream could not attach the resource
and aborted at Vulkan import with "Failed to get allocation info for
ColorBuffer". The final QEMU code rejects this configuration at realize time.
Android therefore needs renderer resource/import work as well as gralloc/HAL
integration before it can use this dom0-owned pool. The existing guest-allocated
gfxstream capture path is unaffected.

Supply dma-bufs with QMP `add-fd` and SCM_RIGHTS. Keep the pool and its fdsets
stable until consumers have finished. Each GPU import retains its own fd
reference. Removing an fdset prevents subsequent imports but does not revoke
existing resources. A UUID registry entry alone would not create these resources.

Configure a private QMP socket per QEMU, for example:

```
-qmp unix:/run/camera-test/g0.qmp,server=on,wait=off
```

Restrict the directory to the test operator. The broker must be able to connect
to QMP and read/write the render node. Do not put multiple unrelated fds into an
import fdset. Replacing a pool requires stopping its consumers first.

## Build and run

Build QEMU normally. Build this checker in dom0 and in each Linux guest:

```
make -C contrib/virtio-media-handover
```

Dependencies: C compiler, pkg-config, libdrm and Vulkan development headers;
Python 3.9+, libgbm, a working hardware Vulkan driver, and SSH for the harness.
Install the guest checker as `/tmp/blob-check`, or set `--guest-binary`.

First check only native GPU access:

```
cd contrib/virtio-media-handover
python3 broker.py --frames 3 --native-first 1
```

Then test a Venus guest (capset 4), supplying its SSH address, QMP socket,
capset ID, and guest Vulkan ICD path:

```
python3 broker.py --frames 8 --native-first 2 \
    --guest edgar@10.0.3.10 /run/camera-test/g0.qmp 4 \
            /usr/share/vulkan/icd.d/virtio_icd.json
```

Repeat `--guest` for additional VMs. Native consumption runs first, overlaps
the first guest frame, and then stops. This tests a change in consumer ownership;
it does not claim that a display handover has happened. Each reader must finish
its GPU work and report the expected checksum before the broker releases a slot.

To capture from a V4L2 device that supports DMABUF import:

```
python3 broker.py --camera /dev/video0 --width 640 --height 480 \
    --frames 8 --native-first 2 \
    --guest edgar@10.0.3.10 /run/camera-test/g0.qmp 4 \
            /usr/share/vulkan/icd.d/virtio_icd.json
```

The capture helper queues the same pool to the camera as YUYV buffers. It holds
each dequeued frame until all readers finish. GBM allocations are deliberately
larger than the YUYV payload; the checksum covers the full allocation, including
the initially zeroed unused bytes. A failed reader stops the test rather than
allowing the camera to overwrite storage still in use. Vivid is a suitable
software-filled source; a UVC camera still has its USB ingest copy.

## Boot-display handover contract

A persistent dom0 service can allocate this pool and begin its boot preview
before Android exists. Android later imports the pool through virtio-gpu.
The service keeps camera capture active. Android imports the pool and submits
a ready surface to the dom0 compositor. After its GPU acquire fence signals,
the compositor switches at a display refresh. Retire the native preview only
after presentation feedback and its final scanout release. Boot completion or
capture DQBUF alone cannot acknowledge this handover. The compositor keeps
ownership of the physical display throughout.

If Android must allocate its own gralloc blobs, QEMU can instead export those
host fds to the service and switch capture pools. Old pool users must drain
before retirement; a pause-free switch depends on the capture driver. Separate
allocations do not alias automatically. Neither variant is a camera-device
passthrough handover: dom0 can keep ownership and provide fallback on guest exit.

The production design still needs subscriber queues, negotiated image layouts,
bounded loans and drop policy, GPU/scanout release fences, disconnect handling,
and Android buffer-import and presentation integration. This experiment isolates
the storage question before implementing those pieces.
