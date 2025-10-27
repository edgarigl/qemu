.. _virtio_msg_bus_amp_pci:

Virtio-msg-bus AMP PCI
======================

This note describes how virtio-msg-bus is implemented over AMP PCI shared
memory and interrupts. It focuses on the lower-layer bus that carries
virtio-msg bus messages and transport messages. QEMU-specific details such as
command-line examples, object paths, and implementation limits are covered
separately in :doc:`virtio-msg-amp-pci`.

Scope
-----

This note describes the AMP PCI virtio-msg-bus interface. Its purpose is to
document the lower-layer bus details that would need to be standardized if AMP
PCI becomes a standard virtio-msg-bus implementation.

That includes the shared-memory FIFO model, the BAR layout, the register map,
and the interrupt model. The companion document :doc:`virtio-msg-amp-pci`
covers the current QEMU device and command-line usage.

What It Is
----------

Virtio-msg is a message-based virtio transport. Instead of driving the device
through the usual MMIO or PCI register accesses, the driver sends small
messages that ask for the same operations: discover a device, read features,
set up queues, read or write config state, and notify activity.

The AMP PCI bus implementation uses a small PCI function for discovery,
shared-memory setup, and interrupts. The actual virtio-msg traffic then flows
through a shared-memory FIFO pair plus a doorbell-style notification.

Why Not Just Use virtio-pci?
----------------------------

virtio-pci works well when both sides want the existing PCI transport.
That means PCI capabilities, queue state exposed through PCI config space
or MMIO, and notifications built around the virtio-pci register model.

The AMP PCI bus implementation is aimed at a different setup:

- the two sides already have shared memory
- trapping or emulating a full virtio-pci register interface is awkward,
  expensive, or simply not a good fit

In those cases it can be simpler to keep the virtio control path as explicit
messages and use PCI only as a bootstrap wrapper for discovery, mapping, and
interrupt delivery.

This is especially useful for AMP-style systems where the guest and the device
side look more like peers sharing memory than a classic VM talking to a
standard PCI transport.

Bus Components
--------------

The bus implementation has a few basic pieces:

- a PCI function used for discovery and interrupt wiring
- a shared-memory region used for a point-to-point FIFO pair
- a doorbell mechanism so one side can tell the other to look at the FIFO
- interrupts so the device side can signal completed work or new messages

The FIFO carries virtio-msg request and response packets. The driver pushes a
message into the driver-to-device direction and rings the matching doorbell.
The device side reads the message, processes it, puts any reply on the
device-to-driver direction, and raises an interrupt to tell the driver there
is something to consume.

The FIFO itself is bus plumbing. The payload on top is still the virtio-msg
protocol, so the higher level operations are the same ones a virtio-msg driver
already expects.

Bus Layout
----------

The current proposal is to standardize a small PCI wrapper for the bus with
three BARs:

.. list-table:: BAR layout
   :widths: 10 25 65
   :header-rows: 1

   * - BAR
     - Contents
     - Notes
   * - 0
     - Bus registers
     - Version register, reserved space for future common registers, and one
       doorbell register.
   * - 1
     - FIFO memory
     - Shared-memory area holding one 16 KiB FIFO window.
   * - 2
     - MSI-X table and PBA
     - Standard PCI MSI-X structures.

BAR 0 is intentionally small:

.. list-table:: BAR 0 register layout
   :widths: 15 20 15 50
   :header-rows: 1

   * - Offset
     - Name
     - Access
     - Description
   * - ``0x00``
     - ``VERSION``
     - RO
     - Register layout revision implemented by the device.
   * - ``0x04`` - ``0x1f``
     - Reserved
     - -
     - Reserved for future common registers. Keeping this space free allows
       the common register block to grow without moving the doorbell array.
       Reserved registers read as zero and ignore writes.
   * - ``0x20``
     - ``NOTIFY``
     - WO
     - Doorbell register. The driver writes ``1`` to this register after
       placing a message in the driver queue. Other values are reserved for
       future use.

BAR 1 holds the FIFO storage. The bus uses one fixed 16 KiB window.

.. list-table:: Shared-memory layout
   :widths: 20 25 55
   :header-rows: 1

   * - Offset range
     - Region
     - Purpose
   * - ``0x0000`` - ``0x0fff``
     - Reserved
     - Reserved for future use.
   * - ``0x1000`` - ``0x1fff``
     - Driver queue
     - Messages written by the driver and consumed by the device side.
   * - ``0x2000`` - ``0x2fff``
     - Device queue
     - Messages written by the device side and consumed by the driver.
   * - ``0x3000`` - ``0x3fff``
     - Reserved
     - Reserved for future use.

This gives the bus a pair of single-producer/single-consumer queues in shared
memory, one in each direction.

FIFO Queue Format
-----------------

The shared-memory window contains two queues, one for each direction:

- the driver queue carries messages from driver to device
- the device queue carries messages from device to driver

Both queues use the same single-producer, single-consumer ring layout:

.. code-block:: c

   struct virtio_msg_bus_amp_queue {
           le32 head;             /* Producer index. */
           u8 reserved0[60];      /* Align tail to a 64B offset. */
           le32 tail;             /* Consumer index. */
           u8 reserved1[60];      /* Align packets to a 64B offset. */
           u8 packets[][64];      /* One VirtIOMSG per slot. */
   };

``head`` and ``tail`` are 32-bit little-endian indexes. The reserved gaps keep
both fields on separate 64-byte boundaries.

Packet storage starts at ``0x80``. Each packet slot is 64 bytes and carries
one ``VirtIOMSG``. With a 4 KiB queue region this gives a queue capacity of
62 packets. The queue is circular: the producer advances ``head`` after
writing a packet, and the consumer advances ``tail`` after reading one. In the
driver queue, the driver is the producer and the device side is the consumer.
In the device queue, those roles are reversed.

Notifications
-------------

The driver writes to the doorbell register to tell the device side to
look at the driver queue. The device side posts replies or events on the
device queue and raises the MSI-X vector to notify the driver.

Using a single MSI-X vector keeps the notification model simple. The bus
implementation does not need a large register interface; it only needs a way
to say "new messages are ready".

The register space after ``NOTIFY`` is reserved for future use. Reserved
register locations read as zero and ignore writes.

Future Considerations
---------------------

The current layout is intentionally small and simple, but there are obvious
directions for future extension.

One direction is support for a backend running on the PCI host side rather
than in the endpoint-facing software stack. That could make it useful to add a
large prefetchable BAR for DMA between host and endpoint. If that happens, the
current BAR assignment may need to change. For example, the MSI-X table and
PBA could move from BAR 2 to BAR 3 so BAR 2 can be used for a larger DMA
window. This is future work and is not part of the current bus definition.

Another direction is more granular interrupt and notification control. The
current design uses one doorbell and one MSI-X vector. A future revision could
add support for multiple FIFOs, per-device and virtqueue MSI-X vectors,
per-virtqueue driver notifications, or both. That may in turn require
additional register definitions or new doorbell semantics.
This is also future work and is not implemented by the current QEMU model.
