Virtio-msg AMP PCI
==================

This document describes QEMU's ``virtio-msg-amp-pci`` device: what it exposes
to the guest and how to use it. For the lower-layer bus definition behind it,
see :doc:`virtio-msg-bus-amp-pci`.

Virtio-msg-amp-pci Usage
------------------------

A virtio-msg-amp-pci can be created by adding the following to the QEMU
command-line::

    -device virtio-msg-amp-pci

Virtio devices can then be attached to the virtio-msg bus with for example
the following::

    -device virtio-rng-device,bus=/gpex-pcihost/pcie.0/virtio-msg-amp-pci/fifo0/virtio-msg/bus0/virtio-msg-dev

The current QEMU model exposes a single FIFO-backed virtio-msg bus instance
named ``fifo0``. Multiple virtio devices can still be connected behind that
bus by using ``bus1``, ``bus2`` and so on.

QEMU Notes
----------

The lower-layer bus is described in :doc:`virtio-msg-bus-amp-pci`. This
document only covers how QEMU wires that bus into its device model.

Today the main QEMU-specific details are:

- command-line creation of the transport device
- QOM bus paths used when attaching virtio devices behind the fixed ``fifo0``
  instance
- the current model implements a single FIFO pair and a single MSI-X vector
