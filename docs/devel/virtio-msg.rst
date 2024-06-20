..

VirtIO-MSG
==========

Virtio-msg is a new message based virtio transport (as opposed to memory
access based ones). It is comparable to virtio-ccw and to some extent
vhost-user.

QEMU has an implementation of the virtio-msg transport aswell as an
implementation of a proxy that translates between existing transport
(e.g virtio-mmio/pci) and virtio-msg.

At a high level the virtio-msg spec is split into the message transport and
the lower level message bus. Different implementations of msg busses are
expected, e.g FF-A, direct hw (vfio?), Linux user-space, Xen and others.
Currently we have a PoC of a Linux userspace bus that allows communication
between QEMU's running on the same host.

The msg-bus abstraction is implemented here:
  hw/virtio/virtio-msg-bus.c

The linux-user message-bus implementation here:
  virtio-msg-bus-linux-user.c
  include/hw/virtio/spsc_queue.h

The virtio-msg protocol packetizer/decoder here:
  include/hw/virtio/virtio-msg-prot.h

The transport:
  hw/virtio/virtio-msg.c

The proxy device that translates from mmio/pci to msg:
  hw/virtio/virtio-msg-proxy-driver.c

The virtio-msg backend machine:
  hw/virtio/virtio-msg-machine.c

Running
-------

Running a Linux guest on the virt machine:

.. code-block:: bash

   qemu-system-aarch64 -M virt -m 2G -cpu cortex-a72 \
        -object memory-backend-file,id=mem,size=2G,mem-path=/dev/shm/qemu-ram,share=on \
        -machine memory-backend=mem \
        -chardev socket,id=chr0,path=linux-user.socket \
        -serial mon:stdio -display none \
        -kernel Image \
        -initrd core-image-minimal-qemuarm64.rootfs.cpio.gz \
        -append "rdinit=/sbin/init console=ttyAMA0 lpj=100" \
        -device virtio-msg-proxy-driver-pci \
        -device virtio-msg-bus-linux-user,name=linux-user,chardev=chr0


To use virtio-mmio, replace the -device virtio-msg-proxy-driver-pci with:

.. code-block:: bash

   -device virtio-msg-proxy-driver,iommu_platform=on       \
   -global virtio-mmio.force-legacy=false                  \


Running the virtio-msg backends machine:

Before running the virtio-msg machine with the backends, we need to
remove any existing queue's.

.. code-block:: bash

   rm -fr queue-linux-user-d* && \
   qemu-system-aarch64 -M x-virtio-msg -m 2G -cpu cortex-a72 \
        -object memory-backend-file,id=mem,size=2G,mem-path=/dev/shm/qemu-ram,share=on \
        -machine memory-backend=mem \
        -chardev socket,id=chr0,path=linux-user.socket,server=on \
        -serial mon:stdio -display none \
        -device virtio-msg-bus-linux-user,name=linux-user,chardev=chr0 \
        -device virtio-net-device,netdev=net0 \
        -netdev user,id=net0 \
        -object filter-dump,id=f0,netdev=net0,file=net.pcap


