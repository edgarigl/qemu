#
# A minimal version of the config that only supports only a few
# virtual machines. This avoids bringing in any of numerous legacy
# features from the 32bit platform (although virt still supports 32bit
# itself)
#

CONFIG_ARM_VIRT=y
CONFIG_XEN=y
CONFIG_XEN_BUS=y
CONFIG_PCI=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_SERIAL=y
CONFIG_VIRTIO_GPU=y
