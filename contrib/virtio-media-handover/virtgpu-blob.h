/* SPDX-License-Identifier: MIT */
/* MIT UAPI definitions from Linux include/uapi/drm/virtgpu_drm.h. */
/* These additions are missing from older libdrm installations. */
#ifndef HANDOVER_VIRTGPU_BLOB_H
#define HANDOVER_VIRTGPU_BLOB_H

#include <virtgpu_drm.h>

#ifndef DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB
#define VIRTGPU_BLOB_MEM_HOST3D 2
#define VIRTGPU_BLOB_FLAG_USE_MAPPABLE 1
#define VIRTGPU_BLOB_FLAG_USE_SHAREABLE 2
struct drm_virtgpu_resource_create_blob {
    __u32 blob_mem;
    __u32 blob_flags;
    __u32 bo_handle;
    __u32 res_handle;
    __u64 size;
    __u32 pad;
    __u32 cmd_size;
    __u64 cmd;
    __u64 blob_id;
};
#define DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB \
    DRM_IOWR(DRM_COMMAND_BASE + 0x0a, struct drm_virtgpu_resource_create_blob)
#endif

#ifndef DRM_IOCTL_VIRTGPU_CONTEXT_INIT
#define VIRTGPU_CONTEXT_PARAM_CAPSET_ID 1
#define VIRTGPU_CONTEXT_PARAM_NUM_RINGS 2
struct drm_virtgpu_context_set_param {
    __u64 param;
    __u64 value;
};
struct drm_virtgpu_context_init {
    __u32 num_params;
    __u32 pad;
    __u64 ctx_set_params;
};
#define DRM_IOCTL_VIRTGPU_CONTEXT_INIT \
    DRM_IOWR(DRM_COMMAND_BASE + 0x0b, struct drm_virtgpu_context_init)
#endif
#endif
