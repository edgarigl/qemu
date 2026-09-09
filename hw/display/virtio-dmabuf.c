/*
 * Virtio Shared dma-buf
 *
 * Copyright Red Hat, Inc. 2023
 *
 * Authors:
 *     Albert Esteve <aesteve@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "hw/virtio/virtio-dmabuf.h"


static GMutex lock;
static GHashTable *resource_uuids;
static GHashTable *media_blobs;
static uint64_t next_media_blob = VIRTIO_DMABUF_BLOB_BASE;

uint64_t virtio_dmabuf_blob_register(int fd)
{
    uint64_t *id;
    uint64_t result;

    if (fd < 0 || fd == INT_MAX) {
        return 0;
    }
    g_mutex_lock(&lock);
    if (next_media_blob == UINT64_MAX) {
        g_mutex_unlock(&lock);
        return 0;
    }
    if (!media_blobs) {
        media_blobs = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                           g_free, NULL);
    }
    id = g_new(uint64_t, 1);
    *id = next_media_blob++;
    g_hash_table_insert(media_blobs, id, GINT_TO_POINTER(fd + 1));
    result = *id;
    g_mutex_unlock(&lock);
    return result;
}

int virtio_dmabuf_blob_dup(uint64_t id)
{
    gpointer value;
    int fd = -1;

    g_mutex_lock(&lock);
    value = media_blobs ? g_hash_table_lookup(media_blobs, &id) : NULL;
    if (value) {
        fd = qemu_dup(GPOINTER_TO_INT(value) - 1);
    } else {
        errno = ENOENT;
    }
    g_mutex_unlock(&lock);
    return fd;
}

void virtio_dmabuf_blob_unregister(uint64_t id)
{
    g_mutex_lock(&lock);
    if (media_blobs) {
        g_hash_table_remove(media_blobs, &id);
        if (!g_hash_table_size(media_blobs)) {
            g_clear_pointer(&media_blobs, g_hash_table_destroy);
        }
    }
    g_mutex_unlock(&lock);
}

/*
 * uuid_equal_func: wrapper for UUID is_equal function to
 * satisfy g_hash_table_new expected parameters signatures.
 */
static int uuid_equal_func(const void *lhv, const void *rhv)
{
    return qemu_uuid_is_equal(lhv, rhv);
}

static bool virtio_add_resource(QemuUUID *uuid, VirtioSharedObject *value)
{
    bool result = true;

    g_mutex_lock(&lock);
    if (resource_uuids == NULL) {
        resource_uuids = g_hash_table_new_full(qemu_uuid_hash,
                                               uuid_equal_func,
                                               g_free,
                                               g_free);
    }
    if (g_hash_table_lookup(resource_uuids, uuid) == NULL) {
        g_hash_table_insert(resource_uuids, g_memdup2(uuid, sizeof(*uuid)),
                            value);
    } else {
        result = false;
    }
    g_mutex_unlock(&lock);

    return result;
}

bool virtio_add_dmabuf(QemuUUID *uuid, int udmabuf_fd)
{
    bool result;
    VirtioSharedObject *vso;
    if (udmabuf_fd < 0) {
        return false;
    }
    vso = g_new(VirtioSharedObject, 1);
    vso->type = TYPE_DMABUF;
    vso->value = GINT_TO_POINTER(udmabuf_fd);
    result = virtio_add_resource(uuid, vso);
    if (!result) {
        g_free(vso);
    }

    return result;
}

bool virtio_add_vhost_device(QemuUUID *uuid, struct vhost_dev *dev)
{
    bool result;
    VirtioSharedObject *vso;
    if (dev == NULL) {
        return false;
    }
    vso = g_new(VirtioSharedObject, 1);
    vso->type = TYPE_VHOST_DEV;
    vso->value = dev;
    result = virtio_add_resource(uuid, vso);
    if (!result) {
        g_free(vso);
    }

    return result;
}

bool virtio_remove_resource(const QemuUUID *uuid)
{
    bool result;
    g_mutex_lock(&lock);
    result = resource_uuids && g_hash_table_remove(resource_uuids, uuid);
    g_mutex_unlock(&lock);

    return result;
}

static VirtioSharedObject *get_shared_object(const QemuUUID *uuid)
{
    gpointer lookup_res = NULL;

    g_mutex_lock(&lock);
    if (resource_uuids != NULL) {
        lookup_res = g_hash_table_lookup(resource_uuids, uuid);
    }
    g_mutex_unlock(&lock);

    return (VirtioSharedObject *) lookup_res;
}

int virtio_lookup_dmabuf(const QemuUUID *uuid)
{
    VirtioSharedObject *vso = get_shared_object(uuid);
    if (vso == NULL) {
        return -1;
    }
    assert(vso->type == TYPE_DMABUF);
    return GPOINTER_TO_INT(vso->value);
}

int virtio_dup_dmabuf(const QemuUUID *uuid)
{
    VirtioSharedObject *vso;
    int fd = -1;

    g_mutex_lock(&lock);
    vso = resource_uuids ? g_hash_table_lookup(resource_uuids, uuid) : NULL;
    if (!vso) {
        errno = ENOENT;
    } else if (vso->type != TYPE_DMABUF) {
        errno = EINVAL;
    } else {
        fd = qemu_dup(GPOINTER_TO_INT(vso->value));
    }
    g_mutex_unlock(&lock);
    return fd;
}

struct vhost_dev *virtio_lookup_vhost_device(const QemuUUID *uuid)
{
    VirtioSharedObject *vso = get_shared_object(uuid);
    if (vso == NULL) {
        return NULL;
    }
    assert(vso->type == TYPE_VHOST_DEV);
    return (struct vhost_dev *) vso->value;
}

SharedObjectType virtio_object_type(const QemuUUID *uuid)
{
    VirtioSharedObject *vso = get_shared_object(uuid);
    if (vso == NULL) {
        return TYPE_INVALID;
    }
    return vso->type;
}

void virtio_free_resources(void)
{
    g_mutex_lock(&lock);
    g_clear_pointer(&resource_uuids, g_hash_table_destroy);
    g_mutex_unlock(&lock);
}
