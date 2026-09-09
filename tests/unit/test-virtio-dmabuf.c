/*
 * QEMU tests for shared dma-buf API
 *
 * Copyright (c) 2023 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "qemu/osdep.h"
#include "hw/virtio/virtio-dmabuf.h"


static void test_add_remove_resources(void)
{
    QemuUUID uuid;
    int i, dmabuf_fd;

    for (i = 0; i < 100; ++i) {
        qemu_uuid_generate(&uuid);
        dmabuf_fd = g_random_int_range(3, 500);
        /* Add a new resource */
        g_assert(virtio_add_dmabuf(&uuid, dmabuf_fd));
        g_assert_cmpint(virtio_lookup_dmabuf(&uuid), ==, dmabuf_fd);
        /* Remove the resource */
        g_assert(virtio_remove_resource(&uuid));
        /* Resource is not found anymore */
        g_assert_cmpint(virtio_lookup_dmabuf(&uuid), ==, -1);
    }
}

static void test_add_remove_dev(void)
{
    QemuUUID uuid;
    struct vhost_dev *dev = g_new0(struct vhost_dev, 1);
    int i;

    for (i = 0; i < 100; ++i) {
        qemu_uuid_generate(&uuid);
        virtio_add_vhost_device(&uuid, dev);
        /* vhost device is found */
        g_assert(virtio_lookup_vhost_device(&uuid) != NULL);
        /* Remove the vhost device */
        g_assert(virtio_remove_resource(&uuid));
        /* vhost device is not found anymore */
        g_assert(virtio_lookup_vhost_device(&uuid) == NULL);
    }
    g_free(dev);
}

static void test_remove_invalid_resource(void)
{
    QemuUUID uuid;
    int i;

    for (i = 0; i < 20; ++i) {
        qemu_uuid_generate(&uuid);
        g_assert_cmpint(virtio_lookup_dmabuf(&uuid), ==, -1);
        /* Removing a resource that does not exist returns false */
        g_assert_false(virtio_remove_resource(&uuid));
    }
}

static void test_add_invalid_resource(void)
{
    QemuUUID uuid;
    struct vhost_dev *dev = NULL;
    int i, dmabuf_fd = -2, alt_dmabuf = 2;

    for (i = 0; i < 20; ++i) {
        qemu_uuid_generate(&uuid);
        /* Add a new resource with invalid (negative) resource fd */
        g_assert_false(virtio_add_dmabuf(&uuid, dmabuf_fd));
        /* Resource is not found */
        g_assert_cmpint(virtio_lookup_dmabuf(&uuid), ==, -1);
        /* Add a new vhost device with invalid (NULL) pointer */
        g_assert_false(virtio_add_vhost_device(&uuid, dev));
        /* vhost device is not found */
        g_assert(virtio_lookup_vhost_device(&uuid) == NULL);
    }

    for (i = 0; i < 20; ++i) {
        /* Add a valid resource */
        qemu_uuid_generate(&uuid);
        dmabuf_fd = g_random_int_range(3, 500);
        g_assert(virtio_add_dmabuf(&uuid, dmabuf_fd));
        g_assert_cmpint(virtio_lookup_dmabuf(&uuid), ==, dmabuf_fd);
        /* Add a new resource with repeated uuid returns false */
        g_assert_false(virtio_add_dmabuf(&uuid, alt_dmabuf));
        /* The value for the uuid key is not replaced */
        g_assert_cmpint(virtio_lookup_dmabuf(&uuid), ==, dmabuf_fd);
    }
}

static void test_free_resources(void)
{
    QemuUUID uuids[20];
    int i, dmabuf_fd;

    for (i = 0; i < ARRAY_SIZE(uuids); ++i) {
        qemu_uuid_generate(&uuids[i]);
        dmabuf_fd = g_random_int_range(3, 500);
        g_assert(virtio_add_dmabuf(&uuids[i], dmabuf_fd));
        g_assert_cmpint(virtio_lookup_dmabuf(&uuids[i]), ==, dmabuf_fd);
    }
    virtio_free_resources();
    for (i = 0; i < ARRAY_SIZE(uuids); ++i) {
        /* None of the resources is found after free'd */
        g_assert_cmpint(virtio_lookup_dmabuf(&uuids[i]), ==, -1);
    }

}

static void test_media_blob_lifetime(void)
{
    char *path = NULL;
    uint64_t first, second;
    int owner = g_file_open_tmp("qemu-media-XXXXXX", &path, NULL);
    int imported;
    char byte;

    g_assert_cmpint(owner, >=, 0);
    unlink(path);
    g_free(path);
    g_assert_cmpint(write(owner, "x", 1), ==, 1);
    g_assert_cmpuint(virtio_dmabuf_blob_register(-1), ==, 0);
    first = virtio_dmabuf_blob_register(owner);
    g_assert_cmpuint(first, >=, VIRTIO_DMABUF_BLOB_BASE);
    imported = virtio_dmabuf_blob_dup(first);
    g_assert_cmpint(imported, >=, 0);
    g_assert_cmpint(fcntl(imported, F_GETFD) & FD_CLOEXEC, !=, 0);
    virtio_dmabuf_blob_unregister(first);
    g_assert_cmpint(virtio_dmabuf_blob_dup(first), ==, -1);
    g_assert_cmpint(errno, ==, ENOENT);
    /* Old renderer references survive removal; a new epoch gets a new token. */
    second = virtio_dmabuf_blob_register(owner);
    g_assert_cmpuint(second, >, first);
    virtio_dmabuf_blob_unregister(second);
    close(owner);
    g_assert_cmpint(pread(imported, &byte, 1, 0), ==, 1);
    g_assert_cmpint(byte, ==, 'x');
    close(imported);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/virtio-dmabuf/media_blob_lifetime",
                    test_media_blob_lifetime);
    g_test_add_func("/virtio-dmabuf/add_rm_res", test_add_remove_resources);
    g_test_add_func("/virtio-dmabuf/add_rm_dev", test_add_remove_dev);
    g_test_add_func("/virtio-dmabuf/rm_invalid_res",
                    test_remove_invalid_resource);
    g_test_add_func("/virtio-dmabuf/add_invalid_res",
                    test_add_invalid_resource);
    g_test_add_func("/virtio-dmabuf/free_res", test_free_resources);

    return g_test_run();
}
