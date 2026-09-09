/*
 * Host dma-buf / guest virtio-gpu import experiment.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/dma-buf.h>
#include <linux/videodev2.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xf86drm.h>
#include "virtgpu-blob.h"
#include <vulkan/vulkan.h>

#define MAX_BUFFERS 16
#define BLOB_BASE UINT64_C(0xffff000000000000)
#define VK_CHECK(call) do { \
    VkResult result_ = (call); \
    if (result_ != VK_SUCCESS) { \
        fprintf(stderr, "%s: VkResult %d\n", #call, result_); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static void fail(const char *message)
{
    perror(message);
    exit(EXIT_FAILURE);
}

static uint64_t number(const char *s)
{
    char *end;
    uint64_t value;

    errno = 0;
    /* This standalone utility does not link QEMU's parsing helpers. */
    value = strtoull(s, &end, 0);
    if (errno || !*s || *end || *s == '-') {
        fprintf(stderr, "invalid number: %s\n", s);
        exit(EXIT_FAILURE);
    }
    return value;
}

static void dmabuf_sync(int fd, uint64_t flags)
{
    struct dma_buf_sync sync = { .flags = flags };
    int ret;

    do {
        ret = ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
        fail("DMA_BUF_IOCTL_SYNC");
    }
}

static uint32_t checksum(const uint8_t *data, size_t size)
{
    uint32_t hash = 2166136261U;

    for (size_t i = 0; i < size; i++) {
        hash = (hash ^ data[i]) * 16777619U;
    }
    return hash;
}

static uint32_t memory_type(VkPhysicalDevice pd, uint32_t bits,
                            VkMemoryPropertyFlags flags)
{
    VkPhysicalDeviceMemoryProperties props;

    vkGetPhysicalDeviceMemoryProperties(pd, &props);
    for (uint32_t i = 0; i < props.memoryTypeCount; i++) {
        if ((bits & (1U << i)) &&
            (props.memoryTypes[i].propertyFlags & flags) == flags) {
            return i;
        }
    }
    fprintf(stderr, "no memory type for bits=%x flags=%x\n", bits, flags);
    exit(EXIT_FAILURE);
}

/* The only pixel copy is this diagnostic GPU readback into private memory. */
static int gpu_check(int fd, uint64_t size, uint32_t expected, bool verify)
{
    VkApplicationInfo app = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .apiVersion = VK_API_VERSION_1_1,
    };
    VkInstanceCreateInfo ici = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &app,
    };
    VkInstance instance;
    VkPhysicalDevice devices[16], pd = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties props;
    uint32_t count = 16, family = UINT32_MAX;
    VkQueueFamilyProperties families[32];
    float priority = 1.0;
    const char *extensions[] = {
        VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME,
        VK_EXT_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME,
    };

    VK_CHECK(vkCreateInstance(&ici, NULL, &instance));
    VK_CHECK(vkEnumeratePhysicalDevices(instance, &count, devices));
    for (uint32_t i = 0; i < count; i++) {
        vkGetPhysicalDeviceProperties(devices[i], &props);
        if (props.deviceType != VK_PHYSICAL_DEVICE_TYPE_CPU) {
            pd = devices[i];
            break;
        }
    }
    if (!pd) {
        fprintf(stderr, "no hardware Vulkan device\n");
        return 1;
    }
    count = 32;
    vkGetPhysicalDeviceQueueFamilyProperties(pd, &count, families);
    for (uint32_t i = 0; i < count; i++) {
        if (families[i].queueFlags & VK_QUEUE_TRANSFER_BIT) {
            family = i;
            break;
        }
    }
    if (family == UINT32_MAX) {
        fprintf(stderr, "no transfer queue\n");
        return 1;
    }
    VkDeviceQueueCreateInfo qci = {
        .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex = family, .queueCount = 1,
        .pQueuePriorities = &priority,
    };
    VkDeviceCreateInfo dci = {
        .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount = 1, .pQueueCreateInfos = &qci,
        .enabledExtensionCount = 2, .ppEnabledExtensionNames = extensions,
    };
    VkDevice device;
    VkQueue queue;
    VK_CHECK(vkCreateDevice(pd, &dci, NULL, &device));
    vkGetDeviceQueue(device, family, 0, &queue);

    VkExternalMemoryBufferCreateInfo external = {
        .sType = VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO,
        .handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT,
    };
    VkBufferCreateInfo bci = {
        .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
        .pNext = &external, .size = size,
        .usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
        .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
    };
    VkBuffer source, destination;
    VkMemoryRequirements requirements;
    VkDeviceMemory source_memory, destination_memory;
    VK_CHECK(vkCreateBuffer(device, &bci, NULL, &source));
    vkGetBufferMemoryRequirements(device, source, &requirements);
    if (requirements.size > size) {
        fprintf(stderr, "source allocation is smaller than Vulkan requires\n");
        return 1;
    }
    PFN_vkGetMemoryFdPropertiesKHR fd_properties =
        (PFN_vkGetMemoryFdPropertiesKHR)vkGetDeviceProcAddr(
            device, "vkGetMemoryFdPropertiesKHR");
    if (!fd_properties) {
        fprintf(stderr, "vkGetMemoryFdPropertiesKHR unavailable\n");
        return 1;
    }
    VkMemoryFdPropertiesKHR fdprops = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_FD_PROPERTIES_KHR,
    };
    VK_CHECK(fd_properties(device,
                            VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT,
                            fd, &fdprops));
    VkImportMemoryFdInfoKHR import = {
        .sType = VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR,
        .handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT,
        .fd = dup(fd),
    };
    if (import.fd < 0) {
        fail("dup");
    }
    VkMemoryAllocateInfo mai = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .pNext = &import,
        .allocationSize = size,
        .memoryTypeIndex = memory_type(pd, requirements.memoryTypeBits &
                                           fdprops.memoryTypeBits, 0),
    };
    VK_CHECK(vkAllocateMemory(device, &mai, NULL, &source_memory));
    VK_CHECK(vkBindBufferMemory(device, source, source_memory, 0));

    bci.pNext = NULL;
    bci.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    VK_CHECK(vkCreateBuffer(device, &bci, NULL, &destination));
    vkGetBufferMemoryRequirements(device, destination, &requirements);
    mai.pNext = NULL;
    mai.allocationSize = requirements.size;
    mai.memoryTypeIndex = memory_type(pd, requirements.memoryTypeBits,
                                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                                      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    VK_CHECK(vkAllocateMemory(device, &mai, NULL, &destination_memory));
    VK_CHECK(vkBindBufferMemory(device, destination, destination_memory, 0));

    VkCommandPoolCreateInfo pci = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .queueFamilyIndex = family,
    };
    VkCommandPool pool;
    VkCommandBuffer command;
    VK_CHECK(vkCreateCommandPool(device, &pci, NULL, &pool));
    VkCommandBufferAllocateInfo cai = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool = pool, .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
        .commandBufferCount = 1,
    };
    VK_CHECK(vkAllocateCommandBuffers(device, &cai, &command));
    VkCommandBufferBeginInfo begin = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    VK_CHECK(vkBeginCommandBuffer(command, &begin));
    VkBufferMemoryBarrier acquire = {
        .sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER,
        .dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT,
        .srcQueueFamilyIndex = VK_QUEUE_FAMILY_EXTERNAL,
        .dstQueueFamilyIndex = family, .buffer = source, .size = size,
    };
    vkCmdPipelineBarrier(command, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,
                          VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, NULL,
                          1, &acquire, 0, NULL);
    VkBufferCopy region = { .size = size };
    vkCmdCopyBuffer(command, source, destination, 1, &region);
    VkBufferMemoryBarrier barriers[] = {
        {
            .sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER,
            .srcAccessMask = VK_ACCESS_TRANSFER_READ_BIT,
            .srcQueueFamilyIndex = family,
            .dstQueueFamilyIndex = VK_QUEUE_FAMILY_EXTERNAL,
            .buffer = source, .size = size,
        },
        {
            .sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER,
            .srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
            .dstAccessMask = VK_ACCESS_HOST_READ_BIT,
            .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
            .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
            .buffer = destination, .size = size,
        },
    };
    vkCmdPipelineBarrier(command, VK_PIPELINE_STAGE_TRANSFER_BIT,
                          VK_PIPELINE_STAGE_ALL_COMMANDS_BIT |
                          VK_PIPELINE_STAGE_HOST_BIT, 0, 0, NULL,
                          2, barriers, 0, NULL);
    VK_CHECK(vkEndCommandBuffer(command));
    VkSubmitInfo submit = {
        .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
        .commandBufferCount = 1, .pCommandBuffers = &command,
    };
    VK_CHECK(vkQueueSubmit(queue, 1, &submit, VK_NULL_HANDLE));
    VK_CHECK(vkQueueWaitIdle(queue));
    void *data;
    VK_CHECK(vkMapMemory(device, destination_memory, 0, size, 0, &data));
    uint32_t actual = checksum(data, size);
    printf("GPU=%s bytes=%" PRIu64 " checksum=0x%08x expected=0x%08x %s\n",
           props.deviceName, size, actual, expected,
           verify ? (actual == expected ? "OK" : "FAIL") : "READ");
    vkUnmapMemory(device, destination_memory);
    vkDestroyCommandPool(device, pool, NULL);
    vkDestroyBuffer(device, destination, NULL);
    vkDestroyBuffer(device, source, NULL);
    vkFreeMemory(device, destination_memory, NULL);
    vkFreeMemory(device, source_memory, NULL);
    vkDestroyDevice(device, NULL);
    vkDestroyInstance(instance, NULL);
    return verify && actual != expected;
}

static int guest_check(uint64_t size, uint32_t expected,
                       uint32_t slot, uint32_t capset)
{
    int drm = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC), fd;
    struct drm_virtgpu_context_set_param params[] = {
        { .param = VIRTGPU_CONTEXT_PARAM_CAPSET_ID, .value = capset },
        { .param = VIRTGPU_CONTEXT_PARAM_NUM_RINGS, .value = 1 },
    };
    struct drm_virtgpu_context_init ctx = {
        .num_params = 2, .ctx_set_params = (uintptr_t)params,
    };
    struct drm_virtgpu_resource_create_blob blob = {
        .blob_mem = VIRTGPU_BLOB_MEM_HOST3D,
        .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE |
                      VIRTGPU_BLOB_FLAG_USE_SHAREABLE,
        .size = size, .blob_id = BLOB_BASE + slot,
    };

    if (drm < 0 || ioctl(drm, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &ctx) < 0 ||
        ioctl(drm, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &blob) < 0 ||
        drmPrimeHandleToFD(drm, blob.bo_handle, DRM_CLOEXEC | DRM_RDWR, &fd)) {
        fail("guest blob import");
    }
    int ret = gpu_check(fd, size, expected, true);
    close(fd);
    struct drm_gem_close close_bo = { .handle = blob.bo_handle };
    if (ioctl(drm, DRM_IOCTL_GEM_CLOSE, &close_bo) < 0) {
        fail("GEM_CLOSE");
    }
    close(drm);
    return ret;
}

/* Read a frozen finite pool; the producer must not reuse any of its slots. */
static int v4l2_check(const char *path, uint32_t count)
{
    int camera = open(path, O_RDWR | O_CLOEXEC);
    int fds[MAX_BUFFERS], ret = 0;
    uint64_t sizes[MAX_BUFFERS];
    struct v4l2_requestbuffers request = {
        .count = count, .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = V4L2_MEMORY_MMAP,
    };
    struct v4l2_exportbuffer exp = {
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE, .flags = O_RDWR | O_CLOEXEC,
    };

    if (!count || count > MAX_BUFFERS) {
        fprintf(stderr, "invalid buffer count\n");
        return 1;
    }
    if (camera < 0 || ioctl(camera, VIDIOC_REQBUFS, &request) < 0 ||
        request.count != count) {
        fail("V4L2 REQBUFS");
    }
    exp.index = count;
    if (ioctl(camera, VIDIOC_EXPBUF, &exp) != -1 || errno != EINVAL) {
        fprintf(stderr, "EXPBUF did not reject an invalid slot\n");
        return 1;
    }
    for (uint32_t i = 0; i < count; i++) {
        struct stat st;
        off_t size;

        exp.index = i;
        if (ioctl(camera, VIDIOC_EXPBUF, &exp) < 0) {
            fail("V4L2 EXPBUF");
        }
        fds[i] = exp.fd;
        size = lseek(exp.fd, 0, SEEK_END);
        if (size <= 0 || fstat(exp.fd, &st) < 0) {
            fail("exported dma-buf size");
        }
        sizes[i] = size;
        printf("EXPORT slot=%u inode=%" PRIu64 " bytes=%" PRIu64 "\n",
               i, (uint64_t)st.st_ino, sizes[i]);
        fflush(stdout);
    }
    /* Exported GPU objects must retain the storage after media closes. */
    close(camera);
    for (uint32_t i = 0; i < count; i++) {
        printf("SLOT %u ", i);
        fflush(stdout);
        ret |= gpu_check(fds[i], sizes[i], 0, false);
        close(fds[i]);
    }
    return ret;
}

static void queue_capture(int camera, int fd, uint32_t index)
{
    off_t size = lseek(fd, 0, SEEK_END);
    struct v4l2_buffer buffer = {
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = V4L2_MEMORY_DMABUF, .index = index, .m.fd = fd,
    };
    if (size < 0 || (uint64_t)size > UINT32_MAX) {
        fprintf(stderr, "invalid capture dma-buf size\n");
        exit(EXIT_FAILURE);
    }
    buffer.length = size;
    dmabuf_sync(fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_WRITE);
    if (ioctl(camera, VIDIOC_QBUF, &buffer) < 0) {
        int saved_errno = errno;
        dmabuf_sync(fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_WRITE);
        errno = saved_errno;
        fail("capture QBUF");
    }
}

/* One frame is loaned at a time; RELEASE follows completion of every reader. */
static int capture(const char *path, uint32_t width, uint32_t height,
                    uint32_t count, int *fds)
{
    int camera = open(path, O_RDWR | O_CLOEXEC);
    struct v4l2_format format = { .type = V4L2_BUF_TYPE_VIDEO_CAPTURE };
    struct v4l2_requestbuffers request = {
        .count = count, .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = V4L2_MEMORY_DMABUF,
    };
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    bool queued[MAX_BUFFERS] = { false };

    if (camera < 0) {
        fail("camera open");
    }
    format.fmt.pix.width = width;
    format.fmt.pix.height = height;
    format.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    format.fmt.pix.field = V4L2_FIELD_NONE;
    if (ioctl(camera, VIDIOC_S_FMT, &format) < 0 ||
        format.fmt.pix.width != width || format.fmt.pix.height != height ||
        format.fmt.pix.pixelformat != V4L2_PIX_FMT_YUYV) {
        fprintf(stderr, "camera did not accept the requested YUYV format\n");
        return 1;
    }
    if (ioctl(camera, VIDIOC_REQBUFS, &request) < 0 || request.count < count) {
        fail("capture REQBUFS");
    }
    for (uint32_t i = 0; i < count; i++) {
        off_t size = lseek(fds[i], 0, SEEK_END);
        if (size < 0 || (uint64_t)size < format.fmt.pix.sizeimage) {
            fprintf(stderr, "capture buffer too small\n");
            return 1;
        }
        queue_capture(camera, fds[i], i);
        queued[i] = true;
    }
    if (ioctl(camera, VIDIOC_STREAMON, &type) < 0) {
        fail("capture STREAMON");
    }
    for (;;) {
        struct v4l2_buffer buffer = { .type = type,
                                     .memory = V4L2_MEMORY_DMABUF };
        char *line = NULL;
        size_t capacity = 0;
        uint32_t index, sequence;
        if (ioctl(camera, VIDIOC_DQBUF, &buffer) < 0) {
            fail("capture DQBUF");
        }
        if (buffer.index >= count) {
            fprintf(stderr, "invalid capture index\n");
            return 1;
        }
        queued[buffer.index] = false;
        dmabuf_sync(fds[buffer.index], DMA_BUF_SYNC_END | DMA_BUF_SYNC_WRITE);
        printf("FRAME %u %u %u\n", buffer.index,
               buffer.bytesused, buffer.sequence);
        fflush(stdout);
        ssize_t length = getline(&line, &capacity, stdin);
        if (length < 0 || !strcmp(line, "STOP\n")) {
            free(line);
            break;
        }
        if (sscanf(line, "RELEASE %u %u", &index, &sequence) != 2 ||
            index != buffer.index || sequence != buffer.sequence) {
            fprintf(stderr, "invalid capture release\n");
            free(line);
            return 1;
        }
        free(line);
        queue_capture(camera, fds[buffer.index], buffer.index);
        queued[buffer.index] = true;
    }
    if (ioctl(camera, VIDIOC_STREAMOFF, &type) < 0) {
        fail("capture STREAMOFF");
    }
    for (uint32_t i = 0; i < count; i++) {
        if (queued[i]) {
            dmabuf_sync(fds[i], DMA_BUF_SYNC_END | DMA_BUF_SYNC_WRITE);
        }
    }
    close(camera);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 5 && !strcmp(argv[1], "native")) {
        return gpu_check(number(argv[2]), number(argv[3]), number(argv[4]),
                         true);
    }
    if (argc == 4 && !strcmp(argv[1], "v4l2")) {
        return v4l2_check(argv[2], number(argv[3]));
    }
    if (argc >= 4 && argc <= 6 && !strcmp(argv[1], "guest")) {
        return guest_check(number(argv[2]), number(argv[3]),
                            argc > 4 ? number(argv[4]) : 0,
                            argc > 5 ? number(argv[5]) : 4);
    }
    if (argc >= 7 && argc <= 5 + MAX_BUFFERS && !strcmp(argv[1], "capture")) {
        int fds[MAX_BUFFERS];
        for (int i = 5; i < argc; i++) {
            fds[i - 5] = number(argv[i]);
        }
        return capture(argv[2], number(argv[3]), number(argv[4]),
                       argc - 5, fds);
    }
    fprintf(stderr, "usage:\n"
            "  %s native FD SIZE EXPECTED_FNV32\n"
            "  %s guest SIZE EXPECTED_FNV32 [SLOT [CAPSET]]\n"
            "  %s capture DEVICE WIDTH HEIGHT FD0 FD1 ...\n",
            argv[0], argv[0], argv[0]);
    fprintf(stderr, "  %s v4l2 DEVICE COUNT  (frozen pool only)\n", argv[0]);
    return 1;
}
