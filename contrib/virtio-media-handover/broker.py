#!/usr/bin/env python3
"""Exercise a dom0-owned dma-buf pool with native and guest GPU consumers.

QMP installs fds once. A frame is released only after every reader's GPU has
finished. This deliberately slow harness tests storage and ownership, not FPS.
"""
import argparse
import array
import concurrent.futures
import ctypes
import fcntl
import json
import mmap
import os
from pathlib import Path
import random
import select
import shlex
import socket
import struct
import subprocess
import sys

DMA_BUF_IOCTL_SYNC = 0x40086200
SYNC_READ = 1
SYNC_WRITE = 2
SYNC_END = 4


def sync(fd: int, flags: int) -> None:
    fcntl.ioctl(fd, DMA_BUF_IOCTL_SYNC, struct.pack("=Q", flags))


def checksum(view: mmap.mmap) -> int:
    value = 2166136261
    for byte in memoryview(view):
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return value


class Pool:
    def __init__(self, width, height, count):
        self.library = ctypes.CDLL("libgbm.so.1", use_errno=True)
        signatures = {
            "gbm_create_device": (ctypes.c_void_p, [ctypes.c_int]),
            "gbm_device_destroy": (None, [ctypes.c_void_p]),
            "gbm_bo_create": (ctypes.c_void_p, [ctypes.c_void_p] +
                              [ctypes.c_uint32] * 4),
            "gbm_bo_get_fd": (ctypes.c_int, [ctypes.c_void_p]),
            "gbm_bo_destroy": (None, [ctypes.c_void_p]),
        }
        for name, (result, arguments) in signatures.items():
            function = getattr(self.library, name)
            function.restype = result
            function.argtypes = arguments
        self.render = os.open("/dev/dri/renderD128", os.O_RDWR | os.O_CLOEXEC)
        self.device = self.library.gbm_create_device(self.render)
        self.buffers = []
        if not self.device:
            raise OSError(ctypes.get_errno(), "gbm_create_device")
        try:
            for _ in range(count):
                # Linear ARGB storage has enough space for the YUYV test source.
                bo = self.library.gbm_bo_create(self.device, width, height,
                                                int.from_bytes(b"AR24", "little"),
                                                (1 << 2) | (1 << 4))
                if not bo:
                    raise OSError(ctypes.get_errno(), "gbm_bo_create")
                fd = self.library.gbm_bo_get_fd(bo)
                if fd < 0:
                    self.library.gbm_bo_destroy(bo)
                    raise OSError(ctypes.get_errno(), "gbm_bo_get_fd")
                try:
                    size = os.lseek(fd, 0, os.SEEK_END)
                    view = mmap.mmap(fd, size, flags=mmap.MAP_SHARED,
                                     prot=mmap.PROT_READ | mmap.PROT_WRITE)
                except BaseException:
                    os.close(fd)
                    self.library.gbm_bo_destroy(bo)
                    raise
                self.buffers.append((bo, fd, size, view))
                sync(fd, SYNC_WRITE)
                view[:] = bytes(size)
                sync(fd, SYNC_END | SYNC_WRITE)
        except BaseException:
            self.close()
            raise

    def close(self):
        for bo, fd, _, view in self.buffers:
            view.close()
            os.close(fd)
            self.library.gbm_bo_destroy(bo)
        self.buffers.clear()
        self.library.gbm_device_destroy(self.device)
        os.close(self.render)


class Qmp:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(15)
        self.socket.connect(path)
        self.reader = self.socket.makefile("rb")
        greeting = json.loads(self.reader.readline())
        if "QMP" not in greeting:
            raise RuntimeError("missing QMP greeting")
        self.execute("qmp_capabilities")

    def execute(self, command, arguments=None, fd=None):
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        data = (json.dumps(request) + "\n").encode()
        ancillary = []
        if fd is not None:
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                          array.array("i", [fd]))]
        sent = self.socket.sendmsg([data], ancillary)
        self.socket.sendall(data[sent:])
        while True:
            reply = self.reader.readline()
            if not reply:
                raise RuntimeError("QMP disconnected")
            response = json.loads(reply)
            if "error" in response:
                raise RuntimeError(response["error"])
            if "return" in response:
                return response["return"]

    def close(self):
        self.reader.close()
        self.socket.close()


def check(command: list[str], **kwargs) -> str:
    result = subprocess.run(command, check=True, text=True,
                            stdout=subprocess.PIPE, timeout=45, **kwargs)
    return result.stdout.strip()


def run(args) -> None:
    pool = Pool(args.width, args.height, args.buffers)
    clients = []
    installed = []
    capture = None
    local = str(Path(args.binary).resolve())
    native_env = dict(os.environ, VK_DRIVER_FILES=args.native_icd)
    try:
        for host, path, capset, icd in args.guest:
            client = Qmp(path)
            clients.append(client)
            existing = client.execute("query-fdsets")
            occupied = {item["fdset-id"] for item in existing}
            for slot, (_, fd, size, _) in enumerate(pool.buffers):
                fdset = args.fdset + slot
                if fdset in occupied:
                    raise RuntimeError(f"fdset {fdset} is already occupied")
                reply = client.execute("add-fd", {"fdset-id": fdset,
                                       "opaque": "dom0-camera-prototype"}, fd)
                installed.append((client, fdset, reply["fd"]))
                print(json.dumps({"guest": host, "slot": slot, "bytes": size,
                                  "host_inode": os.fstat(fd).st_ino,
                                  "qemu_fd": reply["fd"]}), flush=True)

        fds = [buffer[1] for buffer in pool.buffers]
        if args.camera:
            capture = subprocess.Popen([local, "capture", args.camera,
                                        str(args.width), str(args.height),
                                        *map(str, fds)], pass_fds=fds,
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, text=True)
        for frame in range(args.frames):
            slot = frame % args.buffers
            sequence = frame
            if capture:
                if not select.select([capture.stdout], [], [], 20)[0]:
                    raise TimeoutError("camera did not produce a frame")
                fields = capture.stdout.readline().split()
                if len(fields) != 4 or fields[0] != "FRAME":
                    raise RuntimeError(f"capture stopped: {fields}")
                slot, _, sequence = map(int, fields[1:])
            _, fd, size, view = pool.buffers[slot]
            if not capture:
                sync(fd, SYNC_WRITE)
                view[:] = random.Random(frame).randbytes(size)
                sync(fd, SYNC_END | SYNC_WRITE)
            sync(fd, SYNC_READ)
            expected = checksum(view)
            sync(fd, SYNC_END | SYNC_READ)
            jobs = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Keep native consumption for the first overlap frame too.
                if frame <= args.native_first or not args.guest:
                    jobs.append(("dom0", executor.submit(
                        check, [local, "native", str(fd), str(size), hex(expected)],
                        pass_fds=[fd], env=native_env)))
                if frame >= args.native_first:
                    for host, _, capset, icd in args.guest:
                        remote = shlex.join(["env", f"VK_DRIVER_FILES={icd}",
                                             args.guest_binary, "guest", str(size),
                                             hex(expected), str(slot), capset])
                        jobs.append((host, executor.submit(
                            check, ["ssh", "-o", "BatchMode=yes", "-o",
                                    "ConnectTimeout=10", host, remote])))
                for name, future in jobs:
                    print(f"frame={frame} slot={slot} reader={name} "
                          f"{future.result()}", flush=True)
            print(f"RELEASE slot={slot} sequence={sequence} readers={len(jobs)}",
                  flush=True)
            if capture:
                capture.stdin.write(f"RELEASE {slot} {sequence}\n")
                capture.stdin.flush()
    finally:
        if capture:
            try:
                capture.stdin.write("STOP\n")
                capture.stdin.flush()
                capture.wait(timeout=5)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                capture.terminate()
                capture.wait(timeout=5)
        # Stop capture before dropping refs, including on reader failure.
        failed_clients = set()
        for client, fdset, fd in installed:
            if client in failed_clients:
                continue
            try:
                client.execute("remove-fd", {"fdset-id": fdset, "fd": fd})
            except (OSError, RuntimeError, ValueError) as error:
                print(f"QMP cleanup failed: {error}", file=sys.stderr)
                failed_clients.add(client)
        for client in clients:
            client.close()
        pool.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest", nargs=4, action="append", default=[],
                        metavar=("USER@HOST", "QMP_SOCKET", "CAPSET", "ICD"))
    parser.add_argument("--binary", default="./blob-check")
    parser.add_argument("--guest-binary", default="/tmp/blob-check")
    parser.add_argument("--native-icd",
                        default="/usr/share/vulkan/icd.d/radeon_icd.json")
    parser.add_argument("--fdset", type=int, default=42)
    parser.add_argument("--buffers", type=int, default=4)
    parser.add_argument("--frames", type=int, default=8)
    parser.add_argument("--native-first", type=int, default=2)
    parser.add_argument("--width", type=int, default=64)
    parser.add_argument("--height", type=int, default=64)
    parser.add_argument("--camera", help="V4L2 capture node; otherwise use patterns")
    args = parser.parse_args()
    if not 2 <= args.buffers <= 16 or args.frames <= args.native_first:
        parser.error("use 2..16 buffers and more frames than native-first")
    if min(args.width, args.height) <= 0 or args.native_first < 0 or args.fdset < 0:
        parser.error("invalid size, frame count, or fdset")
    run(args)


if __name__ == "__main__":
    main()
