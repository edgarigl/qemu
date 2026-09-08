# SPDX-License-Identifier: GPL-2.0-or-later
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Werror
CPPFLAGS += $(shell pkg-config --cflags libdrm vulkan)
LDLIBS += $(shell pkg-config --libs libdrm vulkan)

all: blob-check

blob-check: blob-check.c virtgpu-blob.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDLIBS) -o $@

clean:
	rm -f blob-check

.PHONY: all clean
