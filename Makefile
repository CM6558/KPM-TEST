# KernelPatch Module Makefile
# Build: make
# Output: hero_reader.kpm

# Toolchain — 需要裸机 ARM64 交叉编译器
# 安装: sudo apt install gcc-aarch64-linux-gnu
# 或用 NDK: export CC=aarch64-linux-android24-clang
CC ?= aarch64-linux-gnu-gcc

# KernelPatch source root (clone from github.com/bmax121/KernelPatch)
KP_ROOT ?= $(HOME)/KernelPatch

# Include paths
CFLAGS := -nostdlib -nostartfiles -ffreestanding -fno-stack-protector \
          -fno-common -fno-builtin -fno-asynchronous-unwind-tables \
          -fno-omit-frame-pointer -Wall -Wextra -O2 \
          -I$(KP_ROOT)/kernel/include \
          -I$(KP_ROOT)/kernel/patch/include \
          -I$(KP_ROOT)/kernel/patch/include/uapi \
          -I$(KP_ROOT)/kernel/patch/include/linux

LDFLAGS := -r -e init

# Target
TARGET := hero_reader.kpm
SRC := hero_reader.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: clean
