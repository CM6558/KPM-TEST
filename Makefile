# KPM Makefile — aligned with official KernelPatch demo Makefile structure
# Usage:
#   export TARGET_COMPILE=aarch64-none-elf-
#   export KP_DIR=/path/to/KernelPatch
#   make

ifndef TARGET_COMPILE
    TARGET_COMPILE ?= aarch64-linux-gnu-
endif

ifndef KP_DIR
    KP_DIR ?= $(HOME)/KernelPatch
endif

CC = $(TARGET_COMPILE)gcc

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS := -nostdlib -nostartfiles -ffreestanding -fno-stack-protector \
          -fno-common -fno-builtin -fno-asynchronous-unwind-tables \
          -fno-omit-frame-pointer -Wall -Wextra -O2

TARGET := hero_reader.kpm
SRC := hero_reader.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -r -o $@ $<

# Linker script to suppress unwanted sections
hero_reader.lds:
	@echo "SECTIONS {" > $@
	@echo "  .plt (NOLOAD) : { BYTE(0) }" >> $@
	@echo "  .init.plt (NOLOAD) : { BYTE(0) }" >> $@
	@echo "  .text.ftrace_trampoline (NOLOAD) : { BYTE(0) }" >> $@
	@echo "}" >> $@

clean:
	rm -f *.kpm *.o *.lds

.PHONY: clean
