# KPM Makefile — aligned with SukiSU / kpm-dev-kit rules
#
# Usage:
#   NDK_PATH=/path/to/android-ndk KP_DIR=/path/to/KernelPatch make
#   （或直接设 TARGET_COMPILE 指向 clang 前缀）
#   make check   # 产物静态自检 (scripts/check_kpm.sh)
#
# CI: .github/workflows/build.yml

ifeq ($(OS), Windows_NT)
    PLATFORM := windows-x86_64
else
    PLATFORM := linux-x86_64
endif

ifndef NDK_PATH
    # Fallback: try TARGET_COMPILE if set directly
    ifneq ($(TARGET_COMPILE),)
        CC = $(TARGET_COMPILE)clang
        STRIP = $(TARGET_COMPILE)llvm-strip
    else
        $(error NDK_PATH not set — point it to your Android NDK root, or set TARGET_COMPILE)
    endif
else
    TARGET_COMPILE := $(NDK_PATH)/toolchains/llvm/prebuilt/$(PLATFORM)/bin/
    CC = $(TARGET_COMPILE)aarch64-linux-android31-clang
    STRIP = $(TARGET_COMPILE)llvm-strip
endif

ifndef KP_DIR
    KP_DIR ?= ../KernelPatch
endif

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS = $(INCLUDE_FLAGS) -Wall -O2 -fno-PIC -fno-pie \
         -fno-asynchronous-unwind-tables -fno-stack-protector \
         -fno-unwind-tables -fno-semantic-interposition \
         -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden

LDFLAGS += -s

TARGET := hero_reader.kpm
SRC := hero_reader.c
LDS := hero_reader.lds

all: $(TARGET)

$(TARGET): $(SRC) $(LDS)
	$(CC) $(CFLAGS) -T$(LDS) -c -o hero_reader.o $<
	$(CC) $(LDFLAGS) -r -T$(LDS) -o $@ hero_reader.o
	$(STRIP) -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack $@
	rm -f hero_reader.o

check: $(TARGET)
	sh scripts/check_kpm.sh $(TARGET)

clean:
	rm -f *.kpm *.o

.PHONY: clean check
