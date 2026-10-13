# KPM Makefile — aligned with SukiSU / KPM-Build-Anywhere template
#
# Usage:
#   Set NDK_PATH to your Android NDK root, then:
#   export KP_DIR=/path/to/KernelPatch  (or SukiSU_KernelPatch_patch)
#   make
#
# Or in CI: see .github/workflows/build.yml

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

CFLAGS = $(INCLUDE_FLAGS) -Wall -Ofast -fno-PIC \
         -fno-asynchronous-unwind-tables -fno-stack-protector \
         -fno-unwind-tables -fno-semantic-interposition \
         -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden

LDFLAGS += -s

TARGET := hero_reader.kpm
SRC := hero_reader.c
LDS := hero_reader.lds

all: $(TARGET)

$(TARGET): $(SRC) $(LDS)
	$(CC) $(CFLAGS) -T$(LDS) -c -O2 -o hero_reader.o $<
	$(CC) $(LDFLAGS) -r -o $@ hero_reader.o
	$(STRIP) -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack $@
	rm -f hero_reader.o

clean:
	rm -f *.kpm *.o

.PHONY: clean
