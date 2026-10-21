# KPM Makefile — Termux clang / Android NDK 双支持 (kpm-dev-kit 规则)
#
# 用法:
#   make KP_DIR=/path/to/SukiSU_KernelPatch_patch      # Termux clang 直接构建 (推荐)
#   make NDK_PATH=/path/to/android-ndk KP_DIR=...      # 用 NDK 交叉工具链
#   make check                                         # 产物静态自检
#
# CI: .github/workflows/build.yml

ifeq ($(OS), Windows_NT)
    PLATFORM := windows-x86_64
else
    PLATFORM := linux-x86_64
endif

# 默认用 Termux/系统 clang (aarch64), 也支持 NDK 工具链
ifdef NDK_PATH
    TARGET_COMPILE := $(NDK_PATH)/toolchains/llvm/prebuilt/$(PLATFORM)/bin/
    CC := $(TARGET_COMPILE)aarch64-linux-android31-clang
    STRIP := $(TARGET_COMPILE)llvm-strip
else
    CC ?= clang
    STRIP ?= llvm-strip
endif

KP_DIR ?= ../KP-SUKISU

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS = $(INCLUDE_FLAGS) -Wall -O2 -fno-PIC -fno-pie \
         -fno-asynchronous-unwind-tables -fno-stack-protector \
         -fno-unwind-tables -fno-semantic-interposition \
         -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden

LDFLAGS += -s

TARGET := hero_reader.kpm
OBJ := hero_reader.o
SRC := hero_reader.c
LDS := hero_reader.lds

all: $(TARGET)

$(TARGET): $(SRC) $(LDS)
	$(CC) $(CFLAGS) -c -o $(OBJ) $<
	$(CC) $(LDFLAGS) -r -T$(LDS) -o $@ $(OBJ)
	$(STRIP) -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack $@
	rm -f $(OBJ)

check: $(TARGET)
	sh scripts/check_kpm.sh $(TARGET)

clean:
	rm -f *.kpm *.o

.PHONY: clean check
