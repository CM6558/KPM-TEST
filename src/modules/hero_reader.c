/* hero_reader.c — 主入口 (模块化拆分后)
 *
 * 王者荣耀 hero-reader KPM (Kernel Patch Module) - 主文件
 * 目标: com.tencent.tmgp.sgame -> libGameCore.so 内 Hero 实时坐标读取
 *
 * 架构: 各功能拆到 hr_*.c, 公共声明在 hr_internal.h
 *   hr_pagewalk.c     — 页表/VMA/ELF base 定位
 *   hr_metadata.c     — IL2CPP metadata
 *   hr_il2cpp_scan.c  — IL2CPP class/field 扫描
 *   hr_actor_chain.c  — ★ GameRoot->Hero->Transform->VInt3 坐标链
 *   hr_diag.c         — 诊断命令
 *   hr_lifecycle.c   — 生命周期/init/ctl0
 *   hr_internal.h    — 公共头
 *
 * Makefile 不变,只是把 hero_reader.c 编译产物改为包含以下 c 文件即可。
 */

#include "hr_internal.h"

/* 模块直接 include 源码(单 .o 编译) */
#include "hr_pagewalk.c"
#include "hr_metadata.c"
#include "hr_il2cpp_scan.c"
#include "hr_actor_chain.c"
#include "hr_diag.c"
#include "hr_lifecycle.c"
