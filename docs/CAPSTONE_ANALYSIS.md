# libGameCore.so capstone 静态分析结果 (2026-10-14)

## 分析方法
- 工具: Python capstone (CS_ARCH_ARM64, CS_MODE_ARM), 不使用 IDA
- 分析范围: ELF段表解析 + .text全段反汇编 + 重定位分析 + IL2CPP metadata解析

---

## 核心发现: 指针链断裂点

### 问题
当前 KPM 路径走 IL2CPP 的 `static_fields + ??? → C++ 对象`, 但:
**C++ GameTacticsManager 对象不在 IL2CPP 的 static_fields 中**
**它存储在 libGameCore.so 自己的 .bss 段全局变量中**

### 根因 (libGameCore.so 与 IL2CPP 是完全解耦的)
- libGameCore.so 不导入任何 il2cpp_* 函数 (672 个 PLT 导入中无 il2cpp)
- libGameCore.so 不包含 "il2cpp" 或 "static_field" 字符串
- C++ 对象由 libGameCore.so 内部的延迟初始化(lazy-init)创建和存储
- C# 代码通过 P/Invoke 调用 libGameCore.so 的导出函数触发初始化
- 但对象指针本身存储在 libGameCore.so 的 BSS 全局变量中, 不在 C# 堆中

### 修正的指针链

```
libGameCore_base + 0x53ddb90      → GameTacticsManager C++ 对象指针 (.bss 全局)
  对象 + 0x220                      → UnitLabelFinder 子对象
  UnitLabelFinder + 0xC8           → UnitLabel 数组 begin
  UnitLabelFinder + 0xD0           → UnitLabel 数组 end
  UnitLabel[i] + 0x0C              → camp_id (u32)
  UnitLabel[i] + 0x14              → x_pos (u32)
  UnitLabel[i] + 0x1C              → z_pos (u32)
  UnitLabel[i] + 0x2C              → hp (u32, >=1 有效)
  遍历步长: 0xB8 (184 字节)
```

### 旧路径 (已确认断裂)
```
libil2cpp_base + 0xE344EA0 → s_domain → ... → class + 0xB8 → static_fields
static_fields + ??? → C++ 对象  ← 断裂! C++ 对象不在 C# static_fields 中
```

---

## 详细证据

### 1. 延迟初始化函数 (lazy-init) @ vaddr 0x03167510

```asm
0x03167510: adrp     x19, #0x53dd000          ← .bss 页基址
0x03167514: ldr      x0, [x19, #0xb90]        ← x0 = *(0x53ddb90) ← 全局对象指针!
0x03167518: cbz      x0, #0x3167524           ← 已初始化则跳过
0x0316751c: ldp      x30, x19, [sp], #0x10
0x03167520: ret

; 创建新对象:
0x03167524: mov      w0, #0x38c0              ← 分配 0x38c0 (14528) 字节
0x03167528: bl       #0x4b40050               ← malloc(0x38c0)
0x0316752c: adrp     x1, #0x5046000
0x03167530: add      x1, x1, #0x460           ← x1 = *(0x5046460) = 构造函数指针
0x03167534: bl       #0x21b054c               ← 构造(对象, 构造函数指针)
0x03167538: str      x0, [x19, #0xb90]        ← *(0x53ddb90) = 新对象指针 ← 存储!
0x0316753c: ldp      x30, x19, [sp], #0x10
0x03167540: ret
```

### 2. 构造函数 @ vaddr 0x3166ce0

创建多个子对象, 间距 0xF0:
```
x19 + 0x0F0 → sub-object 1 (constructor 0x311fea8)
x19 + 0x1E0 → sub-object 2 (constructor 0x30b2338)
x19 + 0x2D8 → sub-object 3 (constructor 0x30e5374)
x19 + 0x3C8 → sub-object 4 (constructor 0x30e4844)
x19 + 0x4B8 → sub-object 5
x19 + 0x5A8 → sub-object 6
x19 + 0x698 → sub-object 7
x19 + 0x788 → sub-object 8
x19 + 0x878 → sub-object 9
x19 + 0x968 → sub-object 10
x19 + 0xA58 → sub-object 11
```
+0x220 (UnitLabelFinder) 在 +0x1E0 子对象范围内 (0x1E0 ≤ 0x220 < 0x2D8)

### 3. Init 函数 @ vaddr 0x276a198 (file_off 0x2769198)

```asm
0x276a1bc: mov      x24, x0              ← x24 = 对象 (参数0)
; ... 初始化各种字段 (0x64, 0x148, 0x140, 0x3a0, 0x414, 0x424, 0x470, 0x4A0...)
; x24 从不存储到任何全局变量 (仅存到 sp+0x160 栈保存)
0x276abc8: add      x0, x24, #0x220      ← x0 = 对象+0x220 = UnitLabelFinder
0x276abcc: ldr      x8, [x8, #0xd30]     ← 初始化函数指针
0x276abd4: blr      x8                   ← 调用 UnitLabelFinder 初始化
; 字符串引用:
;   "fail_to_init_unit_label_finder" @ 0x11ed4f1
;   "comatk_unit_label_size" @ 0x118d2f2
;   "TacticsMultiTaskTwoHandAction" @ 0x113f2de
;   "[Init] init start" @ 0x114c930
;   "ai_tactics::GameTacticsManager::Init() " @ 0x11a6c8e
```

### 4. 全局对象读取点 @ vaddr 0x02f98b24

```asm
0x02f98b20: adrp     x8, #0x5102000
0x02f98b24: ldr      x1, [x8, #0xb90]     ← x1 = *(0x53ddb90) = 对象指针
```
两个引用点: accessor (lazy-init) + 使用点

### 5. 注册表与 dispatch 分析

注册表在 .rodata (0x0c471a0 区域), 格式为三元组 {type=0x403, func_ptr, slot_addr}:
- GetPosFromMonster (func=0x24b2590) → slot=0x508adf0
- Init (func=0x276a198) → slot=0x509b580

通过 R_AARCH64_RELATIVE (type=1027) 重定位填充:
- `*(0x508adf0) = base + 0x24b2590` → GetPosFromMonster 函数指针
- `*(0x509b580) = base + 0x276a198` → Init 函数指针

这些是函数指针表 (dispatch table), 不是对象指针存储。

### 6. ELF 段映射确认

```
.text:    vaddr=0x02185770, file_off=0x02184770, delta=+0x1000
.rodata:  vaddr=0x00fbe3a0, file_off=0x00fbe3a0 (同址)
.data:    vaddr=0x04ff8890, file_off=0x04ff5890
.bss:     vaddr=0x0526f000, file_off=N/A (零初始化), size=0x001de478
```

0x53ddb90 确认在 .bss 范围内 (0x526f000 ≤ 0x53ddb90 < 0x544d478)

---

## IL2CPP Metadata 辅助信息

- IL2CPP v29, magic 0xFAB11BAF, 未加密
- typedef 结构体大小 = 88 字节
- BattleLogic (Assets.Scripts.GameLogic.BattleLogic) = 类型 #42279
- ActorManager (Assets.Scripts.GameLogic.ActorManager) = 类型 #42984
- static_fields 偏移: class + 0xB8 (IDA确认)

---

## KPM 修改建议

### 当前代码问题
hero_reader.c 通过 libil2cpp.so 的 s_domain → assemblies → classes → static_fields
寻找 C++ 对象指针。但 C++ 对象不在 C# static_fields 中。

### 修改方案
1. 添加 libGameCore.so base 查找 (类似 libil2cpp base 的 VMA 扫描)
   - 扫描匹配 ELF magic 的可执行 VMA
   - 验证: 读取 *(libGameCore_base + 0x508ac00) 是否为有效函数指针
     (应指向 .text 范围内的地址)

2. 读取 GameTacticsManager 指针:
   ```c
   // libGameCore.so base + 0x53ddb90 → GameTacticsManager C++ 对象
   unsigned long gc_base = ...;  // libGameCore.so base
   unsigned long manager_ptr;
   if (!rm(&manager_ptr, gc_base + 0x53ddb90, sizeof(manager_ptr)))
       return;  // 读取失败
   if (!manager_ptr) return;  // 对象未初始化
   ```

3. 获取 UnitLabel 数组:
   ```c
   unsigned long ulf_ptr;  // UnitLabelFinder
   if (!rm(&ulf_ptr, manager_ptr + 0x220, sizeof(ulf_ptr)))
       return;
   unsigned long begin, end;
   if (!rm(&begin, ulf_ptr + 0xC8, sizeof(begin)))
       return;
   if (!rm(&end, ulf_ptr + 0xD0, sizeof(end)))
       return;
   // 遍历: 步长 0xB8, 从 begin 到 end
   for (unsigned long p = begin; p < end; p += 0xB8) {
       uint32_t camp, hp, x, z;
       rm(&camp, p + 0x0C, 4);
       rm(&hp,   p + 0x2C, 4);
       rm(&x,    p + 0x14, 4);
       rm(&z,    p + 0x1C, 4);
       if (hp < 1) continue;  // 无效
       // ... 使用 camp/x/z
   }
   ```
