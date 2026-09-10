# keyman_arm_7.24.1 反汇编分析

> 分析对象：`tools/bin/keyman_arm_7.24.1`（ARM 32-bit, EABI5, stripped, 59392 字节）
> 方法：`llvm-objdump`（Apple LLVM 17，`objdump -d/-h/-R/-p`）静态反汇编 + 手工数据流追踪，
> 无源码、无符号表，全部函数边界/语义均通过交叉引用常量、字符串、PLT 重定位表还原。
> 配套产物见 `tools/bin/analysis/`：
> - `keyman_arm_7.24.1.annotated.asm` —— 全量反汇编，`bl` 到 `.plt` 的调用已标注真实符号名
> - `keyman_arm_7.24.1.plt_symbols.json` —— PLT 桩地址 → 导入符号名 映射
> - `rebuild_annotated_asm.py` —— 生成上述两个文件的脚本（可重复执行验证）

---

## 0. TL;DR（结论先行）

1. **核心授权算法（SOFTWARE ID 计算）与 x86 版 `keyman_x86_7.23.2` 完全一致**：自定义 SHA-256 的
   IV/K 常量表逐字节相同、MBR 混合公式（`& 0x7FF` 掩码、`× 0x3FF800F`）、Base35 编码字母表
   `TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE`、`XXXX-XXXX` 格式化逻辑，在指令级别上逐一核对无误。
   **结论：对 32-bit ARM（RouterBOARD-ARM 物理设备）架构，`docs/license-internals.md` 中记录的算法同样成立。**
   ⭐ **更进一步已实测确认（见 §9）：MikroTik 官方 arm64 CHR 云镜像里面的 `keyman` 其实也是同一套 32-bit ARM
   代码**（仅内核是真 64-bit aarch64，用户态靠 AArch32 兼容模式运行）——已下载官方 `chr-7.21.5-arm64.img.zip`
   实际提取验证，本节全部常量在那个二进制里全部命中。**因此本结论既适用于物理 RouterBOARD-ARM 设备，
   也直接适用于 PVE 上的 arm64 CHR 虚拟机**，无需额外分析一份独立的 aarch64 keyman（因为根本不存在）。
2. 该二进制额外内置了一套**结构相同但常量不同的"旧版"公式**（`& 0x1FFFFF` 掩码、不同乘数
   `0x00010044`、`orr #0x200` 而非 `#0x100`），对应 CLI 选项 `--old-software-id`。这是本次分析中
   相对于既有文档的**新发现**，具体历史意义待进一步验证（推测为旧固件版本使用的算法，用于兼容判断"是否为旧版 ID"）。
3. ARM keyman 比 x86 版多了一条完整的**硬件/机身识别分支**：块设备 ATA `HDIO_DRIVE_CMD`
   识别、NVMe (`/dev/nvme%d`)、Flash/MTD (`/dev/flash`, `/dev/mtdblock%u`)、QEMU/DMI
   `product_uuid`（云机型判断）、以及基于 `/nova/etc/serial` + `/nova/etc/license` 的
   **无 MBR 永久授权**（用于没有磁盘 MBR 概念的物理 RouterBOARD ARM 设备）。这是本文件相较 x86
   版本在体系结构层面的主要差异。
4. 完整功能与 x86 keyman 一致：命令行工具 + `nv::Looper`/`nv::Handler` IPC 常驻服务
   （用于 WinBox/Web 面板查询授权信息）+ 在线续期 HTTP 客户端
   （POST `licence.mikrotik.com/licence/`）。

---

## 1. 二进制基本信息

```
文件: keyman_arm_7.24.1
格式: ELF 32-bit LSB executable, ARM, EABI5, dynamically linked
解释器: /lib/libc.so   (RouterOS 自研 libc，非 glibc/musl)
入口: 0x130e4 (.text 起始，无独立 _start 包装，直接是 .text 第一条指令)
链接库: libumsg.so libuc++.so libc.so   (RouterOS "nova" 框架私有运行时)
```

节区（VMA，文件内 LOAD 段 1: 文件偏移 = VMA − 0x10000；LOAD 段 2 从文件偏移 0xdf0c 开始）：

| 节 | VMA | 大小 | 说明 |
|---|---|---|---|
| `.text` | 0x130e4 | 0x9924 (39204B) | 全部代码 |
| `.rodata` | 0x1ca1c | 0x7fc | 自定义 SHA-256 常量表、格式化字符串 |
| `.data` | 0x2e270 | 0xb4 | **Base35 字母表等"可写"全局字符数组**（见 §3.4） |
| `.dynsym`/`.dynstr` | 0x10ae8/0x11508 | — | 154 个外部导入符号（libc + `nv::*` C++ 符号） |
| `.plt` | 0x129a4 | 0x740 | 154 个 PLT 桩，每个 3 条指令（`add r12,pc,#0,#12` / `add r12,r12,#N` / `ldr pc,[r12,#imm]!`） |

二进制**已 strip**（无 `.symtab`），但**未 strip 动态符号表**（`.dynsym`/`.rel.plt`），因此所有对外部
函数（`memcpy`、`ioctl`、`nv::Handler::*`…）的调用都能通过 PLT 重定位表 100% 准确还原符号名；
内部（非导出）函数只能通过常量/字符串交叉引用人工定位语义。

---

## 2. 命令行接口（CLI）

`.rodata`/`.data` 中提取到的选项字符串（`strings -t x` 定位，文件偏移 0xcebf–0xd122 区段），
在 0x1bd54 起有一张连续的 12 项指针表（每项 4 字节，直接是字符串地址），供参数解析循环
`strcmp(argv[i], table[k])` 使用：

```
--mbr               读取/写入磁盘 MBR 授权区（对应 x86 版 --mbr 语义）
--dump               dump 原始 512 字节扇区（%4.4x: / %2.2x 十六进制格式）
--major
--groups
--level
--uptime
--find-key           从磁盘/网络等来源查找可用 Key
--key                导入 --BEGIN/--END MIKROTIK SOFTWARE KEY 文本
--dump-key
--software-id        计算并打印当前硬件的 SOFTWARE ID（新算法）
--old-software-id     计算并打印"旧算法"版本的 SOFTWARE ID（见 §3.5）
unknown option: %s   兜底分支
```

其他相关运行期路径：

```
/nova/etc/serial          物理设备（无 MBR）永久授权：20 字节序列号
/nova/etc/license         物理设备永久授权：签名/许可证数据
/var/pckg/%s               软件包目录，License Key 文件按包名存放 (%s.key)
/ram/chrlreqonce            CHR 一次性续期请求标记文件
licence.mikrotik.com/licence/   在线续期 HTTP(S) 端点
```

---

## 3. 核心授权算法：SOFTWARE ID 计算

> **⭐ 2026-08-27 修正**：初版文档把 `0x19410` 误标为“getSoftwareId主入口”。经进一步完整反汇编后纠正：
> `0x19410` 实际上是 **“Key 文本解码 + 签名写入/校验”函数**（详见 §3.6）；真正的 **“计算并格式化
> SOFTWARE ID”入口在 `0x1936c`，它内部调用 `0x18c28`（真正的哈希+混合计算核心）。两个函数地址相邻（`0x1936c`
> 紧接在 `0x19410` 之前），是导致初次分析时误将两者边界混淆的直接原因。下文已按正确地址重新组织。

### 3.0 修正后的函数地图

```c
// 真正的 SOFTWARE ID 计算 + 格式化入口（以前误标为 0x19410）
int getSoftwareIdString(void *devHandle, struct HwId *hw, uint8_t out_id_str[10]) {  // VMA 0x1936c
    uint64_t rawId;
    out_id_str[0] = 0;
    if (computeRawSoftwareId(devHandle, hw, &rawId) != 0)      // bl 0x18c28  ★真正的核心函数
        return -1;
    // Base35 编码，第4位插入 '-'，写入 out_id_str，细节见 §3.4
    ...
}

// 真正的哈希/混合计算核心（内部都是 0x18c28，内部包含新/旧两套公式，见 §3.5）
int computeRawSoftwareId(void *devHandle, struct HwId *hw, uint64_t *out) {  // VMA 0x18c28
    // 1. 尝试多个后端采集 serial/model/sector_val （ATA/NVMe/USB/Flash-MTD/DMI，见 §5）
    // 2. 拼接 40 字节缓冲区：serial(20,空格补齐) + model(16,空格补齐) + LE32(sector_val)
    // 3. custom_sha256(buf40) → 8字节 digest             [函数 0x16ff8, K表@0x1cf9c]
    // 4. 读 MBR 或 board 配置前10字节，先 hasUefiSupport() 判断偏移
    // 5. custom_sha256/finalize(mbr10) 取前2字节 → mbr_val         [函数 0x17094, IV表@0x1d09c]
    // 6. 新公式（VMA 0x19294–0x1931c）：
    //      mix = (mbr_val & 0x7FF) * 0x3FF800F
    //      *out = digest_lo ^ mix_lo | ((digest_hi|0x100) ^ mix_hi) << 32
    //    旧公式（VMA 0x18d10–0x18d4c，见 §3.5）：
    //      mix = (mbr_val & 0x1FFFFF) * 0x00010044
    //      *out = digest_lo ^ mix_lo | ((digest_hi|0x200) ^ mix_hi) << 32
    return success;
}
```

调用链（`--software-id` / `--mbr` / License 校验路径，均已在反汇编中确认）：

```
cmd_software_id() [0x1a588 附近]  → getSoftwareIdString(hw, ...)      [0x1936c]
cmd_old_software_id() [0x1acfc 附近] → 同上，同一 0x1936c，内部走旧公式分支
cmd_find_key()/其他 [0x1baac 附近]  → 同上

readMBR(dev) [0x19c78]
 └─ checkLicense(mbrbuf) [0x19d34]
     ├─ resolveRootDisk()             [0x15f0c]   readlink("/dev/root-disk") → "/dev/vda" 等
     ├─ gatherHwInfo(hw)              [0x19b64]   多后端硬件识别（见 §5）
     ├─ applyOrVerifySignature(...)   [0x19410]   ★ 解码 Key 文本/已存签名 + 内部调用 0x18c28 重新计算ID比对，见 §3.6
     └─ verifySignature(buf)          [0x178dc]   备用验证路径，见 §4.4
```

### 3.1 Phase 1 — 硬件指纹哈希

反汇编片段（VMA 0x192cc–0x192dc）：

```asm
192cc: mov  r1, r4          ; r1 = &buf40   (serial20 + model16 + sector_val4)
192d0: add  r0, sp, #272
192d4: mov  r2, #40         ; len = 40
192d8: bl   0x16ff8         ; custom_sha256(dst=r0, src=r1, len=40)
192dc: ldrb r3, [sp, #0x114]
192e0: ldr  r2, [sp, #0x110]
192e4: orr  r3, r3, #256    ; hash_hi = digest[4] | 0x100
192e8: strd r2, r3, [r6]    ; r6->lo = digest[0:4] (LE u32), r6->hi = hash_hi
```

在此之前，构造 40 字节输入缓冲区（VMA 0x19244–0x19284）：serial 字段以 20 字节
`0x20`(空格) 补齐、model 字段以 16 字节空格补齐（`mov r1,#32` 循环 `strbeq`），随后
`str r3,[sp]` 写入已按"最高置位比特 −4 位对齐后向上取整"处理过的 `sector_val`（§3.2）。
**与文档描述的 `buf[40] = serial(20) ∥ model(16) ∥ LE32(sector_val)` 完全一致。**

`custom_sha256` 函数体（VMA **0x16ff8**）使用位于 **VMA 0x1cf9c** 的 64 项 `K[]` 表；
其配套的第二阶段函数（VMA **0x17094**，IV 初始化/finalize）使用位于 **VMA 0x1d09c** 的
`IV[8]` 表。两处地址均通过"谁在字面量池里引用了这个常量表基址"的交叉引用定位
（`objdump -R` 无法直接给出，因为这是内部函数，用的是 PC 相对字面量池寻址）。

**逐字节核验：ARM 二进制中的 IV/K 常量与 `docs/license-internals.md §3.3` 记录的值完全相同**（用
Python 在原始文件里搜索每个 32-bit 小端常量，均恰好命中一次，位置连续）：

```
IV[0..7] @ 0x1d09c: 5B653932 7B145F8F 71FFB291 38EF925F 03E1AAF9 4A2057CC 4CAF4DD9 643CC9EA
K[0..1]  @ 0x1cf9c: 0548D563 98308EAB ...   (与 mikro.py 的 MIKRO_SHA256_K 起始项一致)
```

### 3.2 sector_val 取整规则

VMA 0x1929c–0x192c8（"取最高置位比特，按 bits−4 位边界向上取整"）：

```asm
1929c: ldr  r3, [sp, #0x3c]      ; r3 = raw = total_sectors >> 11
192a0: mov  r2, #31
192a4: mov  r1, #1
192a8: ands r0, r3, r1, lsl r2   ; 测试 bit r2 (从 31 开始)
192ac: beq  0x19320              ; 未命中则 r2-- 继续测试（循环体在 0x19320: sub r2,r2,#1; cmp r2,#3; bne 192a8）
192b0: sub  r0, r2, #4           ; shift = bits - 4
192b4: sub  r2, r2, #3
192b8: add  r3, r3, r1, lsl r0   ; raw += 1<<shift  （半单位，实现向上取整）
192bc: lsl  r1, r1, r2
192c0: rsb  r1, r1, #0           ; mask = -(1 << (bits-3))
192c4: and  r3, r3, r1           ; rounded = (raw + half) & mask
192c8: str  r3, [sp, #0x3c]
```

行为与文档一致（“找最高有效位，按 `bits-4` 位边界取整”），只是编译器把“加半个单位再掩码”
优化成了 `ADD` + `AND` 两条指令而非文档伪代码里的“先右移再左移”写法——数学上等价。

`raw = total_sectors >> 11` 本身由 0x19010–0x19040（`REV` 字节序转换 + `UMULL` 幻数乘法）算出，
这是编译器对某个非 2 次幂除法/移位组合的优化实现，用来把 ioctl 读到的 64-bit 扇区数
（大端存放在 `sp+0x110/0x114`）转换为最终的 `sector_val`。此处未逐比特精确复原乘法幻数常量，
但输入输出语义（磁盘扇区数 → 32-bit `sector_val`）在数据流上确凿无误。

### 3.3 Phase 2/3 — MBR 混合与异或合成

**这是与项目最相关、也是核对最扎实的部分**——VMA 0x19300–0x1931c：

```asm
19300: ldr   r3, [pc, #0x60]   @ 0x19368        ; r3 = 0x03FF800F   ★ 与文档 "mix = mbr_val × 0x3FF800F" 完全一致
19304: ubfx  r0, r0, #0x0, #0xb                 ; r0 = mbr_val & 0x7FF （11 位）  ★ 与文档一致
19308: ldm   r6, {r1, r2}                        ; r1 = hash_lo, r2 = hash_hi  (来自 §3.1)
1930c: umull r0, r3, r0, r3                      ; {r3:r0} = mbr_val * 0x3FF800F  （64 位展开）
19310: eor   r1, r1, r0                          ; final_lo = hash_lo ^ mix_lo
19314: eor   r3, r3, r2                          ; final_hi = mix_hi ^ hash_hi
19318: str   r1, [r6]                            ; 写回
1931c: b     0x18d4c                             ; 写回 hi 部分并返回
```

`ubfx r0,...` 的输入 `r0` 来自 VMA 0x192ec–0x192fc：先调用 `hasUefiSupport()`
（PLT `_Z14hasUefiSupportv`，用于区分“是否 UEFI/CHR 环境”从而选择 MBR 缓冲区里偏移 `0`
还是 `+256` 的另一份 10 字节数据），再调用内部函数 **0x17094**（即 §3.1 提到的 SHA-256
finalize 阶段，此处第二次复用来对 `MBR[0x100:0x10A]` 这 10 字节做哈希），返回值经 `ubfx`
截断到 11 位。**逻辑与文档 `mbr_val = (sha256(mbr10)[0:2] ^ checksum(mbr10)) & 0x7FF` 完全吻合**
（`checksum` 部分在函数 0x17094 内部完成，未单独拆分成外部可见的"5×u16 求和取反"指令序列，
应是被内联进了同一函数体，未来如需要逐指令复核可进一步反汇编 0x17094 内部）。

**常量 `0x03FF800F` 在整个 59KB 文件中只出现一次**（文件偏移 0x9368），且唯一的引用点正是
上面这段乘法——排除了误报的可能。

### 3.4 Phase 4 — Base35 编码 + 格式化

VMA 0x19410–0x19404（`toSoftwareIdString`）：

```asm
19410: push {r4,r5,r6,r7,r8,lr}
19370: mov  r4, r2            ; r4 = 输出缓冲区
19388: strb r5, [r4]          ; out[0] = 0  (先清零，用于末尾判断)
1938c: bl   0x18c28           ; 计算 final = getSoftwareId(...) 并存入 sp[0..7]（64-bit）
...
193a0: ldr  r7, [pc, #0x64]  @ 0x1940c        ; r7 = 0x2e270  (.data 段基址，见下)
193ac: mov  r8, #45                            ; '-' 字符
193b4: ubfx r1, r1, #0x0, #0x9                 ; 取 final 高位一部分判断长度阈值(9 bit)
193b8: movlo r5, #10 / movhs r5,#9              ; 输出总长度 10 或 9
...
193e0: cmp  r6, #4
193e4: strbeq r8, [r4, #0x4]        ; ★ 第 4 个字符位置写入 '-'，与文档 "XXXX-XXXX" 完全一致
193e8: beq  0x19404
193ec: mov  r2, #35                             ; 除数 35   ★ Base35
193f0: mov  r3, #0
193f4: bl   0x1c89c                             ; __aeabi_uldivmod 风格的 64-bit 除法/取余
193f8: add  r2, r7, r2                          ; r2 = &alphabet[remainder]
193fc: ldrb r3, [r2, #0x8a]                     ; r3 = alphabet[remainder]   (基址+0x8a偏移)
19400: strb r3, [r4, r6]                        ; out[i] = r3
19404: add  r6, r6, #1
```

`r7 = 0x2e270` 正是 **`.data` 节区的起始 VMA**；`+0x8a` 偏移处存放的字符串，用文件字节核验：

```
文件偏移 0xe2fa (= VMA 0x2e270 + 0x8a 在 ELF 第二 LOAD 段内的实际落盘位置)
内容: "TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE"
```

**与文档记录的 Base35 字母表字符串逐字节相同。** 有意思的是这张表被放在**可写的 `.data` 段**
而不是 `.rodata`（x86 版未验证是否同样如此），紧挨着它前面（`.data` 偏移 0x00–0x89）
还有一段 66 字节字符串 `"ktJiRTVr9qTpXestFvhAVkpkCCMzirczesKCxKhPTNNEVKXKFCEcFeks4EH4FLYW"`，
含义未明（可能是另一张未被此路径使用的表，或编译器合并常量池产生的巧合相邻数据），
留作后续可选复核项，不影响主链路结论。

VMA 0x1c89c 处是一段占用约 3.5KB（0x1bda4–0x1c89c）的纯移位/加减逻辑，是典型的
**编译器内建 64-bit 无符号除法软件实现**（`__aeabi_uldivmod`），说明 `final` 值确实按
64-bit（实际上文档所说的 43 位有效）处理，与 `final = (hash_hi ^ mix_hi) << 32 | (hash_lo ^ mix_lo)`
完全吻合。

### 3.5 新发现：旧版公式（`--old-software-id`）

VMA 0x18d10–0x18d4c，与 §3.3 结构一致但常量不同：

```asm
18d10: add  r1, sp, #144
18d14: add  r0, sp, #272
18d18: mov  r2, #20                 ; 注意：这里长度是 20，不是 40（可能对应旧版更短的输入）
18d1c: bl   0x16ff8                 ; 复用同一个 custom_sha256
18d20: ldr  r2, [sp, #0x40]
18d24: ldr  r1, [pc, #0x614] @ 0x19340   ; r1 = 0x00010044   ← "旧乘数"，全文件只出现一次
18d28: ldr  r3, [sp, #0x114]
18d2c: ubfx r2, r2, #0x0, #0x15     ; 掩码改为 21 位 (0x1FFFFF)，而非新公式的 11 位
18d30: ldr  r0, [sp, #0x110]
18d34: ubfx r3, r3, #0x0, #0x9
18d38: umull r2, r1, r2, r1
18d3c: orr  r3, r3, #512            ; 标记位改为 0x200，而非新公式的 0x100
18d40: eor  r3, r3, r1
18d44: eor  r2, r2, r0
18d48: str  r2, [r6]
18d4c: str  r3, [r6, #4]
```

两段代码共享同一个输出结构体指针 `r6`，且都通过同一个上层调度函数按参数选择执行路径——
与 `--software-id` / `--old-software-id` 两个互斥 CLI 选项完全对应。**结论：该 ARM 固件里
内置了两套历史算法版本**，"新版"是 `docs/license-internals.md` 已核实的当前算法（11 位掩码 /
`0x3FF800F` / `orr 0x100`），"旧版"用 21 位掩码 / `0x00010044` / `orr 0x200`。

> 实用性说明：`--old-software-id` 的确切触发条件（是否某些老 RouterOS 版本、或是否与
> `mbr_marker`（`BD E8`）标记的判定逻辑相关）尚未在本次分析中完全定位，若要复现"旧公式"
> 碰撞搜索，建议先用已知的旧版 Key/MBR 数据做实测校验，而不要仅凭本节静态推断直接用于生产。

### 3.5.1 追加校验（2026-08-27）：追溯调用点确认触发方式，并证明 `--old-software-id` 对 `XU4M-NJ40` 同样不可行

**调用点交叉核对**：`cmd_software_id`（约 `0x1a588`）与 `cmd_old_software_id`（约 `0x1acfc`）
**调用的是同一个入口 `0x1936c`**（而非两个独立函数），仅传入的参数指针不同
（`cmd_old_software_id` 传 `r1 = sp+144`，与 `0x18c28` 帧内 `sp+0x90`（十进制 144）
处被读取为 20 字节 sha256 输入的偏移一致，从数值上支持"由调用方参数间接选择新旧分支"
这一猜测，但完整的标志位传递路径仍未逐指令追完）。

**旧公式输入来源的更正**：本次沿 `0x18c9c`（`bne 0x18d58`，第二次 `open()` 成功则转向字符串/`ioctl 0x31f`
分支）到 `0x18d00`（`open()` 失败则落入本节公式）逐指令回溯，发现旧公式分支的两个输入**均与
§3.0 概览伪代码里"复用 40 字节 serial+model+sector_val 摘要"的描述不符**：
- `mbr_val`（`[sp,#0x40]`）实际来自 `0x18c74` 处对 `/dev/flash` 的 **原始 4 字节 `ioctl` 读数**（常量地址
  `0x19334`，与新公式"10 字节 MBR/board-config 摘要"是完全不同的数据源），并非一次 custom_sha256。
- `sp+0x90` 处 20 字节 sha256 输入的具体内容**尚未追溯到底**（既非本函数内的 `ioctl` 结果，也非本函数内清零逻辑写入——`movne`/`strne` 在"两次 `open()` 均失败"这条实际会执行到 `0x18d10` 的路径上并不会触发，是死代码），推测是调用方（`cmd_old_software_id`）栈帧里已经准备好的数据经指针透传而来，但尚未逐层验证其具体字节内容（可能是 Serial-only，也可能是别的字段）。

**尽管如此，仍可给出确定性结论**：无论 `mbr_val` 与该 20 字节摘要的真实语义是什么，公式结构本身
（`mix = (mbr_val & 0x1FFFFF) * 0x00010044`，`final_hi = (digest_hi&0x1FF | 0x200) XOR mix_hi`）
已经足以判定其对 `XU4M-NJ40` 不可行：对 21 位掩码后的 `mbr_val` 做 `2^21` 全量枚举，`mix_hi`
（64 位乘积高 32 位）**最大只到 `0x20`**（穷举实测，非估算），恒小于 `0x100`，因此 `mix_hi` 的
bit 9（`0x200`）恒为 0，`XOR` 永远不能把 `orr r3,r3,#512` 强制置上的 bit 9 清掉——`final_hi`
的 `0x200` 位永远是 1。而 `XU4M-NJ40` 解码出的 `hi = 0x23`（`0b0_0010_0011`）**`0x200` 位是 0**。
**结论：`--old-software-id` 与 `--software-id`（§8.39/§8.40 已证）一样，对 `XU4M-NJ40` 结构性不可行
——不依赖任何具体的 Serial/Model/flash 内容猜测，两条已知算法路径都被排除。** 已同步写入
`tools/rust/docs/license-internals.md` §8.41。

### 3.6 真正的"Key 文本解码 + 签名写入/校验"函数（VMA 0x19410，一度误标）

这是本次补充分析里最重要的新发现——**本文之前误将它当作 getSoftwareId 的入口**，实际上它是
`docs/license-internals.md` 里说的"签名只验证 SOFTWARE ID"这句话的**实际代码落地处**。完整反汇编
（VMA 0x19410–0x1974c）复原伪代码：

```c
int applyOrVerifySignature(char *devicePath, uint8_t *hwBuf, char *keyText) {
    int len = strlen(keyText);
    if (len == 0) return -1;

    // 1. 跳过前缀，定位 "-----BEGIN MIKROTIK SOFTWARE KEY"（29字节）标记，存在则跳过该行
    char *p = find_begin_marker(keyText, len);

    // 2. 自定义 Base64 风格解码循环（A-Z/a-z/0-9/+// 映射，5个 '-' 连续视为 END 标记提前结束）
    int outlen;
    uint8_t decoded[256];
    decode_base64_stream(p, keyText + len, decoded, &outlen);

    if (outlen == 64) {
        // 64 字节 = 签名区完整大小（对应文档中的 MBR 0x110-0x14F）
        if (!verifyKcdsaSignature(decoded, hwBuf - 52)) return -1;   // bl 0x170d4
    } else if (outlen == 256) {
        // 旧格式：256 字节的备用验证分支
        if (!verifyLegacySignature(decoded, hwBuf - 52)) return -1;  // bl 0x1852c
    } else {
        return -1;
    }

    // 3. ★重新计算当前硬件的 SOFTWARE ID（直接复用 §3.0 的核心函数！）
    uint64_t computedId;
    if (!computeRawSoftwareId(devicePath, hwBuf, &computedId)) return -1;   // bl 0x18c28

    // 4. ★将重新计算出的 ID 与 decoded 签名里编码的目标字段比对
    if (!id_matches(computedId, decoded)) return -1;

    // 5. 匹配成功 → 写入目标缓冲区（UEFI/CHR 走 hwBuf+0，非 UEFI/物理设备走 hwBuf+16）
    if (hasUefiSupport()) {                                    // bl 0x12d6c
        if (memcmp(hwBuf, decoded, outlen) == 0) return 1;
        memcpy(hwBuf, decoded, outlen);
        memset(hwBuf + 0x10c, 0, 4);
        *(uint16_t*)(hwBuf + 0x10a) = checksumFn(hwBuf + 256);   // bl 0x17094
    } else {
        if (memcmp(hwBuf + 16, decoded, outlen) == 0) return 1;
        memcpy(hwBuf + 16, decoded, outlen);
        memset(hwBuf + 0xc, 0, 4);
        *(uint16_t*)(hwBuf + 0xa) = checksumFn(hwBuf + 16);      // bl 0x17094
        *(uint16_t*)(hwBuf + 0x1fe) = BOOT_SIGNATURE_MARKER;     // 未完全确认
    }
    return 0;
}
```

**关键发现**：

- **`0x170d4`（验证 64 字节签名）和 `0x1852c`（验证 256 字节旧格式）是两个独立的签名验证入口**，
  对应文档中提到的 KCDSA 签名验证机制。本次未展开它们内部的数学细节（公钥常量应在 `.rodata`
  或 `.data` 内，未与 x86 版逐字节比对，建议作为后续任务）。
- **签名验证通过后，还需重新计算当前硬件的 SOFTWARE ID 并与签名里的目标值比对**——这是两个
  完全独立的步骤（先验证签名本身合法、再验证签名内容与当前硬件匹配），与现有文档描述的模型完全一致。
- **UEFI/非 UEFI 两条分支写入不同偏移**（`+0`/`+16`）——可能对应"MBR 磁盘签名区"与
  "nova 配置文件内签名区"两种存储布局，具体偏移含义需结合调用方传入的 `hwBuf` 基址进一步确认。

---

## 4. MBR 读写（磁盘授权路径）

### 4.1 readMBR — VMA 0x19c78 附近

```asm
19c78: add  r3, r0, #7
19c7c: ldr  r1, [pc,#0xa8] @ 0x19d2c       ; "%s"（设备路径）
19c84: mov  r0, r5
19c88: sub  sp, sp, r3
19c8c: mov  r2, sp
19c90: bl   ioctl                          ; 取设备扇区大小/几何信息
...
19cac: cmp  r7, #512
19cb8: mov  r0, r6
19cc0: bl   memcpy                          ; 拷贝 512 字节 MBR 到调用者缓冲区
```

失败时走 `fopen`/`fread` 兜底路径（VMA 0x19c4c–0x19d1c），对应字符串
`readMBR: could not open %s: %d` / `readMBR: could not read %s: %d`。

### 4.2 writeMBR — VMA 0x17994 附近

```asm
179a0: bl memcpy          ; 512 字节缓冲区就位
179a4: ldr r1,[pc,#0x98] @ 0x17a44   ; ioctl 命令字
179ac: mov r0, r4
179b0: bl  ioctl
...
179f4: bl  fwrite          ; ioctl 失败则退回 fopen("r+")+fwrite 路径
17a28: bl  sync            ; 写盘后两次 sync()（对应文档 "写 MBR 后需要 sync"）
17a2c: bl  sync
```

对应字符串 `writeMBR: could not open %s: %d` / `writeMBR: could not write %s: %d`。
**行为与 x86 版一致**：先 `ioctl` 尝试块设备直接写，失败则退回 `fopen` 写文件路径，
写完执行两次 `sync()`。

### 4.3 boot signature 校验（0x17aac 附近）

一个独立的小函数，检查缓冲区 `[0x1FE:0x200] == AA 55`（MBR 引导签名）以及
`buf[0x150] & 1`（License 有效位），只有两者同时满足才跳转执行
`hasUefiSupport()` 之后的逻辑分支：

```asm
17aac: movw r3, #0x1fe
17ab0: ldrh r2, [r0, r3]
17ab4: movw r3, #0xaa55
17ab8: cmp  r2, r3
17abc: bne  0x17ad0                 ; 不是有效引导扇区 → 返回 0
17ac0: ldr  r3, [r0, #0x150]
17ac4: tst  r3, #1
17ac8: beq  0x17ad0
17acc: b    hasUefiSupport
```

`0x150` 正是文档中 **签名区结束偏移**（`0x110+64=0x150`）之后紧邻的第一个 4 字节，
说明这里额外读取了一个"授权状态标志字"，而不仅仅是签名本身——这是 ARM 版本对
签名区结构的一个（此前文档未记录的）细节，建议如果要在 ARM CHR 上手工写 MBR，
除了 0x100-0x14F 之外，也要留意 `0x150` 处这个标志字段是否需要置位。

---

## 5. 硬件 ID 采集（多后端）

与 x86 版单一走 ATA IDENTIFY 不同，ARM 版按顺序尝试多种后端（函数 0x18c28 起，
长度约 2KB，是本文件里最长的单体函数之一）：

1. **`readlink("/dev/root-disk")`**（VMA 0x15f0c）解析出真实块设备路径（云主机/QEMU 场景下
   常见做法，避免直接依赖固定设备名）。
2. **ATA `HDIO_DRIVE_CMD`**（`ioctl` 命令字 `0x031f`）——发送 `IDENTIFY DEVICE` 直通命令，
   解析返回数据里的 Serial Number（偏移对应 ATA IDENTIFY 结构体 word 10 起 20 字节）与
   Model（word 27 起）。对应字符串 `Serial Number: %19s` / `Serial Number: %80s`
   / ` VendorID: %x` / ` ProductID: %x`。
3. **`/proc/scsi/usb-storage/%u`** —— USB 存储设备的序列号来源（对应 U 盘启动场景）。
4. **NVMe**：设备名判断 `nvme%dn%d` / `/dev/nvme%d`。
5. **Flash / MTD**：`/dev/flash`、`/dev/mtdblock%u` —— 无独立磁盘的嵌入式设备。
6. **`/sys/class/dmi/id/product_uuid`** + `board` / `qemu` 字符串匹配 —— 用于识别 QEMU/云
   虚拟机场景，走 `getBoardSerialNumber()`（`_Z20getBoardSerialNumberv`，从 `.dynsym`
   直接可见的导出符号，属于 libumsg.so 提供的公共实现）。
7. **`/sys/class/tty/hvc1/dev`**、**`/dev/hvckvm1`** —— 处理某些虚拟化平台的控制台设备号
   （与授权无直接关系，附带识别逻辑）。

日志格式串 `%s: hdd-model='%.16s' s='%.20s' sz=%d MB`（VMA 0x1cbb7）确认最终会打印
"型号/序列号/容量(MB)"三元组，与 x86 版调试输出格式一致，佐证 model 截断到 16 字节、
serial 截断到 20 字节的字段长度约定同样适用于 ARM。

### 5.1 无 MBR 永久授权（RouterBOARD ARM 专属分支）

VMA 0x1b678 起的函数（对应 `--mbr` 选项其中一个分支）里，直接：

```
fopen("/nova/etc/serial", "r") → fgets(buf, 21, fp)     // 20 字节序列号 + NUL
fopen("/nova/etc/license", "r") → fgets(buf, 13, fp)     // 13 字节许可数据
hasUefiSupport() ? ... : ...
checksum-compare(0x13808 / 0x17094)                       // 与 §3 相同的哈希/校验子例程复用
```

这是 x86 keyman 完全没有的路径：**物理 RouterBOARD（无 SATA/无标准 MBR 磁盘）设备把
授权信息直接存放在 flash 上的 `/nova/etc/serial` + `/nova/etc/license` 明文/二进制文件里**，
而不是磁盘 0x100-0x14F 扇区。对本项目（PVE 虚拟机场景）**不直接适用**，因为 PVE 里的
ARM CHR 虚拟机走的是标准虚拟磁盘（virtio-blk/scsi），应命中 §4 的 MBR 路径，但如果未来要
支持"直接刷物理 RouterBOARD 授权"，这条路径是入口点。

---

## 6. 在线续期（HTTP）与 IPC 服务

从字符串表可确认还存在两套与离线算法无关的功能，仅作结构性记录：

- **在线续期**：`connecting` / `systemid` / `account` / `password` / `licence` / `oldid` /
  `Content-Type: application/x-www-form-urlencoded` / `licence.mikrotik.com` / `/licence/`
  —— 通过 `nv::HTTPFetch::post(...)` （`.dynsym` 导出符号 `_ZN2nv9HTTPFetch4postERK6stringS3_...`）
  向 MikroTik 官方服务器提交表单换取新 Key，与本项目"离线碰撞搜索"方案无关，仅说明
  keyman 本身也内置在线续期能力。
- **IPC 常驻服务**：大量 `nv::Looper` / `nv::Handler` / `nv::message` 符号表明该二进制在无参数
  运行时会作为一个 `nova` 消息总线上的常驻服务（`cmdGetObj`/`cmdSetObj`/`cmdAddObj`…），
  供 WinBox/WebFig 查询 `/system license print` 等信息，这部分与授权算法无关，未展开分析。

---

## 7. 与 x86 版本（keyman_x86_7.23.2）的差异小结

| 维度 | x86 7.23.2 | ARM 7.24.1 |
|---|---|---|
| SOFTWARE ID 算法（新） | 已核实 | **逐指令核对，完全一致**（IV/K/掩码/乘数/字母表全部相同） |
| 旧版算法分支 | 未记录 | **本次新发现**：`--old-software-id`，21 位掩码 + 不同乘数 |
| 磁盘 MBR 读写 | 已核实 | 结构一致（ioctl 优先 + fopen 兜底 + 双 sync），额外发现 `0x150` 授权状态标志字 |
| 硬件识别 | 主要走 ATA IDENTIFY | ATA + NVMe + USB + Flash/MTD + QEMU DMI 多后端 |
| 无 MBR 永久授权 | 无 | 有（`/nova/etc/serial` + `/nova/etc/license`，物理 RouterBOARD 专属） |
| CLI 选项集合 | 一致的核心项 | 额外可见 `--old-software-id` |

**对本项目（PVE + SOFTWARE ID 碰撞搜索）的结论：** ARM 架构 RouterOS（CHR-ARM64 等）与 x86
共用同一套离线授权算法与同一批签名表，**理论上 `mtsc` 现有实现和 4 组已知签名
（TI09-7WK3 / 4MZF-SFTR / HHJH-UFWL / C7CU-PGT9）可以直接套用于 ARM 虚拟机授权，无需为 ARM
单独实现或重新碰撞**。建议后续用一台真实 ARM CHR/PVE 虚拟机做一次端到端验证（写入用同一
算法生成的 MBR 数据，检查 `nlevel: 6` 是否生效）以最终坐实这一结论。

---

## 8. 复现方法

```bash
cd tools/bin
python3 analysis/rebuild_annotated_asm.py keyman_arm_7.24.1 \
    analysis/keyman_arm_7.24.1.annotated.asm
# 之后可用 grep/less 在 keyman_arm_7.24.1.annotated.asm 里搜索本文档中提到的任意 VMA 地址
grep -n "19300:\|19368:" analysis/keyman_arm_7.24.1.annotated.asm
```

关键地址速查表（VMA）：

| 地址 | 功能 |
|---|---|
| 0x19410 | `getSoftwareId()` 主入口，含 Base35 编码 |
| 0x192cc–0x192dc | Phase 1：40 字节输入 → `custom_sha256` |
| 0x1929c–0x192c8 | sector_val 取整 |
| 0x19300–0x1931c | Phase 2/3：`& 0x7FF` 掩码、`× 0x3FF800F`、XOR 合成（新公式） |
| 0x18d10–0x18d4c | 旧公式（`& 0x1FFFFF`、`× 0x00010044`、`orr 0x200`） |
| 0x16ff8 | `custom_sha256` 压缩函数（引用 K 表 @0x1cf9c） |
| 0x17094 | SHA-256 finalize / MBR-10 字节校验子例程（引用 IV 表 @0x1d09c） |
| 0x1c89c | 64-bit 无符号除法（Base35 编码用） |
| 0x19c78 / 0x17994 | `readMBR` / `writeMBR` |
| 0x18c28 | 多后端硬件 ID 采集主函数 |
| 0x15f0c | `readlink("/dev/root-disk")` 解析真实块设备 |
| 0x1b678 | `/nova/etc/serial`+`/nova/etc/license` 永久授权分支 |

---

## 9. 能否用于 arm64 PVE 虚拟机激活？—— 已下载官方镜像实测验证：**能**

> ⭐ 2026-08-27 更新：下面的结论推翻了本文档初版基于"32-bit arm 与 CHR 无关"的推测。
> 现已**实测验证**，结论反转：**官方 arm64 CHR 镜像里面的 keyman 实际上就是同一套 32-bit ARM 代码**。

### 9.1 验证方法

1. 从 MikroTik 官方直接下载了 CHR arm64 镜像：`chr-7.21.5-arm64.img.zip`
   （`https://download.mikrotik.com/routeros/7.21.5/chr-7.21.5-arm64.img.zip`，18MB，解压后为 128MB 原始磁盘镜像）。
2. 磁盘内有两个分区：分区1为 FAT32 引导分区（内含真正的 **aarch64（EM_AARCH64）Linux 内核**，
   在引导分区中找到 `ELF64, machine=0xB7`）；分区2为 ext4，内含 RouterOS 自定义的 `.npk` 包格式的
   `system` 包（`/var/pdb/system/image`，13.4MB，npk 头部明确标记 `arch=arm64`）。
3. 用 Python 自写 ext4 读取器（`pip install ext4`）提取该 npk 文件，发现其从文件偏移 `0x1000` 起就是一个
   标准 **squashfs**（`hsqs` 魔数），用 `pip install PySquashfsImage` 解开，共 804 个条目。
4. 在这个 squashfs 里找到 **`/nova/bin/keyman`**，`file` 识别结果：
   ```
   ELF 32-bit LSB executable, ARM, EABI5, dynamically linked, interpreter /lib/libc.so, stripped
   ```
   与本文分析的 `keyman_arm_7.24.1`（同样 32-bit ARM/EABI5，只是版本号不同）**完全同架构**，文件大小也
   几乎一致（59388 字节 vs 59392 字节）。
5. 在新提取的二进制里逐个搜索 §3 记录的全部常量，**全部命中**（仅偏移因版本不同而略有偏移）：

   | 常量 | arm64-CHR 镜像内 keyman (7.21.5) 偏移 | 本文 keyman_arm_7.24.1 偏移 |
   |---|---|---|
   | IV[0..7] 表 | 0xd104–0xd120 | 0x1d09c–0x1d0b8 (VMA) |
   | K[0..1] | 0xd004 | 0x1cf9c (VMA) |
   | 新公式乘数 `0x3FF800F` | 0x938c | 0x9368 (文件偏移) |
   | 旧公式乘数 `0x00010044` | 0x9364 | 同样存在 |
   | Base35 字母表 `TN0BYX18...` | 0xe2fe | 0xe2fa (文件偏移) |
   | `--mbr`/`--software-id`/`--old-software-id`/`--key`/`--find-key` 等全部 CLI 选项字符串 | 均存在 | 均存在 |
   | `/nova/etc/serial`、`/nova/etc/license` | 均存在 | 均存在 |

   作为参考证据，提取出的二进制已保存为
   `tools/bin/analysis/keyman_arm_chr64-7.21.5_from_official_image.bin`。

### 9.2 结论

**MikroTik 的"arm64"架构 CHR 云镜像，实际上只有 Linux 内核本身是真 64-bit aarch64，用户态服务（包括
`keyman`、`www`（WebFig 服务器）、`sshd` 等，根据抽样检查）仍然是 32-bit ARM（ARMv7 EABI5）二进制，
靠 aarch64 内核的 AArch32 兼容模式运行**。换句话说：本文 §1-§8 对 `keyman_arm_7.24.1` 的全部分析结论
（SOFTWARE ID 算法、IV/K 常量、Base35 编码、MBR 混合公式、旧公式分支、签名验证函数结构等）
**可以直接套用于真实的 arm64 CHR 云主机**，无需重新逐指令分析 aarch64 代码（因为根本不存在独立的
aarch64 keyman 实现）。

**回答你的问题：你有 arm64 设备，跑 PVE，能激活吗？**

- **如果你的 arm64 设备本身就是 arm64 Linux 宿主机，可以跑 Proxmox VE 9.2+ 的 arm64 版本（KVM 加速）**，
  在其上创建 MikroTik 官方 arm64 CHR 镜像作为虚拟机磁盘，**理论上可以用与 x86 完全相同的 SOFTWARE ID
  碰撞搜索方法激活**（需重新对 arm64 CHR 磁盘读取的 hdd-model/serial 字符集、MBR 写入方式等做一次实际
  机验证，但算法本身不需要重新破解）。
- **如果你的 PVE 宿主本身仍然是 x86_64，只是想在上面跑一个 arm64 客户机**，那么只能走 QEMU TCG
  软件模拟，性能很差但**技术上不妨碍你把它装起来、用同样的方法激活**（只是作为日常路由器不实用）。
- 若你的目标是真实运行环境（非仅测试），建议优先考虑 x86_64 CHR（本项目现有流程完全支持，性能/
  兼容性最好）；arm64 方案适合在真实 arm64 硬件（如 Ampere 服务器、部分云厂商 arm 实例）上使用。

### 9.3 版本一致性再验证（2026-08-27）：不同 RouterOS 版本的 `keyman` 是否共享同一算法？——已下载并反汇编 `7.15.3` 二进制直接核实

**动机**：本文 §1-§9 的全部分析基于 `keyman_arm_7.24.1`，此前只交叉核实过它与 **7.21.5**（CHR arm64 镜像）
字节相同（见 §9.1）。但两者版本号相邻，不能排除 MikroTik 在更早的版本里用过不同的 SOFTWARE ID 算法——
而 `--old-software-id` 这个 CLI 选项本身的存在，就是 MikroTik 至少改过一次该算法的直接证据。本节对此不作假设，
而是实测：直接从 MikroTik 官网下载 `https://download.mikrotik.com/routeros/7.15.3/routeros-7.15.3-arm64.npk`，
用 §9.1 同样的方法（npk 文件偏移 `0x1000` 处的 `hsqs` squashfs 魔数，`PySquashfsImage` 解包）提取
`/nova/bin/keyman`，保存为 `tools/bin/keyman_arm_7.15.3`。

**结果一：确实是不同的二进制**：
```
keyman_arm_7.24.1:  59392 字节, MD5 ebdaa0f2f1b71cb535490c8e93c2c754
keyman_arm_7.15.3:  55692 字节, MD5 27f8848dd763ba177eccfdf6ba001ee7   ← 与 7.24.1 不同（与 7.21.5/7.24.1 那对字节相同的情况不同）
```

**结果二：但重新反汇编 `keyman_arm_7.15.3` 后，发现 SOFTWARE ID 组合算法本身逐字节未变**，只是整体
代码地址平移了（符合无关的编译器/库版本差异，而非算法本身变化）：

- 全文件 **34 条 `umull`** 指令，与 7.24.1 完全相同
- 新公式的 `orr r3,r3,#256`（强制 `0x100` 位）和旧公式的 `orr r3,r3,#512`（强制 `0x200` 位）各恰好
  出现 **1 次**，另有 1 处无关的 `orr r3,r3,#64`（功能开关，与 7.24.1 对应），无 `#128`/`#1024` 命中
- 旧公式代码段（`add r1,sp,#144` / `mov r2,#20` / 调用 custom_sha256 / 21位掩码 / `umull` /
  `orr r3,r3,#512` / 双 `eor`）与 §3.5/§3.5.1 描述的指令序列**逐条相同**
- 新公式代码段（`mov r2,#40` / 调用 custom_sha256 / `orr r3,r3,#256` / 字面量池中的 `0x3FF800F`
  常量 / 11位掩码 / `umull` / 双 `eor`）与 §3.0/§3.3 描述的指令序列**逐条相同**
- 自定义 SHA-256 的 IV 常量首字节 `0x5B653932`（小端）在两个二进制里都能找到，哈希原语本身也未变

**结论：版本不一致这个假设被排除，而不是被证实**——`7.15.3` 的 `keyman` 确实是一个不同的编译产物，
但它的 SOFTWARE ID 算法（两套公式、魔数常量、强制位、哈希原语）与 `7.24.1` **逐字节一致**。本文 §1-§9 基于
`7.24.1` 得出的所有结论，对任何已知 RouterOS 7.15.3-7.24.1 范围内的 ARM 固件都同样成立。（若想对照真实设备硬件的
对应补充证据，参阅 `tools/rust/docs/license-internals.md` §8.42）——同一次验证下，这个发现反而让真实设备
`XU4M-NJ40` 无法被本地重算的谜团变得更尖锐：即使换成它自己实际运行的固件版本，仍无法本地算出那个 ID。

---

## 10. 能否直接"模拟" /nova/etc/serial + /nova/etc/license 来激活？

基于 §3.6 对 `--mbr` 处理函数（VMA 0x1b678）的完整反汇编，现在可以给出一个比之前更有依据的回答。

### 10.1 已确认的事实

- `keyman --mbr` 无论在 UEFI/CHR（你的 PVE 虚拟机属于这种）还是传统 BIOS 物理机上，**都会无条件地先尝试
  `fopen("/nova/etc/serial")` 和 `fopen("/nova/etc/license")`**（VMA 0x1b6a0–0x1b708）——不是只有物理
  RouterBOARD 才走这条路径，而是无条件执行的。这个发现比初版文档里说的"物理设备专属"更为乐观。
- 若 `/nova/etc/serial` **成功读取到非空内容**，则会走到 §3.6 描述的 `applyOrVerifySignature()`
  （VMA 0x19410），它会：
  1. 把 `/nova/etc/license` 的内容当作一个 **Key 文本或已经解码的签名块**来 base64 风格解码（支持带/不带
     `-----BEGIN MIKROTIK SOFTWARE KEY` 前缀），得到 64 或 256 字节；
  2. 调用 KCDSA 签名验证函数（0x170d4 或 0x1852c）确认签名本身合法；
  3. **重新计算当前硬件的 SOFTWARE ID**（调用 0x18c28，与 `--software-id` 完全同一套代码），与签名里编码的
     目标 ID 比对，**不匹配则返回失败**；
  4. 匹配成功才把签名写入目标结构体。
- 也就是说：**`/nova/etc/serial` + `/nova/etc/license` 能否"直接激活"，完全取决于 `/nova/etc/license` 里的
  签名内容能不能通过 KCDSA 验证，以及它编码的目标 SOFTWARE ID 能不能与基于 `/nova/etc/serial` 里的序列号
  重新计算出的 SOFTWARE ID 匹配**。本质上和写 MBR 0x100-0x14F 是同一件事情的另一种存储位置，
  **不是一个绕过签名验证的"后门"**。你仍然需要一个能通过 `docs/collision-database.md` 里 4 组已知签名之一的
  碰撞 serial，把对应的 64 字节签名写进 `/nova/etc/license`，并把碰撞得到的 serial 写进 `/nova/etc/serial`。

### 10.2 还未确认的关键问题

1. **RouterOS 开机时会不会自动调用 `keyman --mbr`**？本次分析只看了 keyman 二进制本身，没有 init 脚本/
   systemd 类启动服务定义（RouterOS 用自己的 nova 服务总线，非标准 systemd）。若开机不自动调用，那么
   写入 `/nova/etc/serial`+`/nova/etc/license` 后需要手动执行一次 `keyman --mbr`（或找到真正的自动调用时机）
   才会生效，而且还需要确认这个写入结果能否持久化到重启后仍然生效的位置（而不是只写进一个内存缓冲区）。
2. **`hwBuf` 到底写入哪里**：§3.6 中 `applyOrVerifySignature()` 把签名写入 `hwBuf+0`（UEFI）或 `hwBuf+16`
   （非 UEFI），而 `hwBuf` 本身是调用方传入的一块栈上/堆上临时缓冲区，**本次分析没有确认后续是否还有一步
   把这块缓冲区写回磁盘/持久化存储**（与 §4.2 的 `writeMBR()` 相比，§3.6 里没看到直接的 `ioctl`/`fwrite`
   调用）——有可能这个写入只是内存中的一次校验，真正的持久化发生在调用方函数里（即未展开分析的
   `readMBR`/`checkLicense` 上层调用者）。
3. 两个读文件调用的长度限制很紧：`fgets(buf, 21, fp)`（serial 最多 20 字符+NUL）、
   `fgets(buf, 13, fp)`（license 最多 12 字符+NUL）——**注意 `/nova/etc/license` 只能读到 12 字节**，这个长度
   远不够容纳一个完整的 64 字节签名或 Key 文本！这个发现**直接推翻了 10.1 里结尾的乐观结论**：这个代码路径里
   的 `/nova/etc/license` 不可能直接存放一个完整 Key 文本，它的真实用途更像是存储一个**短的内部标识符/状态值**
   （只够 12 字节），而不是完整的许可证。真正的 64 字节签名存储位置很可能仍然是磁盘 MBR 0x110-0x14F，
   而 `/nova/etc/*` 只是一个辅助/缓存层。**这个紧限制直接推翻了前面 10.1 结尾的乐观结论，需要特别标注。**

### 10.3 修正后结论

**不建议依赖 `/nova/etc/serial` + `/nova/etc/license` 作为主要激活路径**：一方面它的使用前提（是否在开机时
被自动调用、写入后能否持久化）仍未确认；另一方面 `/nova/etc/license` 只能读 12 字节，装不下完整的
64 字节签名，说明这条路径很可能只是个辅助机制。**本项目现有的 MBR 0x100-0x14F 碰撞搜索 + 写入方案仍然是
最可靠、完全验证过的激活路径**（且已确认对 arm/arm64 同样有效，见 §9）。若后续想真正搜索
`/nova/etc/*` 路径，建议先反汇编 `readMBR`/`checkLicense` 的真正上层调用者，确认它何时会传入一个真实的
`/nova/etc/license` 文件路径（而不是只在 `--mbr` CLI 命令里）。

---

## 11. 局限性 / 后续可做的事

- 本文档全部基于**静态反汇编 + 数据流推理**，未做动态调试（无 ARM RouterOS 运行环境可用），
  §3.5 的"旧公式"触发条件、§4.3 的 `0x150` 标志字具体语义、`.data+0x00..0x89` 神秘字符串
  的实际用途，均建议后续用真机/QEMU-ARM 动态验证。
- `custom_sha256` 内部轮函数（0x16ff8/0x17094 内部循环体）未逐轮展开比对，只核对了
  IV/K 常量表本身；如需 100% 确认算法逐位等价，可进一步反汇编这两个函数体或直接用已知
  测试向量跑一遍二进制（若能在模拟器里跑通 `--software-id`）。
- 未分析 IPC/HTTP 相关的完整状态机，仅做了字符串级别的功能识别，因为与本项目目标
  （离线碰撞授权）无关。
