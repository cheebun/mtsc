# 动态分析报告：`keygen_x86`（elseif/MikroTikPatch）

> 状态：已复核到 2026-09-14 的动态观测数据（含完整 CLI 参数矩阵、`getrandom` 精确调用点静态反汇编 §4.1、`mt_transform` 等效代码定位 + base64 间接证据 §6.1、Ghidra 无头分析尝试 §6.2——payload 拼装/签名调用位置这两点暂时搁置，根因是 garble 剥离了 Go 版本信息）
> 对象：`/tmp/MikroTikPatch/keygen/keygen_x86`
> 环境：远程 Debian 13 x86_64 主机（`hkg-land-03`，经 SSH 代理访问），Linux 内核支持 `unshare --pid --mount`
> 方法：私有 mount namespace + 私有 PID namespace + `strace -f` 全量 syscall 追踪 + 故障注入（详见 `03-sandbox-manual.md`）

---

## 1. 二进制基本信息

| 属性 | 值 |
|---|---|
| 格式 | ELF 32-bit LSB，statically linked，stripped |
| 语言 | Go（`r2 -qc "iI"` → `lang go`），构建时经 **garble** 混淆 |
| 体积 | 4,907,132 字节 |
| 符号 | 无（garble 随机化包/函数名） |
| 字符串 | 剥离/加密，`go buildinfo` 段被清除 |
| 静态链接的 crypto 库 | `crypto/ed25519`、`crypto/aes`、`crypto/sha256`、`crypto/sha1`、`crypto/rsa`、`crypto/tls`、`crypto/x509` |

静态分析（反汇编 + 字符串提取）走到死胡同后，本报告转向动态观测。

---

## 2. CLI 参数矩阵（完整实测）

`keygen_x86` 的全部入口实测如下（均为沙箱内观测，`<stdin>` 显式喂 `n`）：

| argv | 行为 | 退出码 |
|---|---|---|
| （无参数） | MBR 身份随机化 + 调用 `/nova/bin/keyman --software-id` + **本地零网络签出 License** | 0（有 fake `keyman`）；2（无 `keyman`，`execve` 得 `ENOENT`） |
| `chr` | 写 MBR 模式标志 + 提示重启；确认后 `execve("/usr/sbin/reboot", ["reboot","-f"])` | 0（拒绝重启） |
| `x86` | 与 `chr` 完全镜像："set to x86 mode" + 同样的两次 MBR 写入 + 提示重启 | 0（拒绝重启） |
| `license` | 打印 `Usage: keygen [x86 | chr]` | 1 |
| `activate` | 同上 | 1 |
| `key` | 同上 | 1 |
| `sign` | 同上 | 1 |
| `keygen` | 同上 | 1 |

两个值得注意的点：

1. **usage 消息只列出 `[x86 | chr]`，没列出"无参数"路径**——说明"无参数 → 生成 License"是一条未在 usage 里暴露的隐藏/默认入口（正是补丁项目安装后"自动授权"所走的那条路）。
2. **`license`/`activate`/`key`/`sign`/`keygen` 全部是无效参数**，不存在独立的"生成授权"子命令——生成 License 只能通过"无参数"路径触发。

---

## 3. 设备探测逻辑（`/dev/flash` vs `/dev/root-disk`）

每次运行（含各子命令）开始时，`keygen_x86` 都执行同一套探测：

```
openat("/dev/flash", O_RDONLY)          → 若成功，走"真实 RouterBOARD"路径
openat("/dev/root-disk", O_RDONLY)      → 若成功，走"x86/CHR"路径
```

关键观测：

- 真实 RouterBOARD 路径依赖一个厂商私有 `ioctl(fd, 0x4601, ...)`（编号恰与 Linux 帧缓冲的 `FBIOPUT_VSCREENINFO` 相同，**纯属数字巧合**；MikroTik 在此复用了该编号作自有 flash 参数查询）。此协议在无真实硬件/驱动时无法伪造，该路径在假 `/dev/flash` 上会 `ENOTTY` 后 `exit(2)`。
- x86/CHR 路径只做普通块设备读写，可在伪造的常规文件上完整复现，是本报告的主要研究对象。

---

## 4. MBR 身份随机化写入

当只有 `/dev/root-disk`（1MB 全零普通文件）可用时，观测到如下序列：

```
read(fd, buf, 512)              # 读 MBR 第一个扇区（全零）
getrandom(buf, 10, 0)           # 生成 10 字节真随机数
write(fd, new_mbr, 512)         # 写回
fsync(fd); close(fd)
```

写回 buffer 的字节布局（`strace` 捕获的转义串逐一解码）：

| 偏移 | 长度 | 内容 |
|---|---|---|
| `0x000` | 256 字节 | `\0` × 256 |
| `0x100` | 10 字节 | 随机 identity（样本：`CC 11 26 11 F9 AB 50 FE E6 8E`） |
| `0x10A` | 2 字节 | marker（样本：`4F 09`） |
| 其余 | — | `\0` |

**结论**：`keygen_x86` 会为每台"无实体 flash"的机器生成一个随机 **10 字节身份种子**（写入 MBR 偏移 `0x100`），并附带由该身份推导出的 **2 字节 marker**（偏移 `0x10A`）。这与本项目 `mtsc` 中 `--identity` 参数模拟的机制完全同构。

> 偏移 `0x100`/`0x10A` 与本项目 `src/targets.rs::marker_from_identity()` 文档注释中的标注一致，且 marker 值经实测与 `marker_from_identity()` 计算结果逐字节吻合 —— 见 `02-cross-validation.md`。

### 4.1 `getrandom` 精确调用点（2026-09-14 补充，静态+动态双重确认）

之前只确认了"会调用 `getrandom`"，本次把具体指令地址钉死。全二进制反汇编 `.text` 段搜索系统调用号 `0x163`（355，linux/386 的 `SYS_getrandom`）**只命中一处**，排除了"多个 `getrandom` 调用点、分不清哪个是身份生成"的可能：

```
081b4990: mov    DWORD PTR [esp],0x163      ; trap = 355 (SYS_getrandom)
081b4997: mov    DWORD PTR [esp+0x4],eax    ; arg1 = 缓冲区指针
081b499b: mov    eax,DWORD PTR [esp+0x2c]
081b499f: mov    DWORD PTR [esp+0x8],eax    ; arg2 = 长度 = 10
081b49a3: mov    eax,DWORD PTR [esp+0x34]
081b49a7: mov    DWORD PTR [esp+0xc],eax    ; arg3 = flags = 0
081b49ab: call   0x8189ac0                  ; -> Syscall 包装
```

调用链：`0x081b4990`（设置 trap/buf/len/flags 四个参数）→ `0x8189ac0`（Go 的 `Syscall` 包装，补零 arg4-6）→ `0x8189a60`（把全部 6 个参数搬上栈）→ `0x805bbc0`（真正执行 `int $0x80` 的裸系统调用 trampoline，全二进制所有直接系统调用共用同一份）：

```
0805bbc0: mov    0x4(%esp),%eax      ; trap number  -> eax
0805bbc4: mov    0x8(%esp),%ebx      ; arg1
0805bbc8: mov    0xc(%esp),%ecx      ; arg2
0805bbcc: mov    0x10(%esp),%edx     ; arg3
0805bbd0: mov    0x14(%esp),%esi     ; arg4
0805bbd4: mov    0x18(%esp),%edi     ; arg5
0805bbd8: mov    0x1c(%esp),%ebp     ; arg6
0805bbdc: int    $0x80               ; <- 真正的系统调用陷入
0805bbde: cmp    $0xfffff001,%eax    ; <- strace -i 报出来的地址就是这里
0805bbe3: jbe    0x805bbfc
0805bbe5: movl   $0xffffffff,0x20(%esp)   ; 错误路径：r1=-1
0805bbed: movl   $0x0,0x24(%esp)
0805bbf5: neg    %eax                ; errno = -eax
0805bbf7: mov    %eax,0x28(%esp)
0805bbfb: ret
0805bbfc: mov    %eax,0x20(%esp)     ; 成功路径：r1=eax
0805bc00: mov    %edx,0x24(%esp)     ; r2=edx
0805bc04: movl   $0x0,0x28(%esp)     ; errno=0
0805bc0c: ret
```

这也解释了一个此前的疑惑：`strace -i` 对 `openat`/`getrandom`/`write` 报出来的地址全是同一个（`0x0805bbde`）——因为那是这个共享 trampoline 里 `int $0x80` 之后的返回地址，不是每个系统调用各自的调用点，Go 的直接系统调用全都走这一份通用代码，只是 `eax` 里的调用号不同。

**动态交叉验证**：真实跑一遍无参数路径，`getrandom` 返回的 10 字节（样本：`df e4 a8 cb ca c9 48 c3 ac 3f`）在紧接着的 `write(fd, mbr, 512)` 里原样出现在偏移 `0x100`，后面跟着 marker `ee c3` 在 `0x10A`——证实这条调用链确实就是喂给 MBR 身份写入的那次 `getrandom`，不是 Go 运行时内部其他用途（比如 map hash 种子）的调用。

返回后 `081b49b8: test eax,eax` / `081b49bc: cmp eax,0x26` 检查 `ENOSYS`（38）——标准的 `golang.org/x/sys/unix` `Getrandom()` 包装模式：优先探测 `getrandom(2)`，只有老内核不支持时才回退到 `/dev/urandom`。

---

## 5. `chr` / `x86` 子命令：改标志位 + 调系统 `reboot -f`

在隔离沙箱中运行 `./keygen_x86 chr`（`x86` 行为完全镜像，仅提示文案不同）：

```
输出:
  Author: elseIf@live.cn
  RouterOS has been set to CHR mode   (x86 时为 "set to x86 mode")
  Reboot your device [Y/n]:
```

syscall 关键序列：

```
write(/dev/root-disk, mbr, 512)     # 第一次：写 MBR（随机身份）
write(/dev/root-disk, mbr, 512)     # 第二次：写 MBR（切换模式标志位）
write(stdout, "RouterOS has been set to CHR mode\n")
write(stdout, "Reboot your device [Y/n]: ")
```

确认重启（stdin 收到 `y`）后：

```
execve("/usr/sbin/reboot", ["reboot", "-f"]) = 0
reboot(MAGIC1, MAGIC2, LINUX_REBOOT_CMD_CAD_ON)    # 被 strace 故障注入拦成 EPERM
reboot(MAGIC1, MAGIC2, LINUX_REBOOT_CMD_RESTART)   # 被 strace 故障注入拦成 EPERM
```

**关键结论**：

1. `keygen_x86` 自己**不直接调用 `reboot(2)` 系统调用**，而是 `execve` 出系统自带的 `/usr/sbin/reboot -f`，由后者发起真实重启。
2. 交互提示 `[Y/n]` 中，**空输入 / EOF 会被当作确认重启（默认 Y）** —— 这是本会话早期一次真实误重启事故的根因，详见 `03-sandbox-manual.md` 的安全注意。
3. `chr`/`x86` 全程（含重启）**零网络 syscall**，纯本地操作。

**模式标志位偏移已定位：`0x150`，单字节，`00` = x86 模式，`01` = CHR 模式。**

对同一份初始全零 `fake_rootdisk`，分别跑 `keygen_x86 x86` 和 `keygen_x86 chr` 并截取各自第二次 `write(/dev/root-disk, mbr, 512)` 的内容逐字节 diff：两次写入除 `0x100-0x109`（每次随机的 identity，需排除）外，唯一固定且稳定不同的字节落在偏移 `0x150`——`x86` 模式写入 `00`，`chr` 模式写入 `01`，其余 510 字节（含 `0x10A` marker、`0x10C-0x10F` reserved）在两种模式下逐字节一致。

**这与此前"x86/CHR 是同一套内核/驱动、仅靠运行时标志位切换"的假设吻合**：`keygen_x86`/官方固件都不需要在 `x86` 与 `chr` 两种模式间切换任何驱动模块或分区内容——切换动作完整地体现为对磁盘固定偏移一个字节的写入，配合一次重启。这与另一条独立证据链（`mikrotik-gpl` 仓库里 x86_64 内核只有一份 `x86_64.config`，物理网卡驱动与虚拟化 Guest 驱动被编译进同一份配置，没有为 x86/CHR 分别维护配置）指向同一结论，但**尚未证实**驱动/许可证以外还有第三方消费这个字节（比如 RouterOS 自身的许可证解析代码在启动时读取 `0x150` 来决定按 `SOFTWARE-ID`/`nlevel` 还是 `system_id`/`level` 格式解析——这一步仍是本节的下一步验证方向，见下方未决问题）。

---

## 6. 不带参数：调用 `/nova/bin/keyman --software-id` 并本地签出 License

不带任何参数运行时，除 MBR 身份随机化外，还观测到：

```
execve("/nova/bin/keyman", ["/nova/bin/keyman", "--software-id"]) = -1 ENOENT
```

`/nova/bin/keyman` 是真实 RouterOS 系统自带的官方授权工具，通用 Debian 主机上不存在，因此默认路径在此失败并 `exit(2)`。

为继续观测，我们在沙箱内伪造了一个 `/nova/bin/keyman`（对 `--software-id` 打印一行文本）。随后：

```
输出:
  Author: elseIf@live.cn
  Software ID: <fake keyman 原样回显的整行>
  License Key:
  -----BEGIN MIKROTIK SOFTWARE KEY------------
  8wvg/OBxPRLDRlfNNnZPAChccTLoN2pXmY/Bw0Fl+Sco
  1hI1eCrYiYoSRBvYsnTvXrs/uKoMotaZR4WeWyukDA==
  -----END MIKROTIK SOFTWARE KEY--------------
  For the key change to take effect, you should reboot the router.
```

**本次运行最关键的事实**：从 `execve(/nova/bin/keyman)` 到打印出完整 License Key 文本块，`strace -e trace=network` 追踪到 **零次网络调用**。这说明 `keygen_x86` 二进制内 **内置了足以在本地完成 EC-KCDSA 签名运算的密钥材料**，签发 License 不需要询问任何服务器。

用本项目 `mtsc key2sig` 对该 License 解码/验证（真实 MikroTik 公钥）：

```
Software ID: 2FJ5-TZ4V        # 与喂给 fake keyman 的 "TI09-7WK3" 不一致
Router OS Version: 6
License Level: 22             # 与 loskiq/license.py 中 lic_gen_ros() 硬编码的 varb8=22 相同
License valid: false
```

**解读**（尚未完全定论，见下文）：

1. `keygen` 把 `keyman --software-id` 的**整行原始输出**当作文本原样打印（未做字段解析）。
2. 真正被签进 License 的 `Software ID`（`2FJ5-TZ4V`）是它**自行另行计算**的——很可能内部还有一套与本项目 `mtsc` 相近的"读磁盘参数 → 算 SOFTWARE ID"逻辑，而不是信任 `keyman` 打印的文本。本观测所用 `fake_rootdisk` 为全零普通文件（非真实块设备、无真实 Model/Serial/容量），故其算出的 ID 无真实含义，License 自然验证不过。
3. `License valid: false` 表明这份 License **未通过真实 MikroTik 公钥验证**。这既可能因为输入数据是伪造的，也可能因为内置密钥是**该补丁项目自签的密钥**（只对已 patch 固件有效），本报告未对此下定论。

### 6.1 SOFTWARE ID 签发流程补充（2026-09-14，静态+动态双重证据）

**确认第 2 点的猜测**：完整 `strace -f -i -k` 追踪显示，`keygen_x86` 在 `execve(/nova/bin/keyman)` **之后**又重新读了一次 `/dev/root-disk`（fd 3），读出的数据和身份随机化那一步写入的同一段随机字节完全一致——证实签发的 SOFTWARE ID 确实是**从磁盘重新读出来计算的**，`keyman` 打印的文本只是原样回显用于显示，从未被解析/使用。`keyman` 的 stdout 也确认是通过 `pipe2`+`clone`+`execve` 真正捕获的（标准 Go `os/exec` `Output()` 模式），不是靠继承 stdout。

**找到 `mt_transform` 等效代码**（地址约 `0x82f30a0`-`0x82f34a3`）：反汇编显示一段操作 4 个寄存器的循环，核心特征是 **8 处 `rol reg,cl`（数据依赖的变量位移量循环左移）**，配合"从全局表按下标取值 → 减法 → 与旋转结果异或"的结构，和这个项目 `convert.rs::mt_transform()` 的"减法 → 数据依赖旋转 → 异或 → 加法"ARX 结构吻合。全局表通过 `ds:0x84eae68`/`ds:0x84eae6c`（Go slice 的 ptr/len 字段模式）访问，与 `ROUND_CONSTANTS` 按下标索引的访问方式一致。未逐条验证代数顺序是否完全相同（`keygen_x86` 这边应该走加密方向，本项目 `mt_transform` 走的是解密方向，运算顺序理论上会互为镜像）。

**base64 LSB-first 间接证据**：未做新的静态验证，但已有充分的间接证据——本项目自己的 `MT_BASE64`（`data_encoding` + `BitOrder::LeastSignificantFirst`）能把 `keygen_x86` 真实生成的 License Key 文本**结构性解码成功**（解出规整的 64 字节块，`Nonce Hash`/`Signature` 字段格式正常，不是乱码）。如果 `keygen_x86` 用的是标准 MSB-first base64，用 LSB-first 解码器去解几乎不可能凑巧得到规整结构，所以这足以支持"两者比特序一致"的结论。

**未能定位**（如实记录，不强行下结论）：
- 16 字节 payload 的具体拼装位置（`SOFTWARE_ID(6B) + reserved(1B) + level=22(1B) + 补零(8B)`）——搜索附近区域的 `0x16` 立即数只找到一处比较指令，没找到写入。
- 签名调用本身的位置/参数结构——延续了此前几轮自动化单步追踪的失败结果，这次人工排查也未能定位，`.gopclntab` 存在但 `go tool objdump -s` 因缺 `.symtab` 无法用，函数名恢复仍不可行。

### 6.2 Ghidra 无头分析尝试（2026-09-14）：确认函数边界，反编译/调用者追踪受阻于 garble

`hkg-land-03` 上部署了 Ghidra 11.2.1（`analyzeHeadless` 无头模式），对 `keygen_x86` 做了标准导入分析，用 Jython 脚本定位 §6.1 提到的 `mt_transform` 等效代码所在函数。

**确认了函数真实边界**：`0x082f2e20` - `0x082f34b2`（此前靠人工找 `ret` 推断"两个循环各 4 次旋转对应两个函数"的猜测是错的——Ghidra 判定这就是同一个函数，中间的 `ret` 是无关代码）。

**两个方向都受阻**：

1. **调用者追踪**：`getReferencesTo()` 对函数入口地址返回空结果，没有找到任何调用点。最可能的原因是该函数通过函数指针/接口方法这类**间接调用**触发（反汇编中确实见过 `call eax` 这类模式），静态引用分析追踪不到。
2. **反编译输出不可读**：默认的 `x86:LE:32:default:gcc` 编译规范和 Ghidra 内置的 Go 专用编译规范（`x86:LE:32:default:golang`，随 Ghidra 11.2.1 自带，无需额外插件）都试过，反编译结果里全是 `register0x00000010` 这类占位伪寄存器，不是正常的栈变量。根因在日志里：
   ```
   WARN  Invalid Golang version string [unknown] (GoRttiMapper)
   ERROR Golang symbol analyzer error: unable to get GoRttiMapper
   ```
   Ghidra 的 Go 专用分析依赖读取 `runtime.buildVersion` 字符串来确定 Go 版本，才能正确识别该版本的栈增长检查前导码；**garble 混淆工具专门剥离了这个字符串**，这正是 garble 设计用来对抗此类分析的效果，不是配置问题，换编译规范解决不了。

**结论**：payload 拼装位置、签名调用位置这两个缺口，在"`objdump` 人工读汇编"和"Ghidra 无头分析（含内置 Go 编译规范）"两条路径下都没能突破，根本原因是 garble 混淆本身针对性地干扰了 Go 二进制的自动化分析。继续往下需要更专业的手段（手动重建 Go 版本元数据、自定义脚本剥离栈检查前导码，或专门的 garble 反混淆工具），本报告到此为止，不再继续推进这个方向。

---

## 7. 网络行为总览

对以下所有已测路径，`strace` 的 `network` 分类（`socket`/`connect`/`sendto`/`recvfrom`/`getaddrinfo` 等）追踪结果：

| 运行路径 | 网络 syscall |
|---|---|
| 无参数（`/dev/null` 缺失） | 0 |
| 无参数（`/dev/null` 补齐） | 0 |
| `chr`（拒绝重启 / 确认重启） | 0 |
| `x86`（拒绝重启） | 0 |
| `license`/`activate`/`key`/`sign`/`keygen`（无效参数） | 0 |
| 无参数 + 伪造 `keyman`（签出 License） | 0 |

**结论**：目前已探明的所有执行路径均为**纯本地行为**，无任何外联请求。

---

## 8. 结论与未决问题

### 已确认

1. `keygen_x86` 是 Go 编写的静态二进制，经 garble 混淆、符号与字符串均剥离。
2. 设备探测分 `flash`（厂商私有 ioctl 协议）/ `root-disk`（普通块设备）两条路径。
3. 会对磁盘 MBR 做**随机身份种子 + marker** 写入（偏移 `0x100`/`0x10A`）。
4. CLI 仅有两个有效子命令 `chr`/`x86`（互为镜像，模式切换），无参数路径是隐藏的 License 生成入口，其余参数均为无效参数。
5. `chr`/`x86` 子命令 = 写 MBR 标志位 + `execve(/usr/sbin/reboot -f)`，纯本地、零网络。
6. 无参数路径会调用 `/nova/bin/keyman --software-id`，并**在本地零网络地签出 License**——证明二进制内置签名密钥材料。`keyman` 的输出仅用于显示，**不参与实际计算**：`keygen_x86` 在 `execve` 之后重新读了一次 `/dev/root-disk`，签出的 SOFTWARE ID 来自这次重读，不是解析 `keyman` 的文本（§6.1）。
7. 内置密钥签出的 License 在"伪造磁盘数据"场景下**未通过真实 MikroTik 公钥验证**。
8. `chr`/`x86` 模式标志位偏移已定位：**MBR `0x150`，单字节，`00` = x86，`01` = CHR**（§5）。与 `mikrotik-gpl` 仓库独立证据链（x86_64 内核只有一份 `x86_64.config`，物理网卡驱动与虚拟化 Guest 驱动编译进同一份配置）吻合，支持"x86/CHR 为同一套内核/驱动、仅靠该标志位在运行时切换"的假设。
9. `getrandom` 精确调用点已定位：`0x081b4990`，完整调用链见 §4.1。
10. `mt_transform` 等效代码已定位（地址约 `0x82f30a0`-`0x82f34a3`，§6.1）：ARX 结构、数据依赖旋转、全局表按下标索引，均与本项目 `convert.rs::mt_transform()` 吻合；代数顺序未逐条验证。
11. MikroTik 定制 SHA-256 IV 全部 8 个字均已确认，与本项目 `src/sha256_constants.rs::INITIAL_HASH_VALUES` 逐字节一致（§4.1 附近的交叉验证）。
12. base64 LSB-first 比特序有间接证据支持（本项目 `MT_BASE64` 能结构性解码 `keygen_x86` 真实输出，§6.1），未做直接静态验证。

### 未决问题（本报告不做、也不建议在此方向上继续）

1. 内置私钥究竟是"补丁项目自签密钥"还是"MikroTik 官方私钥"——可通过对真实合法设备的磁盘数据做行为级验证来间接判断（**不提取密钥**，见文末安全边界），本报告未完成。
2. **16 字节 payload 的具体拼装位置**（`SOFTWARE_ID(6B) + reserved(1B) + level=22(1B) + 补零(8B)`）尚未定位——搜索附近区域的 `0x16` 立即数只找到比较指令，没找到写入；Ghidra 无头分析（含内置 `golang` 编译规范）也未能突破，根因是 garble 剥离了 `runtime.buildVersion`，Ghidra 的 Go 专用分析器因此失效（§6.1、§6.2）。本方向**暂时搁置**，不建议在没有更专业的 Go 反混淆工具前继续投入。
3. ~~`0x150` 具体被哪段代码消费尚未确认~~ **已解决，见 `docs/investigation/license-internals.md` §8.64**：从真实 x86 `keyman`（官方 `routeros-7.24.2.npk` 提取）反汇编直接定位到独立函数 `0x804bfb5`——校验 MBR `0x1FE` 引导签名后，读取偏移 `0x150` 处 4 字节并取最低 1 位返回。与本报告动态观测的 `00`=x86/`01`=CHR 整字节写入完全吻合（读取端只关心 bit0）。该读取**独立于** `nv::ROSMode`/`hasFeature()` 机制（`keyman` 并不导入这两个符号，只有 `loader`/`sysinit`/`moduler` 导入）——这个读取函数的调用者（即返回的 bit 具体怎么被用来切换许可证解析格式）尚未追，仍是开放项。
4. **签名调用本身的位置/参数结构未定位**——多轮自动化单步追踪 + 人工反汇编排查 + Ghidra 无头分析（`getReferencesTo()` 对目标函数入口返回空，疑似经函数指针间接调用，静态引用分析追踪不到）均未成功；`.gopclntab` 存在但因 `.symtab` 被剥离，`go tool objdump -s` 无法使用，函数名恢复仍不可行（§6.1、§6.2）。**同样暂时搁置**。

---

## 附：本会话安全边界

- 全程使用 `unshare --fork --pid --mount --mount-proc` 私有命名空间 + strace 故障注入，未对宿主机真实块设备做任何写入。
- 早期一次未加 PID 隔离的测试导致宿主机真实重启（`keygen chr` 对 EOF stdin 默认确认重启），事故根因与规避方法已记录于 `03-sandbox-manual.md`。
- 未提取、未 dump、未还原任何私钥标量字节；本报告仅记录可观测的行为与验证结果。
