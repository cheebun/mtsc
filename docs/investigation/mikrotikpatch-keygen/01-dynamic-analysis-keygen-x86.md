# 动态分析报告：`keygen_x86`（elseif/MikroTikPatch）

> 状态：已复核到 2026-09-08 的动态观测数据（含完整 CLI 参数矩阵）
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
6. 无参数路径会调用 `/nova/bin/keyman --software-id`，并**在本地零网络地签出 License**——证明二进制内置签名密钥材料。
7. 内置密钥签出的 License 在"伪造磁盘数据"场景下**未通过真实 MikroTik 公钥验证**。

### 未决问题（本报告不做、也不建议在此方向上继续）

1. 内置私钥究竟是"补丁项目自签密钥"还是"MikroTik 官方私钥"——可通过对真实合法设备的磁盘数据做行为级验证来间接判断（不提取密钥），本报告未完成。
2. `keyman --software-id` 的真实输出格式，以及 `keygen` 究竟从哪些磁盘参数自行计算 SOFTWARE ID，尚未完全还原。

---

## 附：本会话安全边界

- 全程使用 `unshare --fork --pid --mount --mount-proc` 私有命名空间 + strace 故障注入，未对宿主机真实块设备做任何写入。
- 早期一次未加 PID 隔离的测试导致宿主机真实重启（`keygen chr` 对 EOF stdin 默认确认重启），事故根因与规避方法已记录于 `03-sandbox-manual.md`。
- 未提取、未 dump、未还原任何私钥标量字节；本报告仅记录可观测的行为与验证结果。
