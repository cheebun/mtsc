# 沙箱操作手册：安全重测 `keygen_x86`

> 目的：在真实 Linux 主机上安全地动态分析 obfuscated Go 静态二进制 `keygen_x86`，**绝不触碰宿主机的真实块设备，绝不触发宿主机真实重启**。
> 适用环境：Debian 13 x86_64（`hkg-land-03`，root）。需内核支持 `unshare --pid --mount` 与 `mount --mount-proc`。
> 前置：`strace`、`util-linux`（`unshare`）、`coreutils`（`timeout`）已安装。

---

## 0. 目录约定

- **工作目录一律放 `/root/kg`（ext4 磁盘），不放 `/tmp`**：`/tmp` 是 tmpfs，占内存且宿主重启即清空（本会话已因此丢过一次文件）。
- 本机原始二进制来源：`/tmp/MikroTikPatch/keygen/keygen_x86`（本地 macOS 侧），经 `scp` 传至远程 `/root/kg/`。

```bash
ssh hkg-land-03 'mkdir -p /root/kg'
scp /tmp/MikroTikPatch/keygen/keygen_x86 hkg-land-03:/root/kg/keygen_x86
ssh hkg-land-03 'chmod +x /root/kg/keygen_x86 && dd if=/dev/zero of=/root/kg/fake_rootdisk bs=1M count=1'
```

---

## 1. 隔离原理（为什么这套方案可靠）

`keygen_x86` 是**静态链接** Go 二进制，`LD_PRELOAD` 劫持对它无效（无动态库加载、syscall 直通 `int 0x80`/`syscall`）。因此采用两层保护：

### 第一层：非初始 PID namespace（内核级保护）

```bash
unshare --fork --pid --mount --mount-proc
```

- 一旦进程树进入非初始 PID namespace，Linux 内核规定：`reboot(2)` 不会真的重启宿主，而是退化为给该 namespace 的 init 发信号（`SIGHUP`/`SIGINT`），仅清掉沙箱内进程。
- 该保护对**直接调用 `reboot(2)`** 和 **fork/exec 出 `/usr/sbin/reboot` 再由其调用 `reboot(2)`** 两种情况都有效——因为子进程继承同一非初始 namespace。
- `--mount-proc` 会把 `/proc` 挂载为当前 PID namespace 的视图，方便用 `ps` 观察沙箱内进程；它要求同时有 `--mount` 创建新 mount namespace。

### 第二层：strace 故障注入（观测级保护）

```bash
strace -f -e inject=reboot:error=EPERM
```

- `strace` 通过 `ptrace` 在 syscall 执行前拦截，可对**任意二进制**（含静态 Go）生效，不依赖动态链接。
- 让 `reboot` syscall 直接返回 `EPERM`，即使第一层被绕过也能阻止真实重启。
- 注意：故障注入只拦"系统调用名"；若目标通过 `/proc/sysrq-trigger`、kexec、watchdog 等旁路重启，需另行防护（本会话未观测到此类路径）。

---

## 2. 沙箱内 `/dev` 与 `/nova` 的伪造

在私有 mount namespace 里用 tmpfs 覆盖 `/dev`，伪造目标会打开的设备节点：

```bash
unshare --fork --pid --mount --mount-proc -- bash -c '
  mount --make-rprivate / 2>/dev/null
  mount -t tmpfs tmpfs /dev
  cp /root/kg/fake_rootdisk /dev/root-disk
  mknod /dev/null c 1 3
  chmod 666 /dev/null
  cd /root/kg
  # ... 在此运行被测命令 ...
'
```

说明：

- `mount --make-rprivate /`：切断 mount 事件的传播，防止 tmpfs 挂载影响宿主（防御性措施，正常情况下 unshare --mount 已隔离挂载表）。
- `/dev/root-disk`：1MB 全零普通文件模拟 x86/CHR 磁盘。
- `/dev/null`：缺失会导致 `openat("/dev/null") = ENOENT` 提前退出；须 `mknod` 出字符设备并 `chmod 666`。
- `/dev/flash`：**故意不建**，使 `openat("/dev/flash")` 返回 `ENOENT`，让二进制走 `/dev/root-disk` 路径（真实 flash 的厂商私有 ioctl `0x4601` 无法伪造，建了反而卡死）。

伪造 `/nova/bin/keyman`（供"不带参数"路径使用）：

```bash
  mkdir -p /nova
  mount -t tmpfs tmpfs /nova
  mkdir -p /nova/bin
  cat > /nova/bin/keyman <<'EOF'
#!/bin/sh
echo "$@" >> /root/kg/keyman_calls.log
if [ "$1" = "--software-id" ]; then
  echo "software-id: TI09-7WK3"
fi
EOF
  chmod +x /nova/bin/keyman
```

> 注意：若直接 `mkdir -p /nova/bin` 而不先用 tmpfs 覆盖 `/nova`，会写到宿主机真实根文件系统（mount namespace 不隔离已有挂载点内的写操作）。因此**先挂 tmpfs 再 mkdir**。

---

## 3. 标准调用模板

```bash
ssh hkg-land-03 bash -s <<'REMOTE'
unshare --fork --pid --mount --mount-proc -- bash -c '
  mount --make-rprivate / 2>/dev/null
  mount -t tmpfs tmpfs /dev
  cp /root/kg/fake_rootdisk /dev/root-disk
  mknod /dev/null c 1 3
  chmod 666 /dev/null
  cd /root/kg
  strace -f -s 300 \
    -e trace=network,openat,open,connect,socket,write,ioctl,reboot,execve \
    -e inject=reboot:error=EPERM \
    -o /root/kg/tr_XXX.txt \
    timeout 5 ./keygen_x86 <ARGS> <<< "<stdin输入>"
  echo "EXIT:$?"
'
REMOTE
```

**stdin 输入必须显式给出**：

- 测 `chr`/`x86` 且不想触发重启：`<<< "n"`（明确拒绝）。
- 想观测"确认重启"的 syscall 行为：`<<< "y"`（配合上述两层保护，重启会被安全拦截）。
- **切勿让 stdin 为 EOF**（如 `</dev/null` 或无输入的重定向）：`keygen chr` 会把空输入当作确认重启（默认 Y），这是本会话早期真实误重启事故的根因。

---

## 4. 已知安全陷阱

| 陷阱 | 后果 | 规避 |
|---|---|---|
| `keygen chr`/`x86` + EOF stdin | 空输入 = 默认确认重启 → 宿主机真实重启（若未加 PID 隔离） | 显式 `<<< "n"`；永远包在 `unshare --pid` 内 |
| 只有 `unshare -m`（无 `--pid`） | 进程仍是宿主真实 root、有完整 capability，`reboot()` 能打到真实内核 | 必须 `--fork --pid --mount --mount-proc` |
| 在 `/tmp` 工作 | tmpfs 占内存、宿主重启即清空 | 用 `/root/kg` |
| 不挂 tmpfs 就 `mkdir /nova` | 写进宿主真实根文件系统 | 先 `mount -t tmpfs tmpfs /nova` 再建目录 |
| 建假的 `/dev/flash` | 二进制走厂商私有 ioctl 路径，无法伪造而卡死 | 故意不建，让它 ENOENT |

---

## 5. 结果收集

```bash
# 拉取 trace 到本地分析
scp hkg-land-03:/root/kg/tr_XXX.txt /tmp/tr_XXX.txt

# 过滤关键 syscall
grep -nE "openat|write\(|read\(|execve|reboot|connect|socket" /tmp/tr_XXX.txt
```

---

## 6. 本会话已生成的关键 trace（供对照）

| 文件 | 场景 | 关键结论 |
|---|---|---|
| `tr_noargs2/3.txt` | 无参数，`/dev/null` 补齐 | 打开 `/dev/null` 后仍 `exit(2)`；Go runtime 多线程退出 |
| `tr_chr.txt` | `chr` + 拒绝重启 | 写两次 MBR，`execve` 前退出，零网络 |
| `tr_chr_yes.txt` | `chr` + 确认重启 | `execve("/usr/sbin/reboot", ["reboot","-f"])`；两次 `reboot()` 被注入为 `EPERM` |
| `tr_noargs4.txt` | 无参数 + 伪造 `keyman` | 本地零网络签出 License；`key2sig` 验得 `License valid: false` |
