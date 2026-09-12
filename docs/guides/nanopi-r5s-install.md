# NanoPi R5S (PVE) 安装 RouterOS 7.24.1 ARM64 教程

## 硬件环境

宿主机为 [NanoPi R5S](https://wiki.friendlyelec.com/wiki/index.php/NanoPi_R5S)（[中文文档](https://wiki.friendlyelec.com/wiki/index.php/NanoPi_R5S/zh)），搭载瑞芯微 RK3568 处理器（ARM64 架构）。

系统采用 FriendlyElec 提供的[官方镜像](https://wiki.friendlyelec.com/wiki/index.php/NanoPi_R5S#Official_image)（`rk3568-XYZ-proxmox-6.1-YYYYMMDD.img.gz`），本质上是 FriendlyElec 自编译的 Debian 12 系统上安装了 PVE 8.2.7 服务，并非 Proxmox 官方原生编译的发行版。宿主机通过设备树（Device Tree）引导，而非 ACPI。

因为宿主机本身是 ARM64，所有虚拟机也只能运行 ARM64 架构（`arch: aarch64, machine: virt`），无法运行 x86 镜像。

## 核心问题

在 ARM64 QEMU `virt` 机型上安装 RouterOS 时，会遇到一个关键障碍：**该机型没有 IDE 和 SATA 总线**。

常规做法是将 ISO 挂载为 SCSI CD-ROM（`media=cdrom`），但 RouterOS 安装内核启动后会报错 `FATAL ERROR: no CD-ROM found(1)`——因为 virtio-scsi 控制器下的 CD-ROM 设备不会在 Linux 中注册为标准的 `/dev/sr0` 节点，安装程序根本找不到安装介质。

## 解决方案

将 ISO 文件直接作为**普通 SCSI 磁盘**挂载（不带 `media=cdrom`）。这样做的原理是：UEFI 固件能够识别 ISO 内嵌的 `efiboot.img`，从中加载 `BOOTAA64.EFI` 引导安装内核；安装内核启动后会扫描所有块设备，在 SCSI 磁盘上找到 npk 安装包，从而顺利完成安装。

本教程的配置对应 Software ID `C7CU-PGT9`。

---

## 第一步：创建虚拟机

以下命令一步完成虚拟机创建，涵盖目标系统盘、ISO 安装盘、EFI 变量盘以及磁盘 model/serial 参数：

```bash
qm create 304 \
  --name MikroTik-RouterOS-arm64 \
  --arch aarch64 --bios ovmf --machine virt \
  --cpu host --cores 2 --memory 512 --ostype l26 \
  --scsihw virtio-scsi-pci \
  --scsi0 local:1,format=qcow2 \
  --scsi1 local:iso/mikrotik-7.24.1-arm64.iso,size=73032K \
  --boot order=scsi1\;scsi0 \
  --net0 virtio,bridge=vmbr0 \
  --serial0 socket --vga virtio \
  --efidisk0 local:0,efitype=4m,pre-enrolled-keys=0,format=raw \
  --args "-set device.scsi0.product=RouterOS-SCSI -set device.scsi0.serial=653876263836"
```

**参数说明：**

| 参数 | 说明 |
|------|------|
| `--scsi0 local:<GB>,format=qcow2` | 目标系统盘。`<GB>` 为容量，单位 GB（如 `local:1` 即 1GB）。创建时仅支持数字形式，不支持 `size=1G` 写法。创建后 PVE 自动展开为完整路径 |
| `--scsi1 ...,size=73032K` | ISO 安装盘。`size` 为 ISO 文件的实际大小（KB），通过 `ls -l` 查看字节数再除以 1024 得到。**绝对不能带 `media=cdrom`**，这是本方案的关键 |
| `--efidisk0 local:0` | EFI 变量盘，`0` 表示使用默认容量（64MB） |
| `--args` | 通过 QEMU 参数设置目标磁盘的 model 和 serial。**必须在创建时指定**，否则安装后 SOFTWARE ID 会是不可预期的默认值。`device.scsi0` 对应目标磁盘的 SCSI ID |

> 本例为 `scsi0`/`virtio-scsi-pci`，`sector_val` 固定为 `0`，磁盘容量不参与 SOFTWARE ID。使用 `mtsc check --bus scsi --model RouterOS-SCSI --serial 653876263836` 可不传 `--size`，但必须显式指定 `--model`。短数字 serial 会分别输出左补零和右补空格的结果，应核对与虚拟机实际匹配的一项。`ide`/`nvme` 则必须提供容量，并使用相同的 sector rounding。使用 qcow2 还是 raw 格式不影响虚拟机内部看到的磁盘大小。

---

## 第二步：启动并安装

```bash
qm start 304
```

打开 **PVE Web 控制台**，选中 VM 304，点击右上角 **Console** 下拉菜单，选择 **xterm.js**。

等待约 25–30 秒（ARM64 UEFI 启动较慢），安装界面会自动显示。如果超时仍为空白，按一下 Enter 即可刷新。

**安装操作流程：**

1. **选择目标磁盘** — 使用左右方向键切换磁盘，按 Enter 确认。由于 xterm.js 连接有延迟，可能会错过这个画面，此时按一下左右方向键即可刷新显示出磁盘列表，选择后按 Enter 确认
2. **选择安装包** — 使用上下方向键或 `p`/`n` 键移动光标，空格键勾选或取消。`system` 包默认已选中，建议额外勾选 `container`（从 system 按两次 ↓ 再按空格）等所需的包
3. **开始安装** — 按 `i` 键
4. **确认擦除磁盘** — 屏幕提示 `Warning: all data on the disk '/dev/sda' will be erased!`，按 `y` 确认
5. **等待安装完成** — 屏幕显示 `Software installed. Press ENTER to reboot`
6. **不要按 Enter** — 直接在宿主机上执行 `qm stop 304` 停止虚拟机

---

## 第三步：切换为磁盘启动

安装完成后，删除 ISO 安装盘并将启动顺序改为仅从系统盘引导。由于目标盘始终挂在 scsi0，`--args` 中的设备名无需修改：

```bash
qm set 304 --delete scsi1
qm set 304 --boot order=scsi0
```

---

## 第四步：写入 MBR 授权数据

RouterOS 的授权信息存储在磁盘 MBR 的 0x100–0x14F 区域，共 80 字节。通过 `qemu-nbd` 映射 qcow2 磁盘后，用 `dd` 写入：

```bash
modprobe nbd max_part=8
qemu-nbd -c /dev/nbd0 /var/lib/vz/images/304/vm-304-disk-1.qcow2
echo "00000000000000000000BDE800000000F4E11772DEEAED8AF43668DA5EBDAD0846B694FFE9E77EFAE77E11A6049E4303B0B09DCEF8D9A647D643D1BAD4AF13B9659CCB11A06D3A9080096634E4E88B07" | sed 's/../\\x&/g' | xargs printf | dd of=/dev/nbd0 bs=1 seek=$((0x100)) conv=notrunc
dd if=/dev/nbd0 bs=1 skip=$((0x100)) count=80 | od -A x -t x1z
qemu-nbd -d /dev/nbd0
```

上面的固定 header 只适用于本例的全零 identity。当前 `mtsc search` 未指定 `--identity` 时会扫全部 2048 个 `mbr_val`，并默认 `--pad end` 右补空格；新结果必须一起使用输出的 serial、identity、marker，不能照抄本例 header。复现旧搜索约定需显式加 `--identity 00000000000000000000 --pad start`。

上面写入的 80 字节 Hex 由四个字段拼接而成：

| 偏移 | 字段 | 长度 | 本例值 |
|------|------|------|--------|
| 0x100–0x109 | Identity | 10 字节 | `00000000000000000000` |
| 0x10A–0x10B | Marker | 2 字节 | `BDE8` |
| 0x10C–0x10F | Reserved | 4 字节 | `00000000` |
| 0x110–0x14F | Signature | 64 字节 | `F4E11772DEEAED8AF43668DA5EBDAD0846B694FFE9E77EFAE77E11A6049E4303B0B09DCEF8D9A647D643D1BAD4AF13B9659CCB11A06D3A9080096634E4E88B07` |

> ⚠️ **必须先完成安装再写入 MBR。** RouterOS 安装程序会覆盖 0x10A–0x10B 位置的数据，如果先写入授权信息，Marker 会被安装程序破坏。

写入完成后，启动虚拟机：

```bash
qm start 304
```

通过 PVE Web 控制台的 xterm.js 或命令行 `qm terminal 304` 连接串口，即可看到 RouterOS 登录界面。使用 `/system license print` 命令确认授权状态。

---

## 附录：曾尝试过的失败方案

以下方案在实际测试中均无法正常工作，记录在此供参考：

| 方案 | 失败原因 |
|------|----------|
| ISO 挂为 `media=cdrom` | 安装内核报 `FATAL ERROR: no CD-ROM found(1)`，virtio-scsi 下的 CD-ROM 设备不被识别 |
| 通过 IDE 总线挂载 | QEMU 报 `Bus 'ide.1' not found`，ARM64 virt 机型不提供 IDE 控制器 |
| 通过 SATA 总线挂载 | ARM64 virt 机型不提供 AHCI 控制器，无法使用 SATA 设备 |
| ISO 挂为 virtio-blk 磁盘 | 虚拟机黑屏无输出，UEFI 固件无法从 virtio-blk 设备上识别 ISO 的引导结构 |
