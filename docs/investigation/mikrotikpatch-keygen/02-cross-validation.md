# 交叉验证记录：marker 公式与公钥常量

> 目的：把本会话动态观测到的两条独立证据，与本项目 `mtsc` 的既有实现逐字节比对，形成交叉验证。
> 时间：2026-09-08

---

## 1. Marker 公式验证：`mix_from_identity` / `marker_from_identity` vs 官方 keygen 实测写入

### 1.1 本项目公式（`src/targets.rs`）

```rust
fn raw16_from_identity(identity: &[u8; 10]) -> u16 {
    let sha_val = crate::sha256::hash_10(identity);   // MikroTik 定制 SHA-256 取前 2 字节
    let mut sum: u16 = 0;
    for chunk in identity.chunks_exact(2) {
        sum = sum.wrapping_add(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let chksum = !sum;
    sha_val ^ chksum
}

pub fn marker_from_identity(identity: &[u8; 10]) -> [u8; 2] {
    raw16_from_identity(identity).to_le_bytes()
}
```

公式（文档见 `docs/license-internals.md` §3.2/§3.6）：

```
raw16   = MikroTik_SHA256(identity)[0:2] as LE u16  XOR  NOT(Σ 5 个 LE u16 字)
marker  = raw16 的低 16 位，小端序 → [u8; 2]
```

### 1.2 官方 keygen 的动态观测（`01-dynamic-analysis-keygen-x86.md` §3）

`keygen_x86` 对伪造 `/dev/root-disk` 写入 MBR 时，`strace` 捕获到：

- 偏移 `0x100`（10 字节随机 identity）：`CC 11 26 11 F9 AB 50 FE E6 8E`
- 偏移 `0x10A`（2 字节 marker）：`4F 09`

（偏移值通过逐字节解码 `write(3, "...", 512)` 的转义串、数出 identity 前恰好 256 个 `\0` 字节确认为 `0x100`，与 `src/targets.rs` 文档注释中的标注一致。）

### 1.3 用本项目工具独立复算

```
$ ./target/release/mtsc check \
    --serial 1 --size 6415394816 --unit b \
    --model "VMware Virtual I" --identity CC112611F9AB50FEE68E

  Identity: CC112611F9AB50FEE68E
  Marker:   4F09
```

### 1.4 结论

本项目实现的 `marker_from_identity()` 对官方 obfuscated `keygen_x86` 现场生成的**全新随机 identity** 算出的 marker `4F09`，与二进制实际写入 MBR 的 `4F 09` **逐字节完全一致**。

这条证据的意义：`mix_from_identity`/`marker_from_identity` 公式不再只是"反汇编 + 对既有硬件签名反推"的产物，而是被**官方 keygen 二进制的一次独立、动态、随机的运行**所证实——这是一个新生成的 identity（此前从未在任何已知数据集里出现过），两者在 marker 字节上完全对齐。

---

## 2. 公钥常量验证：`loskiq/MikroTikPatch` vs `curve25519.rs`

### 2.1 两处来源

**来源 A** — `github.com/loskiq/MikroTikPatch` 的 `license.py`（纯 Python 源码，非黑盒二进制），其 `genkey` 子命令硬编码打印：

```python
print('export MIKRO_LICENSE_PUBLIC_KEY="8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"')
print('export MIKRO_NPK_SIGN_PUBLIC_KEY="C293CED638A2A33C681FC8DE98EE26C54EADC5390C2DFCE197D35C83C416CF59"')
```

**来源 B** — 本项目 `src/curve25519.rs` 的 `LICENSE_PUBLIC_KEY` 常量：

```rust
pub const LICENSE_PUBLIC_KEY: [u8; 32] = [
    0x8E, 0x10, 0x67, 0xE4, 0x30, 0x5F, 0xCD, 0xC0, 0xCF, 0xBF, 0x95, 0xC1, 0x0F, 0x96, 0xE5, 0xDF,
    0xE8, 0xC4, 0x9A, 0xEF, 0x48, 0x6B, 0xD1, 0xA4, 0xE2, 0xE9, 0x6C, 0x27, 0xF0, 0x1E, 0x3E, 0x32,
];
```

### 2.2 逐字节比对

| 项 | loskiq/license.py 十六进制 | 本项目 curve25519.rs 字节序 | 结果 |
|---|---|---|---|
| License 验证公钥 | `8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32` | `8E 10 67 E4 30 5F CD C0 CF BF 95 C1 0F 96 E5 DF E8 C4 9A EF 48 6B D1 A4 E2 E9 6C 27 F0 1E 3E 32` | **完全一致** |

### 2.3 结论

两个**完全独立**的逆向工程路径得出了字节级相同的 32 字节公钥：

- 本项目：独立反汇编真实 `keyman_x86_7.23.2` / `keyman_arm32` 二进制，并经真实硬件激活的 `TI09-7WK3` 签名验证通过。
- loskiq fork：未知路径反出后直接以常量形式写死在 Python 脚本里。

两者一致，基本坐实该值确为 **MikroTik 官方真实 license 验证公钥**（X 坐标）。

### 2.4 边界说明

该值属**公钥**——公钥公开是密码学设计的本意（用于验签），泄露公钥不影响安全性，也不能据此签发能通过官方验证的 License。真正不可反推的是与之配对的私钥，本记录不涉及任何私钥材料。

---

## 3. 附：`License Level = 22` 的交叉印证

`keygen_x86` 在伪造 `keyman` 场景下签出的 License，经 `mtsc key2sig` 解码得 `License Level: 22`。

`loskiq/MikroTikPatch` 的 `license.py::lic_gen_ros()` 中同样硬编码：

```python
varb8 = 22  # Features
```

两个独立实现对该字节使用了**同一个魔数 `22`**，说明这是此类自签 License 中"给满功能"的约定标记，而非解析乱码。可作为上述两套工具链同源的旁证。
