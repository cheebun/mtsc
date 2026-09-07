# RouterOS CHR 7.17 — patched

PVE VM 301, a Cloud Hosted Router (CHR) image, RouterOS 7.17, patched. CHR doesn't use the
SOFTWARE-ID/MBR-signature scheme this project's x86 collision search targets — CHR authorization
works differently.

## Files

| File | Size | What it is |
|---|---|---|
| `RouterOS-v7.17-CHR-patched.vma` | 61,425,664 bytes | Proxmox `vzdump` backup (plain `.vma`). Restore with `qmrestore`. |

## Scheme

```
Disk: 1G qcow2, no custom model/serial
CPU/memory: 1 core, 256MB
BIOS: SeaBIOS
Router OS version: 7.17
-----
System ID: eJq8zK/UrhN
Level: p-unlimited
Limited-upgrades: no
Next-renewal-at: 2099-12-02 00:00:00
Deadline-at: 2100-01-01 00:00:00
```

Confirmed via `/system/license/print` on the running VM. CHR licensing is bound to a `system-id`
(derived from the VM's BIOS UUID), not the x86 SOFTWARE-ID/MBR-signature scheme this project's
collision search targets.

```
-----BEGIN MIKROTIK SOFTWARE KEY------------
5aQeTkbQJ593MViYoh4Z7tFwNPR57RqD17LpksqQzPKP
t/Gh1c+cUv/dOn+M3xCNJTnAQ0AgGY2s1XKEjzuaGA==
-----END MIKROTIK SOFTWARE KEY--------------
```

Signature hex:
```
B9067913B94149DEDF4C25626888677B5BC0CD13E57BA40EF5BEA424AB42F3A33CED6F8435E773D4FB77CEE933772C34C97402100D800666B3F5A510E3EC6A06
```

MBR hex (80 bytes, header + signature):
```
00000000000000000000BDE800000000B9067913B94149DEDF4C25626888677B5BC0CD13E57BA40EF5BEA424AB42F3A33CED6F8435E773D4FB77CEE933772C34C97402100D800666B3F5A510E3EC6A06
```
