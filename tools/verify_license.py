#!/usr/bin/env python3
"""verify_license.py -- standalone, pure-stdlib reimplementation of this project's
license verification (src/convert.rs + src/curve25519.rs), for anywhere a Rust
toolchain isn't available.

Pipeline: Key text -> MTBase64 decode -> 64 raw bytes -> split into
(payload[16], nonce_hash[16], signature[32]) -> ARX-decrypt payload (mt_transform)
-> EC-KCDSA verify(payload, nonce_hash, signature, LICENSE_PUBLIC_KEY).

The EC-KCDSA step is implemented via plain Montgomery-curve affine (x, y) point
arithmetic (add/double/scalar-mult) rather than curve25519-dalek's Edwards-form
internals -- mathematically equivalent, see src/curve25519.rs's doc comment for why.

This copy uses the real, stock MikroTik public key. See backup/patched/ for a copy
that uses a patched/substituted public key instead, for verifying self-signed test
licenses against a MikroTikPatch-style trust key swap.

Usage:
    python3 verify_license.py path/to/license.key
    python3 verify_license.py path/to/license.key --pubkey <64-hex-char-public-key>
"""

import sys

# ---- MikroTik custom SHA-256 constants (src/sha256_constants.rs) ----

ROUND_CONSTANTS = [
    0x0548D563, 0x98308EAB, 0x37AF7CCC, 0xDFBC4E3C, 0xF125AAC9, 0xEC98ACB8, 0x8B540795, 0xD3E0EF0E,
    0x4904D6E5, 0x0DA84981, 0x9A1F8452, 0x00EB7EAA, 0x96F8E3B3, 0xA6CDB655, 0xE7410F9E, 0x8EECB03D,
    0x9C6A7C25, 0xD77B072F, 0x6E8F650A, 0x124E3640, 0x7E53785A, 0xE0150772, 0xC61EF4E0, 0xBC57E5E0,
    0xC0F9A285, 0xDB342856, 0x190834C7, 0xFBEB7D8E, 0x251BED34, 0x0E9F2AAD, 0x256AB901, 0x0A5B7890,
    0x9F124F09, 0xD84A9151, 0x427AF67A, 0x8059C9AA, 0x13EAB029, 0x3153CDF1, 0x262D405D, 0xA2105D87,
    0x9C745F15, 0xD1613847, 0x294CE135, 0x20FB0F3C, 0x8424D8ED, 0x8F4201B6, 0x12CA1EA7, 0x2054B091,
    0x463D8288, 0xC83253C3, 0x33EA314A, 0x9696DC92, 0xD041CE9A, 0xE5477160, 0xC7656BE8, 0x5179FE33,
    0x1F4726F1, 0x5F393AF0, 0x26E2D004, 0x6D020245, 0x85FDF6D7, 0xB0237C56, 0xFF5FBD94, 0xA8B3F534,
]
INITIAL_HASH_VALUES = [
    0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F,
    0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA,
]

MASK32 = 0xFFFFFFFF

# ---- EC-KCDSA / license public key (src/curve25519.rs) ----
# The real, stock MikroTik `keyman` public key.

LICENSE_PUBLIC_KEY = bytes.fromhex(
    "8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"
)

# ---- Base-35 SOFTWARE ID table (src/software_id.rs) ----

SID_TABLE = b"TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE"

KEY_BEGIN_MARKER = "-----BEGIN MIKROTIK SOFTWARE KEY------------"
KEY_END_MARKER = "-----END MIKROTIK SOFTWARE KEY--------------"

BASE64_TABLE = list(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


def rotl32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK32


def rotr32(x, n):
    n &= 31
    return ((x >> n) | (x << (32 - n))) & MASK32


# ---- MTBase64 (src/convert.rs::mt_base64_decode / mt_base64_encode) ----
# Same alphabet as standard base64, but LSB-first bit packing -- a literal
# transliteration of the Rust state machine, not a from-scratch reimplementation.


def mt_base64_decode(data: str) -> bytes:
    b64_bytes = [b for b in data.encode("ascii") if b != ord("=")]
    result = bytearray()
    pending_bits = 0
    for i, byte in enumerate(b64_bytes):
        if pending_bits == 0:
            pending_bits = 6
        else:
            pos_prev = BASE64_TABLE.index(b64_bytes[i - 1])
            pos_curr = BASE64_TABLE.index(byte)
            value1 = pos_prev >> (6 - pending_bits)
            value2 = pos_curr & ((1 << (8 - pending_bits)) - 1)
            value = (value1 | (value2 << pending_bits)) & 0xFF
            result.append(value)
            pending_bits -= 2
    return bytes(result)


def mt_base64_encode(data: bytes) -> str:
    encoded = []
    pending_bits = 0
    for i, byte in enumerate(data):
        if pending_bits == 0:
            encoded.append(BASE64_TABLE[byte & 0x3F])
            pending_bits = 2
        elif pending_bits == 6:
            encoded.append(BASE64_TABLE[data[i - 1] >> 2])
            encoded.append(BASE64_TABLE[byte & 0x3F])
            pending_bits = 2
        else:
            index1 = data[i - 1] >> (8 - pending_bits)
            index2 = byte << pending_bits
            encoded.append(BASE64_TABLE[(index1 | index2) & 0x3F])
            pending_bits += 2
    if pending_bits != 0 and data:
        encoded.append(BASE64_TABLE[data[-1] >> (8 - pending_bits)])
    while len(encoded) % 4 != 0:
        encoded.append(ord("="))
    return bytes(encoded).decode("ascii")


def key_text_to_signature_bytes(key_text: str) -> bytes:
    without_markers = key_text.replace(KEY_BEGIN_MARKER, "").replace(KEY_END_MARKER, "")
    b64_data = "".join(ch for ch in without_markers if not ch.isspace())
    if not b64_data:
        raise ValueError("no key data found")
    decoded = mt_base64_decode(b64_data)
    if len(decoded) != 64:
        raise ValueError(f"signature must be 64 bytes, got {len(decoded)}")
    return decoded


def signature_bytes_to_key_text(sig_bytes: bytes) -> str:
    if len(sig_bytes) != 64:
        raise ValueError(f"signature must be 64 bytes, got {len(sig_bytes)}")
    return KEY_BEGIN_MARKER + mt_base64_encode(sig_bytes) + KEY_END_MARKER


# ---- mt_transform: MikroTik's proprietary ARX block cipher (src/convert.rs::mt_transform) ----


def mt_transform(block: bytes) -> bytes:
    assert len(block) == 16
    s = [int.from_bytes(block[i * 4 : i * 4 + 4], "big") for i in range(4)]

    for i in range(16):
        p, q, r, t = i % 4, (i + 1) % 4, (i + 2) % 4, (i + 3) % 4
        k0 = ROUND_CONSTANTS[i * 4]
        k1 = ROUND_CONSTANTS[i * 4 + 1]
        k2 = ROUND_CONSTANTS[i * 4 + 2]
        k3 = ROUND_CONSTANTS[i * 4 + 3]

        s[r] = (s[r] - s[p] - k0) & MASK32
        s[t] = (rotl32(s[p], k0 & 0x0F) ^ s[t])
        s[t] = (s[t] + s[p]) & MASK32

        s[q] = (s[q] - s[t] - k1) & MASK32
        s[r] = (rotl32(s[q], k1 & 0x0F) ^ s[r])
        s[r] = (s[r] + s[q]) & MASK32

        s[p] = (s[p] - s[r] - k2) & MASK32
        s[q] = (rotl32(s[r], k2 & 0x0F) ^ s[q])
        s[q] = (s[q] + s[r]) & MASK32

        s[t] = (s[t] - s[q] - k3) & MASK32
        s[p] = (rotl32(s[t], k3 & 0x0F) ^ s[p])
        s[p] = (s[p] + s[t]) & MASK32

    return b"".join(w.to_bytes(4, "big") for w in s)


# ---- MikroTik custom SHA-256 (src/sha256.rs::compress / mikro_sha256_digest) ----


def compress(padded: bytes):
    w = [0] * 64
    for i in range(16):
        w[i] = int.from_bytes(padded[i * 4 : i * 4 + 4], "big")
    for i in range(16, 64):
        s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK32

    a, b, c, d, e, f, g, h = INITIAL_HASH_VALUES

    for i in range(64):
        s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
        ch = (e & f) ^ ((~e & MASK32) & g)
        t1 = (h + s1 + ch + ROUND_CONSTANTS[i] + w[i]) & MASK32
        s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) & MASK32
        h = g
        g = f
        f = e
        e = (d + t1) & MASK32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK32

    state = [a, b, c, d, e, f, g, h]
    return [(state[i] + INITIAL_HASH_VALUES[i]) & MASK32 for i in range(8)]


def mikro_sha256_digest(data: bytes) -> bytes:
    assert len(data) <= 55, "single-block input only"
    padded = bytearray(64)
    padded[: len(data)] = data
    padded[len(data)] = 0x80
    bit_len = len(data) * 8
    padded[56:64] = bit_len.to_bytes(8, "big")
    state = compress(bytes(padded))
    return b"".join(w.to_bytes(4, "big") for w in state)


# ---- Curve25519 field / Montgomery affine point arithmetic ----

P = 2**255 - 19
A_COEFF = 486662
# Standard Curve25519 base point (9, G_Y); G_Y is the well-known y-coordinate for u=9.
G_Y = 14781619447589544791020593568409986887264606134616475288964881837755586237401
G = (9, G_Y)


def modinv(v):
    return pow(v % P, P - 2, P)


def field_sqrt(a):
    """Square root mod P (P == 5 mod 8). Returns None if `a` is not a QR."""
    a %= P
    if a == 0:
        return 0
    candidate = pow(a, (P + 3) // 8, P)
    if (candidate * candidate - a) % P == 0:
        return candidate
    candidate = (candidate * pow(2, (P - 1) // 4, P)) % P
    if (candidate * candidate - a) % P == 0:
        return candidate
    return None


def point_double(pt):
    if pt is None:
        return None
    x1, y1 = pt
    if y1 % P == 0:
        return None
    lam = ((3 * x1 * x1 + 2 * A_COEFF * x1 + 1) * modinv(2 * y1)) % P
    x3 = (lam * lam - A_COEFF - 2 * x1) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 % P == x2 % P:
        if (y1 + y2) % P == 0:
            return None
        return point_double(p1)
    lam = ((y2 - y1) * modinv(x2 - x1)) % P
    x3 = (lam * lam - A_COEFF - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(pt, k):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result


def recover_y_candidates(x):
    y2 = (pow(x, 3, P) + A_COEFF * pow(x, 2, P) + x) % P
    y0 = field_sqrt(y2)
    if y0 is None:
        return []
    y1 = (P - y0) % P
    return [y0, y1]


def ec_kcdsa_verify(payload16: bytes, nonce_hash16: bytes, signature32_le: bytes, public_key32_le: bytes) -> bool:
    pub_x = int.from_bytes(public_key32_le, "little") & ((1 << 255) - 1)
    sig_scalar = int.from_bytes(signature32_le, "little")

    data_hash = bytearray(mikro_sha256_digest(payload16))
    for i in range(16):
        data_hash[8 + i] ^= nonce_hash16[i]
    data_hash[0] &= 0xF8
    data_hash[31] &= 0x7F
    data_hash[31] |= 0x40
    data_hash_scalar = int.from_bytes(bytes(data_hash), "little")

    term2 = scalar_mult(G, data_hash_scalar)

    for y_cand in recover_y_candidates(pub_x):
        term1 = scalar_mult((pub_x, y_cand), sig_scalar)
        s = point_add(term1, term2)
        if s is None:
            continue
        nonce_bytes = s[0].to_bytes(32, "little")
        recomputed = mikro_sha256_digest(nonce_bytes)
        if recomputed[:16] == nonce_hash16:
            return True
    return False


# ---- SOFTWARE ID Base-35 encode (src/software_id.rs::encode) ----


def software_id_encode(val: int) -> str:
    result = []
    for i in range(8):
        result.append(chr(SID_TABLE[val % 35]))
        val //= 35
        if i == 3:
            result.append("-")
    return "".join(result)


# ---- Top-level: decode a Key text and verify it ----


def decode_and_verify(key_text: str, public_key: bytes = LICENSE_PUBLIC_KEY):
    sig_bytes = key_text_to_signature_bytes(key_text)
    payload = sig_bytes[0:16]
    nonce_hash = sig_bytes[16:32]
    signature = sig_bytes[32:64]

    decrypted = mt_transform(payload)
    software_id_val = int.from_bytes(decrypted[0:8], "little") & 0x0000FFFFFFFFFFFF
    software_id = software_id_encode(software_id_val)
    level = decrypted[7]
    padding_ok = all(b == 0 for b in decrypted[8:])

    valid = ec_kcdsa_verify(decrypted, nonce_hash, signature, public_key)

    return {
        "software_id": software_id,
        "level": level,
        "padding_ok": padding_ok,
        "valid": valid,
        "signature_hex": sig_bytes.hex().upper(),
    }


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(f"usage: {sys.argv[0]} path/to/license.key [--pubkey <64-hex-char-public-key>]", file=sys.stderr)
        sys.exit(2)

    key_path = args[0]
    public_key = LICENSE_PUBLIC_KEY
    if len(args) >= 3 and args[1] == "--pubkey":
        pubkey_hex = args[2]
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        if len(pubkey_bytes) != 32:
            print(f"error: --pubkey must be 64 hex chars (32 bytes), got {len(pubkey_bytes)} bytes", file=sys.stderr)
            sys.exit(2)
        public_key = pubkey_bytes
    elif len(args) != 1:
        print(f"usage: {sys.argv[0]} path/to/license.key [--pubkey <64-hex-char-public-key>]", file=sys.stderr)
        sys.exit(2)

    with open(key_path, "r") as f:
        key_text = f.read()

    result = decode_and_verify(key_text, public_key)
    print(f"SOFTWARE-ID: {result['software_id']}")
    print(f"Level: {result['level']}")
    if public_key != LICENSE_PUBLIC_KEY:
        print(f"Public key: {public_key.hex().upper()} (custom, not the stock MikroTik key)")
    if not result["padding_ok"]:
        print("Warning: reserved bytes not all zero (CHR-format or malformed license)")
    print(f"License valid: {'true' if result['valid'] else 'false'}")
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
