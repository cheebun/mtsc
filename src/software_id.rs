//! SOFTWARE ID encoding/decoding and computation
//!
//! RouterOS uses Base-35 encoding to map a ~40-bit integer to a SOFTWARE ID in `XXXX-XXXX` format.
//! The character table follows MikroTik's proprietary order, not standard Base36.

/// Base-35 character table (MikroTik proprietary order)
const SID_TABLE: &[u8] = b"TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE";

/// Decode a SOFTWARE ID string into a u64 integer.
///
/// Returns `Err` if the input contains characters not present in the Base-35 table.
pub fn decode(s: &str) -> Result<u64, String> {
    let clean: Vec<u8> = s.bytes().filter(|&b| b != b'-').collect();
    let mut val: u64 = 0;
    for &ch in clean.iter().rev() {
        val *= 35;
        match SID_TABLE.iter().position(|&c| c == ch) {
            Some(pos) => val += pos as u64,
            None => return Err(format!("invalid Base-35 character: '{}'", ch as char)),
        }
    }
    Ok(val)
}

/// Encode a u64 integer into a SOFTWARE ID string (`XXXX-XXXX` format).
///
/// Zero encodes as `TTTT-TTTT`.
pub fn encode(mut val: u64) -> String {
    let mut result = String::with_capacity(9);
    for i in 0..8 {
        result.push(SID_TABLE[(val % 35) as usize] as char);
        val /= 35;
        if i == 3 {
            result.push('-');
        }
    }
    result
}

/// Convert the disk's total sector count to sector_val (>> 11, then round up to 4-bit alignment).
///
/// RouterOS uses this value to reduce the SOFTWARE ID's sensitivity to exact disk capacity.
/// For example, 500G drives from the same batch may differ by ±0.1% in capacity;
/// after rounding, their sector_val is identical.
///
/// # Rules
/// ```text
/// raw = total_sectors >> 11
/// bits = highest_set_bit(raw)
/// If bits <= 4: return raw directly
/// Otherwise: round up to a (bits - 4)-bit boundary
/// ```
pub fn round_sectors(raw: u32) -> u32 {
    if raw == 0 {
        return 0;
    }
    let bits = 32 - raw.leading_zeros() as i32;
    if bits <= 4 {
        return raw;
    }
    let shift = (bits - 4) as u32;
    let has_remainder = (raw & ((1 << shift) - 1)) != 0;
    ((raw >> shift) + if has_remainder { 1 } else { 0 }) << shift
}
