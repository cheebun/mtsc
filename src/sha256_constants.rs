//! MikroTik custom SHA-256 shared constants
//!
//! Shared by all SHA-256 backends and the license metadata decoder,
//! avoiding duplicated definitions.

/// MikroTik custom SHA-256 round constants (64 u32)
///
/// Standard SHA-256 uses the fractional parts of the cube roots of the first 64 primes;
/// MikroTik replaces them with proprietary constants to prevent confusion with standard implementations.
pub(crate) const ROUND_CONSTANTS: [u32; 64] = [
    0x0548D563, 0x98308EAB, 0x37AF7CCC, 0xDFBC4E3C, 0xF125AAC9, 0xEC98ACB8, 0x8B540795, 0xD3E0EF0E,
    0x4904D6E5, 0x0DA84981, 0x9A1F8452, 0x00EB7EAA, 0x96F8E3B3, 0xA6CDB655, 0xE7410F9E, 0x8EECB03D,
    0x9C6A7C25, 0xD77B072F, 0x6E8F650A, 0x124E3640, 0x7E53785A, 0xE0150772, 0xC61EF4E0, 0xBC57E5E0,
    0xC0F9A285, 0xDB342856, 0x190834C7, 0xFBEB7D8E, 0x251BED34, 0x0E9F2AAD, 0x256AB901, 0x0A5B7890,
    0x9F124F09, 0xD84A9151, 0x427AF67A, 0x8059C9AA, 0x13EAB029, 0x3153CDF1, 0x262D405D, 0xA2105D87,
    0x9C745F15, 0xD1613847, 0x294CE135, 0x20FB0F3C, 0x8424D8ED, 0x8F4201B6, 0x12CA1EA7, 0x2054B091,
    0x463D8288, 0xC83253C3, 0x33EA314A, 0x9696DC92, 0xD041CE9A, 0xE5477160, 0xC7656BE8, 0x5179FE33,
    0x1F4726F1, 0x5F393AF0, 0x26E2D004, 0x6D020245, 0x85FDF6D7, 0xB0237C56, 0xFF5FBD94, 0xA8B3F534,
];

/// MikroTik custom SHA-256 initial vector (8 u32)
///
/// Standard SHA-256 uses the fractional parts of the square roots of the first 8 primes;
/// MikroTik replaces them with proprietary values.
pub(crate) const INITIAL_HASH_VALUES: [u32; 8] = [
    0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F, 0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA,
];
