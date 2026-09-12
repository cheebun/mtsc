//! AArch64 CPU detection used only while constructing hashing engines.

/// Check all CPU features needed by the ARM SHA2 kernel.
pub(crate) fn arm_sha2_supported() -> bool {
    if std::arch::is_aarch64_feature_detected!("sha2")
        && std::arch::is_aarch64_feature_detected!("neon")
    {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        darwin_sha2_with(sysctl_flag)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
fn darwin_sha2_with(mut flag: impl FnMut(&std::ffi::CStr) -> bool) -> bool {
    // Rust 1.94 std_detect requires hw.optional.AdvSIMD, which is absent on some
    // macOS versions. Query the documented SHA features and the NEON alias;
    // unknown keys/errors must never authorize an unsupported instruction.
    flag(c"hw.optional.arm.FEAT_SHA1")
        && flag(c"hw.optional.arm.FEAT_SHA256")
        && (flag(c"hw.optional.AdvSIMD") || flag(c"hw.optional.neon"))
}

#[cfg(target_os = "macos")]
fn sysctl_flag(name: &std::ffi::CStr) -> bool {
    use std::ffi::{c_char, c_int, c_void};
    unsafe extern "C" {
        fn sysctlbyname(
            name: *const c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }
    let mut value: c_int = 0;
    let mut len = std::mem::size_of_val(&value);
    // The NUL-terminated key and writable integer/length live for the call;
    // null newp with newlen=0 makes this a read-only sysctl query.
    let result = unsafe {
        sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut c_int).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    result == 0 && len == std::mem::size_of_val(&value) && value == 1
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn darwin_sha2_requires_all_features() {
        for sha1 in [false, true] {
            for sha256 in [false, true] {
                for neon in [false, true] {
                    let found = darwin_sha2_with(|name| match name.to_bytes() {
                        b"hw.optional.arm.FEAT_SHA1" => sha1,
                        b"hw.optional.arm.FEAT_SHA256" => sha256,
                        b"hw.optional.neon" => neon,
                        _ => false,
                    });
                    assert_eq!(found, sha1 && sha256 && neon);
                }
            }
        }
        assert!(!darwin_sha2_with(|_| false));
        assert!(darwin_sha2_with(|name| name != c"hw.optional.neon"));
    }

    #[test]
    fn missing_sysctl_fails_closed() {
        assert!(!sysctl_flag(
            c"hw.optional.ros_serialgen_nonexistent_feature"
        ));
    }

    #[test]
    fn detected_features_include_darwin_sha2() {
        if darwin_sha2_with(sysctl_flag) {
            assert!(arm_sha2_supported());
        }
    }
}
