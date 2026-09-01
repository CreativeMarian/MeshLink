//! Windows DPAPI 绑定（Controller MVP：设备身份持久化）。
//!
//! - `CryptProtectData` / `CryptUnprotectData`（crypt32.dll）；
//! - **CurrentUser scope**（不使用 CRYPTPROTECT_LOCAL_MACHINE——machine-wide
//!   任何进程可解密，违反最小权限；MeshAgentService 以用户身份运行时绑定
//!   该用户，服务切换运行身份需 re-enrollment，见 DEVICE_IDENTITY.md）；
//! - 输出缓冲由 LocalFree 释放（DPAPI 约定，防泄漏）。

#![allow(non_snake_case, non_camel_case_types)]

use mesh_common::{ErrorCode, MeshError};
use std::os::raw::{c_int, c_void};

#[repr(C)]
struct CRYPT_INTEGER_BLOB {
    cbData: u32,
    pbData: *mut u8,
}

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

extern "system" {
    fn CryptProtectData(
        pDataIn: *const CRYPT_INTEGER_BLOB,
        szDataDescr: *const u16,
        pOptionalEntropy: *const CRYPT_INTEGER_BLOB,
        pvReserved: *mut c_void,
        pPromptStruct: *mut c_void,
        dwFlags: u32,
        pDataOut: *mut CRYPT_INTEGER_BLOB,
    ) -> c_int;
    fn CryptUnprotectData(
        pDataIn: *const CRYPT_INTEGER_BLOB,
        ppszDataDescr: *mut *mut u16,
        pOptionalEntropy: *const CRYPT_INTEGER_BLOB,
        pvReserved: *mut c_void,
        pPromptStruct: *mut c_void,
        dwFlags: u32,
        pDataOut: *mut CRYPT_INTEGER_BLOB,
    ) -> c_int;
    fn LocalFree(hMem: *mut c_void) -> *mut c_void;
}

/// DPAPI 加密（CurrentUser scope）→ 返回密文。
pub fn protect(plain: &[u8]) -> Result<Vec<u8>, MeshError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: plain.len() as u32,
        pbData: plain.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe {
        CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(),
            std::ptr::null_mut(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
    };
    if ok == 0 {
        return Err(MeshError::new(ErrorCode::Internal, "DPAPI CryptProtectData 失败"));
    }
    let out = unsafe {
        let v = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut c_void);
        v
    };
    Ok(out)
}

/// DPAPI 解密（CurrentUser scope）。
pub fn unprotect(cipher: &[u8]) -> Result<Vec<u8>, MeshError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: cipher.len() as u32,
        pbData: cipher.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe {
        CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut(),
            std::ptr::null_mut(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
    };
    if ok == 0 {
        // 跨用户 / 跨机器 / 篡改的密文都走这里：不区分细节（防探测）。
        return Err(MeshError::new(ErrorCode::Internal, "DPAPI CryptUnprotectData 失败（密文非本用户或已损坏）"));
    }
    let out = unsafe {
        let v = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut c_void);
        v
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_roundtrip() {
        let plain = b"meshlink-private-key-material-32";
        let cipher = protect(plain).expect("protect");
        assert_ne!(&cipher, plain);
        let back = unprotect(&cipher).expect("unprotect");
        assert_eq!(back, plain.to_vec());
    }

    #[test]
    fn dpapi_rejects_garbage() {
        assert!(unprotect(b"garbage-not-dpapi-blob").is_err());
        assert!(unprotect(&[]).is_err());
    }
}
