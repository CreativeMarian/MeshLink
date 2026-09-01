//! 密钥文件严格 ACL（Controller MVP）：DACL 收敛为「当前用户 + SYSTEM」，
//! 并以 PROTECTED_DACL 切断目录继承（父目录宽松 ACE 不再生效）。
//!
//! FFI 说明（对照 MIB_IFROW ABI 教训，逐字段核对）：
//! - `SE_OBJECT_TYPE` 枚举**首位是 `SE_UNKNOWN_OBJECT_TYPE = 0`**，
//!   `SE_FILE_OBJECT = 1`——传 0 会被 Get/SetNamedSecurityInfoW 以
//!   ERROR_INVALID_PARAMETER(87) 拒绝（曾踩坑：.NET P/Invoke 对照实验定位）；
//! - `TOKEN_USER` = `{ SID_AND_ATTRIBUTES User }`，
//!   `SID_AND_ATTRIBUTES` = `{ PSID Sid; DWORD Attributes }`
//!   → x64 布局 8 + 4(+4 padding) = 16 字节；
//! - `SetNamedSecurityInfoW` 签名 8 参（W 版字符串；A 版同名）；
//! - `ConvertStringSidToSidW`（advapi32）获得 SYSTEM SID（S-1-5-18），
//!   比 AllocateAndInitializeSid 的 6 参 subauthority 数组更不易出错。

#![allow(non_snake_case, non_camel_case_types)]

use mesh_common::{ErrorCode, MeshError};
use std::ffi::OsStr;
use std::os::raw::{c_int, c_void};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

const SE_FILE_OBJECT: u32 = 1; // SE_OBJECT_TYPE：0=SE_UNKNOWN_OBJECT_TYPE，1=SE_FILE_OBJECT（枚举首位是 UNKNOWN，勿从 0 起）
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const ACL_REVISION: u32 = 2; // ACCESS_ALLOWED_ACE 只需 REVISION 2
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
const TOKEN_QUERY: u32 = 0x8;
const TOKEN_USER: u32 = 1; // TOKEN_INFORMATION_CLASS

const ACL_BUFFER_LEN: usize = 512; // 2 个 ACE（用户 SID ≤ 68B + SYSTEM 12B）远小于此

type HANDLE = *mut c_void;
type PSID = *mut c_void;
type PCWSTR = *const u16;

extern "system" {
    // advapi32
    fn OpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: u32, TokenHandle: *mut HANDLE) -> c_int;
    fn GetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: u32,
        TokenInformation: *mut c_void,
        TokenInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> c_int;
    fn InitializeAcl(pAcl: *mut u8, nAclLength: u32, dwAclRevision: u32) -> c_int;
    fn AddAccessAllowedAce(pAcl: *mut u8, dwAceRevision: u32, AccessMask: u32, pSid: PSID) -> c_int;
    fn SetNamedSecurityInfoW(
        pObjectName: PCWSTR,
        ObjectType: u32,
        SecurityInfo: u32,
        psidOwner: PSID,
        psidGroup: PSID,
        pDacl: *const c_void,
        pSacl: *const c_void,
    ) -> u32;
    #[cfg(test)]
    fn GetNamedSecurityInfoW(
        pObjectName: PCWSTR,
        ObjectType: u32,
        SecurityInfo: u32,
        ppsidOwner: *mut PSID,
        ppsidGroup: *mut PSID,
        ppDacl: *mut *const c_void,
        ppSacl: *mut *const c_void,
        ppSecurityDescriptor: *mut *mut c_void,
    ) -> u32;
    fn ConvertStringSidToSidW(StringSid: PCWSTR, pSid: *mut PSID) -> c_int;
    // kernel32
    fn GetCurrentProcess() -> HANDLE;
    fn LocalFree(hMem: *mut c_void) -> *mut c_void;
}

fn to_wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// 当前进程用户 SID（克隆为 owned Vec<u8>，布局 = PSID 原始字节）。
pub(crate) fn current_user_sid() -> Result<Vec<u8>, MeshError> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(MeshError::new(ErrorCode::Internal, "OpenProcessToken 失败"));
        }
        let mut needed: u32 = 0;
        GetTokenInformation(token, TOKEN_USER, std::ptr::null_mut(), 0, &mut needed);
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(token, TOKEN_USER, buf.as_mut_ptr() as *mut c_void, needed, &mut needed) == 0 {
            return Err(MeshError::new(ErrorCode::Internal, "GetTokenInformation(TokenUser) 失败"));
        }
        // TOKEN_USER.User.Sid 在偏移 0（结构体首字段为指针）。
        let sid = buf.as_ptr() as *const *const c_void;
        let sid_ptr = *sid as *const u8;
        // SID 布局：Revision(1) SubAuthorityCount(1) IdentifierAuthority(6)
        // SubAuthority×count(4 each)——直接按字节长度克隆。
        let sub_count = *sid_ptr.add(1) as usize;
        let sid_len = 8 + sub_count * 4;
        let owned = std::slice::from_raw_parts(sid_ptr, sid_len).to_vec();
        Ok(owned)
    }
}

fn system_sid() -> Result<Vec<u8>, MeshError> {
    sid_from_string("S-1-5-18")
}

/// 字符串 SID → 原始字节（克隆 owned；布局 = PSID）。
pub(crate) fn sid_from_string(s: &str) -> Result<Vec<u8>, MeshError> {
    unsafe {
        let mut sid: PSID = std::ptr::null_mut();
        let wide = to_wide(s);
        if ConvertStringSidToSidW(wide.as_ptr(), &mut sid) == 0 {
            return Err(MeshError::new(ErrorCode::Internal, format!("ConvertStringSidToSidW({s}) 失败")));
        }
        let sub_count = *(sid as *const u8).add(1) as usize;
        let sid_len = 8 + sub_count * 4;
        let owned = std::slice::from_raw_parts(sid as *const u8, sid_len).to_vec();
        LocalFree(sid);
        Ok(owned)
    }
}

/// 读取文件 DACL 全部 ACE：`(AceType, AccessMask, TrusteeSID)`。
/// NULL DACL（= Everyone 全权，危险）返回空 Vec——由调用方断言拒绝。
/// 用于「非授权账户不可读身份」测试（用户规格五）。
#[cfg(test)]
pub(crate) fn file_dacl_aces(path: &Path) -> Result<Vec<(u8, u32, Vec<u8>)>, MeshError> {
    unsafe {
        let wide = to_wide(path.as_os_str());
        let mut powner: PSID = std::ptr::null_mut();
        let mut pgroup: PSID = std::ptr::null_mut();
        let mut pdacl: *const c_void = std::ptr::null();
        let mut psacl: *const c_void = std::ptr::null();
        let mut psd: *mut c_void = std::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(
            wide.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            &mut powner, &mut pgroup, &mut pdacl, &mut psacl, &mut psd,
        );
        if rc != 0 {
            return Err(MeshError::new(ErrorCode::Internal, format!("GetNamedSecurityInfoW 失败 (WinError {rc})")));
        }
        if pdacl.is_null() {
            LocalFree(psd);
            return Ok(Vec::new());
        }
        // ACL 头：Revision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)。
        let acl = pdacl as *const u8;
        let acl_size = u16::from_le_bytes([*acl.add(2), *acl.add(3)]) as usize;
        let ace_count = u16::from_le_bytes([*acl.add(4), *acl.add(5)]) as usize;
        let mut out = Vec::with_capacity(ace_count);
        let mut off = 8usize;
        for _ in 0..ace_count {
            if off + 8 > acl_size {
                break;
            }
            let ace = acl.add(off);
            let ace_type = *ace;
            let ace_size = u16::from_le_bytes([*ace.add(2), *ace.add(3)]) as usize;
            if ace_size < 8 || off + ace_size > acl_size {
                break;
            }
            let mask = u32::from_le_bytes([*ace.add(4), *ace.add(5), *ace.add(6), *ace.add(7)]);
            // SID 自偏移 8 起（ACCESS_ALLOWED_ACE 头 8 字节）；长度由 SID 头决定。
            let sid_ptr = ace.add(8);
            let sub_count = *sid_ptr.add(1) as usize;
            let sid_len = 8 + sub_count * 4;
            if 8 + sid_len <= ace_size {
                let sid = std::slice::from_raw_parts(sid_ptr, sid_len).to_vec();
                out.push((ace_type, mask, sid));
            }
            off += ace_size;
        }
        // SD 归我们所有（GetNamedSecurityInfoW 分配），ACE 数据已复制，可安全释放。
        LocalFree(psd);
        Ok(out)
    }
}

/// 把文件 DACL 收敛为「当前用户 + SYSTEM 全权、PROTECTED（无继承）」。
/// 建议在文件写入后立即调用（父目录用户级 ACL 之下的纵深防御）。
pub fn restrict_file_acl(path: &Path) -> Result<(), MeshError> {
    let user_sid = current_user_sid()?;
    let sys_sid = system_sid()?;

    let mut acl_buf = vec![0u8; ACL_BUFFER_LEN];
    unsafe {
        if InitializeAcl(acl_buf.as_mut_ptr(), ACL_BUFFER_LEN as u32, ACL_REVISION) == 0 {
            return Err(MeshError::new(ErrorCode::Internal, "InitializeAcl 失败"));
        }
        for sid in [&user_sid, &sys_sid] {
            if AddAccessAllowedAce(
                acl_buf.as_mut_ptr(),
                ACL_REVISION,
                FILE_ALL_ACCESS,
                sid.as_ptr() as PSID,
            ) == 0 {
                return Err(MeshError::new(ErrorCode::Internal, "AddAccessAllowedAce 失败"));
            }
        }
        let wide = to_wide(path.as_os_str());
        let rc = SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl_buf.as_ptr() as *const c_void,
            std::ptr::null(),
        );
        if rc != 0 {
            return Err(MeshError::new(ErrorCode::Internal, format!("SetNamedSecurityInfoW 失败 (WinError {rc})")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn current_user_sid_starts_with_s_1_5() {
        let sid = current_user_sid().expect("user sid");
        assert_eq!(sid[0], 1, "SID Revision");
        assert!(sid.len() >= 12, "SID 最小长度");
        // IdentifierAuthority = 5（NT Authority）→ 字节 2..8 末字节为 5。
        assert_eq!(sid[7], 5, "NT Authority");
    }

    #[test]
    fn system_sid_is_s_1_5_18() {
        let sid = system_sid().expect("system sid");
        assert_eq!(sid[1], 1, "SubAuthorityCount = 1");
        assert_eq!(sid[7], 5);
        // SubAuthority[0] 小端 = 18。
        let sub = u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]);
        assert_eq!(sub, 18);
    }

    #[test]
    fn restrict_acl_on_temp_file() {
        let dir = std::env::temp_dir().join("meshlink-secure-store-test");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("acl-probe.bin");
        let mut f = std::fs::File::create(&file).expect("create");
        f.write_all(b"probe").expect("write");
        drop(f);
        restrict_file_acl(&file).expect("restrict acl");

        // 写回验证：当前用户仍可读写（FILE_ALL_ACCESS 授予自己）。
        std::fs::write(&file, b"probe2").expect("current user retains access");
        assert_eq!(std::fs::read(&file).unwrap(), b"probe2".to_vec());

        // 回读验证：DACL 确实收敛为 2 个 ACE（用户 + SYSTEM），PROTECTED 切断继承。
        unsafe {
            let wide = to_wide(file.as_os_str());
            let mut powner: PSID = std::ptr::null_mut();
            let mut pgroup: PSID = std::ptr::null_mut();
            let mut pdacl: *const c_void = std::ptr::null();
            let mut psacl: *const c_void = std::ptr::null();
            let mut psd: *mut c_void = std::ptr::null_mut();
            let rc = GetNamedSecurityInfoW(
                wide.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                &mut powner, &mut pgroup, &mut pdacl, &mut psacl, &mut psd,
            );
            assert_eq!(rc, 0, "GetNamedSecurityInfoW 回读失败 (WinError {rc})");
            assert!(!pdacl.is_null(), "应存在 DACL");
            // ACL 布局：Revision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)。
            let acl = pdacl as *const u8;
            let ace_count = u16::from_le_bytes([*acl.add(4), *acl.add(5)]);
            assert_eq!(ace_count, 2, "DACL 应恰好 2 个 ACE（当前用户 + SYSTEM）");
            if !psd.is_null() { LocalFree(psd); }
        }
        let _ = std::fs::remove_file(&file);
    }
}
