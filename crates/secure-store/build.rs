fn main() {
    // DPAPI（crypt32.dll）与安全描述符 API（advapi32.dll）。
    println!("cargo:rustc-link-lib=crypt32");
    println!("cargo:rustc-link-lib=advapi32");
}
