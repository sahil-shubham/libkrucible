fn main() {
    #[cfg(target_os = "linux")]
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-soname,libkrun.so.{}",
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap()
    );
    #[cfg(target_os = "macos")]
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-install_name,libkrun.{}.dylib,-compatibility_version,{}.0.0,-current_version,{}.{}.0",
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap(),
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap(),
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap(),
        std::env::var("CARGO_PKG_VERSION_MINOR").unwrap()
    );
    emit_cold_tier_cfg();
}

/// Emit the `cold_tier` cfg for targets that implement cold snapshot/restore.
/// Mirror of vmm/build.rs (the C API gates must match the vmm gates) — keep the
/// target list in sync.
fn emit_cold_tier_cfg() {
    println!("cargo:rustc-check-cfg=cfg(cold_tier)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let cold = matches!(
        (os.as_str(), arch.as_str()),
        ("macos", "aarch64") | ("linux", "x86_64") | ("linux", "aarch64")
    );
    if cold {
        println!("cargo:rustc-cfg=cold_tier");
    }
}
