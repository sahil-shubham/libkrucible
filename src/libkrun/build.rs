fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=Hypervisor");
    }

    emit_checkpoint_cfg();

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
}

/// `cfg(checkpoint)`: the target can save a running VM to disk and restore it.
/// Linux KVM on x86_64 and aarch64 capture every piece of VM state; macOS HVF
/// joins once its vCPU and GIC state is captured too. Confidential (TEE)
/// guests can't be checkpointed by design.
fn emit_checkpoint_cfg() {
    println!("cargo:rustc-check-cfg=cfg(checkpoint)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let tee = std::env::var_os("CARGO_FEATURE_TEE").is_some();
    if os == "linux" && matches!(arch.as_str(), "x86_64" | "aarch64") && !tee {
        println!("cargo:rustc-cfg=checkpoint");
    }
}
