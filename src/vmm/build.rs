fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=Hypervisor");
    }
    emit_cold_tier_cfg();
}

/// Emit the `cold_tier` cfg for targets that implement cold snapshot/restore
/// (checkpoint to disk + restore). This centralizes what was ~20 duplicated
/// `cfg(any(all(macos,aarch64), all(linux,x86_64)))` gates, so widening cold
/// support to a new target is a one-line change here. Keep the target list in
/// sync with libkrun/build.rs.
fn emit_cold_tier_cfg() {
    println!("cargo:rustc-check-cfg=cfg(cold_tier)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let cold = matches!(
        (os.as_str(), arch.as_str()),
        ("macos", "aarch64") | ("linux", "x86_64")
    );
    if cold {
        println!("cargo:rustc-cfg=cold_tier");
    }
}
