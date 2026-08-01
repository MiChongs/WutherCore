#[cfg(feature = "with_ebpf")]
use std::path::PathBuf;

#[cfg(feature = "with_ebpf")]
fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WITH_EBPF");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if !matches!(target_os.as_str(), "linux" | "android") {
        anyhow::bail!("with_ebpf only supports Linux and Android targets");
    }
    let ebpf_features: &[&str] = if target_os == "android" {
        &["android-compat"]
    } else {
        &[]
    };

    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let program_dir = manifest_dir.join("ebpf");
    std::env::set_current_dir(&program_dir)?;
    let root_dir = program_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("eBPF program path is not UTF-8"))?;
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "core-inbound-ebpf",
            root_dir,
            features: ebpf_features,
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
}

#[cfg(not(feature = "with_ebpf"))]
fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WITH_EBPF");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
}
