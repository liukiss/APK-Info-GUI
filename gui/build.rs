//! 构建脚本：仅针对 Windows 目标，用 windres 把 res/icon.ico 嵌入 exe 文件图标。

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let rc = std::path::Path::new(&manifest_dir).join("res/icon.rc");
    let ico = std::path::Path::new(&manifest_dir).join("res/icon.ico");
    if !rc.exists() || !ico.exists() {
        panic!("图标资源缺失: res/icon.rc / res/icon.ico");
    }
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let obj = std::path::Path::new(&out_dir).join("icon.o");
    let status = std::process::Command::new("x86_64-w64-mingw32-windres")
        .arg(&rc)
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("无法运行 x86_64-w64-mingw32-windres，请安装 gcc-mingw-w64-x86-64-win32");
    assert!(status.success(), "windres 编译图标资源失败");
    println!("cargo:rustc-link-arg-bins={}", obj.display());
    println!("cargo:rerun-if-changed=res/icon.rc");
    println!("cargo:rerun-if-changed=res/icon.ico");
}
