fn write_pkg_config() {
    use std::io::prelude::*;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir = target_dir_path();

    let out_path = target_dir.as_path().join("quiceh.pc");
    let mut out_file = std::fs::File::create(out_path).unwrap();

    let include_dir = format!("{manifest_dir}/include");

    let version = std::env::var("CARGO_PKG_VERSION").unwrap();

    let output = format!(
        "# quiceh

includedir={include_dir}
libdir={}

Name: quiceh
Description: quiceh library
URL: https://github.com/frochet/quiceh
Version: {version}
Libs: -Wl,-rpath,${{libdir}} -L${{libdir}} -lquiceh
Cflags: -I${{includedir}}
",
        target_dir.to_str().unwrap(),
    );

    out_file.write_all(output.as_bytes()).unwrap();
}

fn target_dir_path() -> std::path::PathBuf {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_dir = std::path::Path::new(&out_dir);

    for p in out_dir.ancestors() {
        if p.ends_with("build") {
            return p.parent().unwrap().to_path_buf();
        }
    }

    unreachable!();
}

fn main() {
    if cfg!(feature = "aws-lc") {
        println!("cargo:rustc-env=AWS_LC_SYS_NO_PREFIX=1");
    }
    if cfg!(any(feature = "aws-lc", feature = "boringssl-boring-crate")) {
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
    }

    // MacOS: Allow cdylib to link with undefined symbols
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    if cfg!(feature = "pkg-config-meta") {
        write_pkg_config();
    }
}
