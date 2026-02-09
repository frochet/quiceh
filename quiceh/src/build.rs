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
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("aliases.rs");
    let mut f = std::fs::File::create(&dest_path).unwrap();
    use std::io::Write;

    if cfg!(feature = "aws-lc-rs") && !cfg!(feature = "boringssl-boring-crate") {
        let crypto_root = std::env::var("DEP_AWS_LC_RS_1_15_4_SYS_ROOT").unwrap();
        let crypto_lib_name =
            std::env::var("DEP_AWS_LC_RS_1_15_4_SYS_LIBCRYPTO").unwrap();
        let ssl_lib_name =
            std::env::var("DEP_AWS_LC_RS_1_15_4_SYS_LIBSSL").unwrap();

        println!(
            "cargo:rustc-link-search=native={}/build/artifacts",
            crypto_root
        );
        // ssl depends on crypto
        println!("cargo:rustc-link-lib=static={}", ssl_lib_name);
        println!("cargo:rustc-link-lib=static={}", crypto_lib_name);

        writeln!(f, "std::arch::global_asm!(").unwrap();

        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let jump_instr = match arch.as_str() {
            "x86_64" => "jmp",
            "aarch64" => "b",
            _ => "jmp", // fallback
        };

        let mut processed_syms = std::collections::HashSet::new();
        let prefix = "aws_lc_0_37_0_";
        for lib in &[&crypto_lib_name, &ssl_lib_name] {
            let lib_path =
                format!("{}/build/artifacts/lib{}.a", crypto_root, lib);
            let output = std::process::Command::new("nm")
                .arg("-gP")
                .arg(&lib_path)
                .output()
                .expect("failed to execute nm");

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && parts[0].starts_with(prefix)
                    && parts[1] != "U"
                {
                    let sym = parts[0];
                    let sym_type = parts[1];
                    let standard_sym = &sym[prefix.len()..];

                    if processed_syms.contains(standard_sym) {
                        continue;
                    }

                    if standard_sym.starts_with("EVP_")
                        || standard_sym.starts_with("SSL_")
                        || standard_sym.starts_with("HKDF_")
                        || standard_sym.starts_with("AES_")
                        || standard_sym.starts_with("CRYPTO_")
                        || standard_sym.starts_with("ERR_")
                        || standard_sym.starts_with("OPENSSL_")
                        || standard_sym.starts_with("X509_")
                        || standard_sym.starts_with("sk_")
                        || standard_sym.starts_with("ASN1_")
                        || standard_sym.starts_with("BIO_")
                        || standard_sym.starts_with("DH_")
                        || standard_sym.starts_with("DSA_")
                        || standard_sym.starts_with("RSASSA_")
                        || standard_sym.starts_with("RSA_")
                        || standard_sym.starts_with("SHA")
                        || standard_sym.starts_with("EC_")
                        || standard_sym == "TLS_method"
                        || standard_sym == "RAND_bytes"
                    {
                        writeln!(f, "    \".globl {}\",", standard_sym).unwrap();
                        if sym_type == "T" || sym_type == "W" {
                            writeln!(
                                f,
                                "    \"{}: {} {}\",",
                                standard_sym, jump_instr, sym
                            )
                            .unwrap();
                        } else {
                            writeln!(
                                f,
                                "    \".set {}, {}\",",
                                standard_sym, sym
                            )
                            .unwrap();
                        }

                        processed_syms.insert(standard_sym.to_string());

                        if standard_sym.starts_with("OPENSSL_sk_") {
                            let short_sk_sym = &standard_sym["OPENSSL_".len()..];
                            if !processed_syms.contains(short_sk_sym) {
                                writeln!(f, "    \".globl {}\",", short_sk_sym)
                                    .unwrap();
                                if sym_type == "T" || sym_type == "W" {
                                    writeln!(
                                        f,
                                        "    \"{}: {} {}\",",
                                        short_sk_sym, jump_instr, sym
                                    )
                                    .unwrap();
                                } else {
                                    writeln!(
                                        f,
                                        "    \".set {}, {}\",",
                                        short_sk_sym, sym
                                    )
                                    .unwrap();
                                }
                                processed_syms.insert(short_sk_sym.to_string());
                            }
                        }
                    }
                }
            }
        }
        writeln!(f, ");").unwrap();
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
