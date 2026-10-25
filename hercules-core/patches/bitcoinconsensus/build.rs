extern crate cc;

use std::env;

fn main() {
    // Check whether we can use 64-bit compilation
    let use_64bit_compilation = if env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap() == "64" {
        let check = cc::Build::new()
            .file("depend/check_uint128_t.c")
            .cargo_metadata(false)
            .try_compile("check_uint128_t")
            .is_ok();
        if !check {
            println!("cargo:warning=Compiling in 32-bit mode on a 64-bit architecture due to lack of uint128_t support.");
        }
        check
    } else {
        false
    };
    let target = env::var("TARGET").expect("TARGET was not set");
    // Hercules (ticket 047): on Apple targets the two archives are sealed
    // into one object exporting only `bitcoinconsensus_*` (see `seal` below),
    // so cc must not emit its own link directives for them.
    let seal = target.contains("apple");
    let is_big_endian = env::var("CARGO_CFG_TARGET_ENDIAN").expect("No endian is set") == "big";
    let mut base_config = cc::Build::new();
    base_config
        .include("depend/bitcoin/src/secp256k1/include")
        .define("__STDC_FORMAT_MACROS", None)
        .flag_if_supported("-Wno-implicit-fallthrough");

    if target.contains("windows") {
        base_config.define("WIN32", "1");
    }

    base_config.cargo_metadata(!seal);
    let mut secp_config = base_config.clone();
    let mut consensus_config = base_config;

    // **Secp256k1**
    if !cfg!(feature = "external-secp") {
        secp_config
            .include("depend/bitcoin/src/secp256k1/include")
            .include("depend/bitcoin/src/secp256k1/src")
            .flag_if_supported("-Wno-unused-function") // some ecmult stuff is defined but not used upstream
            .define("ECMULT_WINDOW_SIZE", "15")
            .define("ECMULT_GEN_PREC_BITS", "4")
            .define("ENABLE_MODULE_SCHNORRSIG", "1")
            .define("ENABLE_MODULE_EXTRAKEYS", "1")
            // Technically libconsensus doesn't require the recovery feautre, but `pubkey.cpp` does.
            .define("ENABLE_MODULE_RECOVERY", "1")
            // Bitcoin Core 26.0's pubkey.cpp uses EllSwiftPubKey which needs ellswift module.
            .define("ENABLE_MODULE_ELLSWIFT", "1")
            .file("depend/bitcoin/src/secp256k1/src/precomputed_ecmult_gen.c")
            .file("depend/bitcoin/src/secp256k1/src/precomputed_ecmult.c")
            .file("depend/bitcoin/src/secp256k1/src/secp256k1.c");

        if is_big_endian {
            secp_config.define("WORDS_BIGENDIAN", "1");
        }

        if use_64bit_compilation {
            secp_config
                .define("USE_FIELD_5X52", "1")
                .define("USE_SCALAR_4X64", "1")
                .define("HAVE___INT128", "1");
        } else {
            secp_config.define("USE_FIELD_10X26", "1").define("USE_SCALAR_8X32", "1");
        }

        secp_config.compile("libsecp256k1.a");
    }

    let tool = consensus_config.get_compiler();
    if tool.is_like_msvc() {
        consensus_config.flag("/std:c++17").flag("/wd4100");
    } else if tool.is_like_clang() || tool.is_like_gnu() {
        consensus_config.flag("-std=c++17").flag("-Wno-unused-parameter");
    }

    consensus_config
        .cpp(true)
        .include("depend/bitcoin/src")
        .include("depend/bitcoin/src/secp256k1/include")
        .file("depend/bitcoin/src/util/strencodings.cpp")
        .file("depend/bitcoin/src/uint256.cpp")
        .file("depend/bitcoin/src/pubkey.cpp")
        .file("depend/bitcoin/src/hash.cpp")
        .file("depend/bitcoin/src/primitives/transaction.cpp")
        .file("depend/bitcoin/src/crypto/ripemd160.cpp")
        .file("depend/bitcoin/src/crypto/sha1.cpp")
        .file("depend/bitcoin/src/crypto/sha256.cpp")
        .file("depend/bitcoin/src/crypto/sha512.cpp")
        .file("depend/bitcoin/src/crypto/hmac_sha512.cpp")
        .file("depend/bitcoin/src/script/bitcoinconsensus.cpp")
        .file("depend/bitcoin/src/script/interpreter.cpp")
        .file("depend/bitcoin/src/script/script.cpp")
        .file("depend/bitcoin/src/script/script_error.cpp")
        .compile("libbitcoinconsensus.a");

    if seal {
        seal_archives();
    }
}

/// Hercules (ticket 047): prelink libbitcoinconsensus.a + libsecp256k1.a
/// into a single relocatable object in which every symbol except the C API
/// (`bitcoinconsensus_*`) is made local, and link that instead.
///
/// libbitcoinkernel embeds the same Core sources (SHA256, secp256k1,
/// SignatureHashSchnorr, ...) at a newer version under identical global
/// names, ~300 of them. Linked side by side, the linker silently binds both
/// libraries to one copy (an ODR violation). Sealed, this library only ever
/// calls its own v26 code, so hercules-core can link it next to the kernel
/// (`script-consensus-legacy` + `script-kernel`, the differential mode).
fn seal_archives() {
    let out = std::path::PathBuf::from(env::var("OUT_DIR").unwrap());
    let exports = out.join("bitcoinconsensus.exports");
    std::fs::write(&exports, "_bitcoinconsensus_*\n").unwrap();
    let sealed_obj = out.join("bitcoinconsensus_sealed.o");
    let sealed_lib = out.join("libbitcoinconsensus_sealed.a");

    // cc's compiler carries the right --target / -isysroot / min OS version,
    // so the prelink matches the objects it just built.
    let compiler = cc::Build::new().get_compiler();
    let mut cmd = compiler.to_command();
    let mut arg = std::ffi::OsString::from("-Wl,-force_load,");
    arg.push(out.join("libbitcoinconsensus.a"));
    let mut secp = std::ffi::OsString::from("-Wl,-force_load,");
    secp.push(out.join("libsecp256k1.a"));
    let mut exp = std::ffi::OsString::from("-Wl,-exported_symbols_list,");
    exp.push(&exports);
    cmd.args(["-r", "-nostdlib"]).arg(exp).arg(arg);
    if !cfg!(feature = "external-secp") {
        cmd.arg(secp);
    }
    cmd.arg("-o").arg(&sealed_obj);
    let status = cmd.status().expect("spawn prelink");
    assert!(status.success(), "prelinking libbitcoinconsensus failed: {}", status);

    let _ = std::fs::remove_file(&sealed_lib);
    let status = std::process::Command::new("ar")
        .arg("crs")
        .arg(&sealed_lib)
        .arg(&sealed_obj)
        .status()
        .expect("spawn ar");
    assert!(status.success(), "ar failed: {}", status);

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=bitcoinconsensus_sealed");
    println!("cargo:rustc-link-lib=c++");
}
