//! Builds Bitcoin Core's libbitcoinkernel as a static library (ticket 047).
//!
//! 1. Source: a pinned Bitcoin Core release (`CORE_TAG` / `CORE_COMMIT`).
//!    Taken from `$HERCULES_BITCOIN_CORE_SRC` if set (offline builds, or a
//!    checkout you are bumping), otherwise shallow-fetched once by commit
//!    hash into `kernel-sys/bitcoin-core-<tag>/` (gitignored) and verified.
//! 2. cmake configure + build + install into `OUT_DIR`, with the iOS
//!    cross-compile flags the upstream `libbitcoinkernel-sys` build.rs lacks
//!    (without them cmake silently produces a macOS archive for iOS targets;
//!    see the ticket's spike results).
//! 3. A tiny C shim (`src/flags.c`) compiled against the *installed* header,
//!    so tests can check our flag constants against the release's own
//!    `btck_ScriptVerificationFlags_*` values instead of a transcription.
//!
//! Needs cmake and Boost headers on the build machine (`brew install cmake
//! boost`). One configure + build is ~1.5 min per target on an M2; cmake
//! rebuilds incrementally after that.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Pinned Bitcoin Core release. Bumping it is a deliberate project: the
/// kernel C API is unversioned and breaks between releases. Update both
/// lines, rebuild, and rerun the differential tests (see ticket 047).
const CORE_TAG: &str = "v32.0";
const CORE_COMMIT: &str = "465dde277447e2f11e01bea09d2a094d7fb6ef45";
const CORE_REPO: &str = "https://github.com/bitcoin/bitcoin.git";

const BUILD_CONFIG: &str = "Release";

/// Everything but the kernel library switched off.
const BASE_CMAKE_FLAGS: &[&str] = &[
    "-DBUILD_KERNEL_LIB=ON",
    "-DBUILD_SHARED_LIBS=OFF",
    "-DBUILD_TESTS=OFF",
    "-DBUILD_BENCH=OFF",
    "-DBUILD_KERNEL_TEST=OFF",
    "-DBUILD_TX=OFF",
    "-DBUILD_WALLET_TOOL=OFF",
    "-DBUILD_UTIL=OFF",
    "-DBUILD_BITCOIN_BIN=OFF",
    "-DBUILD_DAEMON=OFF",
    "-DBUILD_UTIL_CHAINSTATE=OFF",
    "-DBUILD_CLI=OFF",
    "-DBUILD_FUZZ_BINARY=OFF",
    "-DENABLE_WALLET=OFF",
    "-DENABLE_EXTERNAL_SIGNER=OFF",
    "-DENABLE_IPC=OFF",
    "-DWITH_ZMQ=OFF",
    "-DCMAKE_INSTALL_LIBDIR=lib",
    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/flags.c");
    for var in [
        "HERCULES_BITCOIN_CORE_SRC",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "MACOSX_DEPLOYMENT_TARGET",
        "BOOST_ROOT",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let src = core_source();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build_dir = out.join("build");
    let install_dir = out.join("install");

    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(&src)
        .arg("-B")
        .arg(&build_dir)
        .arg(format!("-DCMAKE_BUILD_TYPE={BUILD_CONFIG}"))
        .arg(format!("-DCMAKE_INSTALL_PREFIX={}", install_dir.display()))
        .args(BASE_CMAKE_FLAGS)
        .args(target_cmake_args());
    run(&mut configure, "cmake configure");

    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "4".into());
    run(
        Command::new("cmake")
            .arg("--build")
            .arg(&build_dir)
            .arg("--config")
            .arg(BUILD_CONFIG)
            .arg("--target")
            .arg("bitcoinkernel")
            .arg(format!("--parallel={jobs}")),
        "cmake build",
    );
    run(
        Command::new("cmake")
            .arg("--install")
            .arg(&build_dir)
            .arg("--config")
            .arg(BUILD_CONFIG)
            .arg("--component")
            .arg("libbitcoinkernel"),
        "cmake install",
    );

    let lib_dir = install_dir.join("lib");
    let include_dir = install_dir.join("include");
    assert!(
        lib_dir.join("libbitcoinkernel.a").exists(),
        "cmake install did not produce {}",
        lib_dir.join("libbitcoinkernel.a").display()
    );

    // Flag/status constants straight from the installed header. Archived
    // with plain `ar` (cc's archiver probes `ar -D`, which Apple's ar
    // rejects with a page of usage warnings).
    let objs = cc::Build::new()
        .file("src/flags.c")
        .include(&include_dir)
        .define("BITCOINKERNEL_STATIC", None)
        .cargo_metadata(false)
        .compile_intermediates();
    let flags_lib = out.join("libhercules_kernel_flags.a");
    let _ = std::fs::remove_file(&flags_lib);
    run(Command::new("ar").arg("crs").arg(&flags_lib).args(&objs), "ar");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=hercules_kernel_flags");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=bitcoinkernel");
    // libbitcoinkernel is C++ (Apple targets: libc++).
    println!("cargo:rustc-link-lib=c++");
    println!("cargo:include={}", include_dir.display());
    println!("cargo:rustc-env=HERCULES_BITCOIN_CORE_TAG={CORE_TAG}");
}

/// Path of a Bitcoin Core source tree at `CORE_COMMIT`.
fn core_source() -> PathBuf {
    if let Ok(dir) = env::var("HERCULES_BITCOIN_CORE_SRC") {
        let dir = PathBuf::from(dir);
        assert!(
            dir.join("src/kernel/bitcoinkernel.h").exists(),
            "HERCULES_BITCOIN_CORE_SRC={} is not a Bitcoin Core source tree",
            dir.display()
        );
        return dir;
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dir = manifest.join(format!("bitcoin-core-{CORE_TAG}"));
    if dir.join(".fetched").exists() {
        return dir;
    }

    // Fetch into a private temp dir and rename into place, so concurrent
    // build scripts (host + iOS, debug + release) never see a half tree.
    let tmp = manifest.join(format!(".bitcoin-core-fetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let git = |args: &[&str], what: &str| run(Command::new("git").arg("-C").arg(&tmp).args(args), what);
    git(&["init", "-q"], "git init");
    git(&["fetch", "-q", "--depth", "1", CORE_REPO, CORE_COMMIT], "git fetch Bitcoin Core");
    git(&["checkout", "-q", "FETCH_HEAD"], "git checkout");
    let head = Command::new("git")
        .arg("-C")
        .arg(&tmp)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse");
    let head = String::from_utf8_lossy(&head.stdout).trim().to_string();
    assert_eq!(head, CORE_COMMIT, "fetched Bitcoin Core commit does not match the pin");
    // Only the source tree is needed; drop the object store.
    let _ = std::fs::remove_dir_all(tmp.join(".git"));
    std::fs::write(tmp.join(".fetched"), format!("{CORE_TAG} {CORE_COMMIT}\n")).unwrap();

    if std::fs::rename(&tmp, &dir).is_err() {
        // Another build script won the race; use its copy.
        let _ = std::fs::remove_dir_all(&tmp);
    }
    assert!(dir.join(".fetched").exists(), "Bitcoin Core source missing at {}", dir.display());
    dir
}

/// Per-target cmake flags. The host build needs none; iOS needs the SDK,
/// arch and deployment target spelled out.
fn target_cmake_args() -> Vec<String> {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target = env::var("TARGET").unwrap();
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        a => panic!("unsupported Apple arch {a}"),
    };
    match os.as_str() {
        "macos" => {
            let mut args = vec![format!("-DCMAKE_OSX_ARCHITECTURES={arch}")];
            if let Ok(v) = env::var("MACOSX_DEPLOYMENT_TARGET") {
                args.push(format!("-DCMAKE_OSX_DEPLOYMENT_TARGET={v}"));
            }
            args
        }
        "ios" => {
            let sim = target.ends_with("-sim") || target.starts_with("x86_64-");
            // Matches the app's deployment target (HerculesApp/project.yml).
            let deploy = env::var("IPHONEOS_DEPLOYMENT_TARGET").unwrap_or_else(|_| "17.0".into());
            let mut args = vec![
                "-DCMAKE_SYSTEM_NAME=iOS".to_string(),
                format!(
                    "-DCMAKE_OSX_SYSROOT={}",
                    if sim { "iphonesimulator" } else { "iphoneos" }
                ),
                format!("-DCMAKE_OSX_ARCHITECTURES={arch}"),
                format!("-DCMAKE_OSX_DEPLOYMENT_TARGET={deploy}"),
                // Boost is header-only for Core; let cmake find the host copy
                // even though the find root is the iOS SDK.
                "-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH".into(),
                "-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=BOTH".into(),
            ];
            if let Some(boost) = boost_root() {
                args.push(format!("-DBoost_ROOT={}", boost.display()));
                args.push(format!("-DCMAKE_PREFIX_PATH={}", boost.display()));
            }
            args
        }
        other => panic!("hercules-kernel-sys: unsupported target OS {other} (macOS and iOS only)"),
    }
}

/// `$BOOST_ROOT`, else Homebrew's boost if installed.
fn boost_root() -> Option<PathBuf> {
    if let Ok(p) = env::var("BOOST_ROOT") {
        return Some(PathBuf::from(p));
    }
    let out = Command::new("brew").args(["--prefix", "boost"]).output().ok()?;
    let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    (out.status.success() && Path::new(&p).join("include/boost").exists()).then_some(p)
}

fn run(cmd: &mut Command, what: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {what}: {e} (is it installed?)"));
    assert!(status.success(), "{what} failed with {status}");
}
