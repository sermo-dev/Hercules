//! Builds Bitcoin Core's libbitcoinkernel as a static library (ticket 047).
//!
//! 1. Source: a pinned Bitcoin Core release (`CORE_TAG` / `CORE_COMMIT`).
//!    Shallow-fetched once by commit hash into `kernel-sys/bitcoin-core-<tag>/`
//!    (gitignored), keeping `.git` so every build re-verifies the commit, its
//!    tree and a clean working tree; a stale or partial copy is refetched.
//!    `$HERCULES_BITCOIN_CORE_SRC` overrides it (offline builds, or a
//!    checkout you are bumping); an override that doesn't verify builds with
//!    a loud warning and an "unverified" library label.
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
/// kernel C API is unversioned and breaks between releases. Update all
/// three (`git rev-parse <commit>^{tree}` gives the tree), rebuild, and
/// rerun the differential tests (see ticket 047).
const CORE_TAG: &str = "v32.0";
const CORE_COMMIT: &str = "465dde277447e2f11e01bea09d2a094d7fb6ef45";
/// Tree hash of `CORE_COMMIT`, checked against the checkout on every build.
const CORE_TREE: &str = "cbf24820b3e51bf8a6a00b0a54d394d16dcf3b7d";
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
        "HERCULES_BITCOIN_CORE_REPO",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "MACOSX_DEPLOYMENT_TARGET",
        "BOOST_ROOT",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let (src, label) = core_source();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build_dir = out.join("build");
    let install_dir = out.join("install");

    // cmake refuses a build dir configured for another source tree (e.g.
    // after switching to or from HERCULES_BITCOIN_CORE_SRC): start fresh.
    let cache = std::fs::read_to_string(build_dir.join("CMakeCache.txt")).unwrap_or_default();
    let configured_src = cache
        .lines()
        .find_map(|l| l.strip_prefix("CMAKE_HOME_DIRECTORY:INTERNAL="))
        .map(PathBuf::from);
    if configured_src.is_some_and(|s| s != src) {
        let _ = std::fs::remove_dir_all(&build_dir);
        let _ = std::fs::remove_dir_all(&install_dir);
    }

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
    println!("cargo:rustc-env=HERCULES_BITCOIN_CORE_LABEL={label}");
}

/// The Core source tree to build, and the label the library reports: the
/// pinned `CORE_TAG` only when the tree is verified to be exactly
/// `CORE_COMMIT`, otherwise an "unverified" label.
fn core_source() -> (PathBuf, String) {
    if let Ok(dir) = env::var("HERCULES_BITCOIN_CORE_SRC") {
        return override_source(PathBuf::from(dir));
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dir = manifest.join(format!("bitcoin-core-{CORE_TAG}"));
    let marker = format!("{CORE_TAG} {CORE_COMMIT}\n");
    // Re-verify if someone touches the fetched tree's checkout state.
    println!("cargo:rerun-if-changed={}", dir.join(".fetched").display());
    println!("cargo:rerun-if-changed={}", dir.join(".git/HEAD").display());
    println!("cargo:rerun-if-changed={}", dir.join(".git/index").display());

    if dir.exists() {
        let marker_ok = std::fs::read_to_string(dir.join(".fetched")).ok().as_deref() == Some(&marker);
        match verify_checkout(&dir) {
            Ok(()) if marker_ok => return (dir, CORE_TAG.into()),
            Ok(()) => println!("cargo:warning={} has a stale or missing .fetched marker; refetching", dir.display()),
            Err(e) => println!("cargo:warning={} is not the pinned Bitcoin Core {CORE_TAG}: {e}; refetching", dir.display()),
        }
        // Only ever delete the directory this script owns (an interrupted
        // or stale fetch), never an override.
        std::fs::remove_dir_all(&dir).unwrap_or_else(|e| panic!("removing stale {}: {e}", dir.display()));
    }

    // Fetch into a private temp dir and rename into place, so concurrent
    // build scripts (host + iOS, debug + release) never see a half tree.
    // `.git` is kept so the tree stays verifiable on later builds.
    let tmp = manifest.join(format!(".bitcoin-core-fetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let git = |args: &[&str], what: &str| run(Command::new("git").arg("-C").arg(&tmp).args(args), what);
    git(&["init", "-q"], "git init");
    // `$HERCULES_BITCOIN_CORE_REPO` may point at a mirror (e.g. a local
    // clone, for offline machines); safe because the result is verified
    // against CORE_COMMIT and CORE_TREE either way.
    let repo = env::var("HERCULES_BITCOIN_CORE_REPO").unwrap_or_else(|_| CORE_REPO.into());
    git(&["fetch", "-q", "--depth", "1", &repo, CORE_COMMIT], "git fetch Bitcoin Core");
    git(&["checkout", "-q", "FETCH_HEAD"], "git checkout");
    std::fs::write(tmp.join(".fetched"), &marker).unwrap();
    if let Err(e) = verify_checkout(&tmp) {
        panic!("fetched Bitcoin Core does not match the pin: {e}");
    }
    if std::fs::rename(&tmp, &dir).is_err() {
        // Another build script won the race; use (and verify) its copy.
        let _ = std::fs::remove_dir_all(&tmp);
    }
    if let Err(e) = verify_checkout(&dir) {
        panic!("Bitcoin Core source at {} does not match the pin: {e}", dir.display());
    }
    (dir, CORE_TAG.into())
}

/// `$HERCULES_BITCOIN_CORE_SRC`: used as given (offline builds, or a checkout
/// you are bumping), but labelled `CORE_TAG` only if it verifies.
fn override_source(dir: PathBuf) -> (PathBuf, String) {
    assert!(
        dir.join("src/kernel/bitcoinkernel.h").exists(),
        "HERCULES_BITCOIN_CORE_SRC={} is not a Bitcoin Core source tree",
        dir.display()
    );
    // Rebuild when the tree or its checked-out commit changes.
    println!("cargo:rerun-if-changed={}", dir.display());
    println!("cargo:rerun-if-changed={}", dir.join(".git/HEAD").display());
    match verify_checkout(&dir) {
        Ok(()) => (dir, CORE_TAG.into()),
        Err(e) => {
            for line in [
                "**************************************************************".to_string(),
                format!("UNVERIFIED Bitcoin Core source: HERCULES_BITCOIN_CORE_SRC={}", dir.display()),
                format!("is not a clean checkout of the pinned {CORE_TAG} ({CORE_COMMIT}): {e}"),
                "libbitcoinkernel is labelled \"unverified\"; do not ship this build.".to_string(),
                "**************************************************************".to_string(),
            ] {
                println!("cargo:warning={line}");
            }
            (dir, "(unverified source)".into())
        }
    }
}

/// Ok if `dir` is its own git checkout of `CORE_COMMIT` (tree `CORE_TREE`)
/// with no modified, deleted or untracked files (the `.fetched` marker
/// aside).
fn verify_checkout(dir: &Path) -> Result<(), String> {
    if !dir.join(".git").exists() {
        return Err("not a git checkout (no .git), so its contents can't be verified".into());
    }
    // GIT_DIR pins git to this checkout, so a non-repo dir inside another
    // repo (e.g. Hercules itself) can't be mistaken for it.
    let git = |args: &[&str]| -> Result<String, String> {
        let out = Command::new("git")
            .env("GIT_DIR", dir.join(".git"))
            .env("GIT_WORK_TREE", dir)
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .map_err(|e| format!("git: {e}"))?;
        if !out.status.success() {
            return Err(format!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let head = git(&["rev-parse", "HEAD"])?;
    if head != CORE_COMMIT {
        return Err(format!("HEAD is {head}"));
    }
    let tree = git(&["rev-parse", "HEAD^{tree}"])?;
    if tree != CORE_TREE {
        return Err(format!("HEAD's tree is {tree}, expected {CORE_TREE}"));
    }
    let status = git(&["status", "--porcelain", "--untracked-files=all", "--", ".", ":!.fetched"])?;
    if !status.is_empty() {
        let first: Vec<&str> = status.lines().take(5).collect();
        return Err(format!("working tree differs from the commit: {}", first.join("; ")));
    }
    Ok(())
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
