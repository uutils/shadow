# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- `chfn` and `chsh` now authenticate the caller before applying a change.
  Both are installed setuid-root and restricted non-root callers to their own
  account, but never verified who was asking — anyone with access to an
  unlocked session could change that user's login shell or GECOS field.
  Distributions already ship `/etc/pam.d/chfn` and `/etc/pam.d/chsh` for this
  (#226)

### Changed

- Without the `pam` feature, `chfn` and `chsh` refuse non-root invocations
  rather than applying an unauthenticated change. Every install path enables
  the feature; a static musl build would not — see
  [docs/PLATFORM-SUPPORT.md](docs/PLATFORM-SUPPORT.md)
- `PrivDrop`, the guard that lowers privileges for a PAM conversation, moved
  from `passwd` into `shadow-core` so every setuid tool uses one implementation
- CI lints and tests the `pam` code path, which the release binaries use but
  no job previously exercised

## [0.2.2] - 2026-09-03

First release to ship prebuilt binaries.

### Added

- Release binaries. Tagging a version now builds and uploads
  `uu_shadow-x86_64-unknown-linux-gnu.tar.gz` (the `shadow-rs` multicall
  binary) with a `.sha256` checksum, via `dist` (#207)
- README section on deploying a release archive: symlinks and the setuid
  bit, neither of which extracting the tarball sets up
- CI rejects AI tooling artifacts in pull requests

### Fixed

- `passwd` could not change a password. `pam` is not a default cargo
  feature, so the release archive, `make install` and
  `make install-multicall` all compiled the interactive change path out;
  only the end-to-end image enabled it. Account status and locking were
  unaffected, which is why it went unnoticed (#220)

### Changed

- Dropped the deprecated `authors` field from the package manifests (#213)
- Renovate no longer edits `.github/workflows/release.yml`, which `dist`
  generates and validates (#227)

## [0.2.1] - 2026-08-05

First release published on crates.io, as `uu_shadow` and `uu_shadow_core`
(both plain names were already taken).

### Added

- `audit.yml` workflow for daily `cargo-audit` security advisory checks (#155)
- AT_EXECFN validation in multicall binary: rejects spoofed `argv[0]` in
  setuid context by comparing against the kernel-recorded executable path (#154)
- Tools identify themselves as part of uutils: `--version` prints
  `<tool> (uutils shadow-rs) <version>` and `--help` carries a project
  footer, including the multicall front-end (#161)
- `.pre-commit-config.yaml` (#164)

### Changed

- AT_EXECFN check uses `rustix::param::linux_execfn()` instead of unsafe
  `libc::getauxval` — zero new unsafe for this feature
- Packages renamed to `uu_shadow` / `uu_shadow_core` for crates.io
- All workspace crate versions aligned
- "Permission denied" for the root-required guards is now taken from the OS
  via `strerror(EACCES)` rather than a hardcoded literal, so it matches the
  host and is localized by glibc (#159)
- Clap-error handling de-duplicated: the `AlreadyPrinted` sentinel and the
  `try_get_matches_from` boilerplate moved from 12 tool error enums into
  `shadow_core::cli` (#181)
- `uucore` 0.8 → 0.9 (#179)
- Random bytes come from `rustix` instead of a separate `getrandom` dependency
  (#165)
- 118 clap `--help`/`--about` strings rewritten from in-tree behavior; `--root`
  no longer claims a `chroot(2)` in the tools that only prefix paths (#161)
- Docker test matrix no longer fails on transient registry timeouts:
  `fail-fast: false`, image-build retry, and `CARGO_NET_RETRY` (#172)
- Dev images install `cargo-deny` as a pinned, checksum-verified prebuilt
  binary instead of compiling it (#175)

### Fixed

- `Cargo.lock` is committed, so the `cargo-audit` job actually runs — it had
  been failing on every invocation, silently masking advisories (#167)
- Removed an `unreachable!()` from `validate.rs` (#156)
- Removed the unused `show_error` / `show_warning` macros from `shadow-core`
  (#182)
- `shadow-core` carries an explicit version in workspace dependencies, needed
  for `cargo publish`

### Security

- `useradd` creates the home directory with its final mode atomically,
  closing a window in which it was world-writable (#157)

## [0.2.0] - 2026-04-22

### Added

- `usermod -p/--password` flag for setting pre-hashed passwords (#114)
- End-to-end deployment tests in Docker: 117 assertions covering symlink
  dispatch, setuid, PAM, Landlock, nscd, and Ansible interop (#102, #115)
- Docker multi-distro CI in GitHub Actions (debian, alpine, fedora)
- Shell completion generation for bash, zsh, fish (#106)
- Renovate for automated dependency updates
- `rust-toolchain.toml` for contributor convenience
- `feat_common_core` feature alias (all 14 tools)

### Changed

- Cargo.toml metadata aligned with uutils ecosystem conventions
- Tool crate descriptions normalized to `"tool ~ (shadow-rs) verb phrase"` format
- Edition 2024 consistently applied across root and workspace packages
- `make install` now defaults to 14 standalone per-tool binaries with
  least-privilege setuid layout matching GNU shadow-utils (#138). Only
  `passwd`/`chfn`/`chsh`/`newgrp` are setuid-root; the other 10 are `0755`.
  The previous multicall install is available as `make install-multicall`.
- `nix` crate fully replaced by `rustix` (raw syscalls, no libc overhead).
  `libc` kept only for PAM FFI, crypt(3) FFI, and process-wide POSIX
  wrappers (setuid/sigprocmask/getpwuid_r) (#140)
- `uucore` upgraded from 0.7 to 0.8 (#150)
- Repo transferred from `shadow-utils-rs/shadow-rs` to `uutils/shadow-rs`

### Security

- PAM password buffers zeroed immediately after use (`zeroize`)
- `initgroups()` called in newgrp before exec (prevents supplementary group leak)
- `SignalBlocker` scoped to file-mutation critical sections only; dropped before
  long-running operations (home deletion, recursive chown, skel copy)
- `UmaskGuard` marked `!Send`/`!Sync` via `PhantomData<Rc<()>>` (thread-safety)
- `newgrp` uses targeted hardening (`suppress_core_dumps` + `sanitized_env`)
  instead of `harden_process()` to avoid leaking `RLIMIT_FSIZE` to exec'd shell
- `atomic_write` retries once on stale temp file from prior crash
- `crypt(3)` wrapper documented as non-thread-safe (uses global state)
- Centralized hardening utilities in `shadow_core::hardening` (deduplicated
  from per-tool copies)
- `println!`/`eprintln!` replaced with non-panicking writes (#141)
- Unwind tables suppressed via `-C force-unwind-tables=no` (#143)

### Fixed

- Password hash validation rejects `:`, `\n`, `\r` (field injection prevention)
- Error on missing shadow entry in usermod (was silent no-op)
- `days_since_epoch()` centralized in shadow-core (was duplicated)

## [0.1.0] - 2026-03-24

### Added

- All 14 shadow-utils tools implemented as drop-in replacements:
  `passwd`, `useradd`, `userdel`, `usermod`, `groupadd`, `groupdel`,
  `groupmod`, `pwck`, `grpck`, `chage`, `chpasswd`, `chfn`, `chsh`, `newgrp`
- Single multicall binary with symlink dispatch (894 KB stripped)
- PAM integration for password authentication and changes
- Atomic file writes with lock-via-hard-link pattern (TOCTOU resistant)
- Stale lock detection via ESRCH-only PID checking
- Password zeroing via `zeroize` crate
- Core dump suppression and file size limit hardening
- Environment sanitization (safe for setuid-root context)
- Signal blocking during critical file operations
- SELinux file context support (best-effort via external tools)
- Audit logging to syslog and auditd
- subuid/subgid allocation for rootless containers (useradd)
- Recursive chown on UID change (usermod)
- Proper date validation with leap year and month-length rules
- GNU-compatible output and exit codes for all tools
- 580+ unit tests, property-based tests (proptest), 6 fuzz targets
- Integration tests for 14 tools
- Docker test matrix: Debian (glibc), Alpine (musl), Fedora (SELinux)
- CI gates: fmt, clippy, test, MSRV (1.94.0), cargo-deny
- Debian and RPM packaging
- Man pages for all 14 tools
- GNU compatibility test suite and PAM end-to-end test

### Security

- `unsafe_code = "deny"` enforced at workspace level (only PAM/crypt FFI exempted)
- `dead_code = "deny"` enforced at workspace level
- O_EXCL temp files (symlink attack prevention)
- Umask guard (RAII) for restrictive file permissions
- GPL clean-room development (MIT license, no GPL source referenced)
- 20+ security findings addressed across 4 review rounds
