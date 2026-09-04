# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Static musl release archive,
  `uu_shadow-x86_64-unknown-linux-musl-static.tar.gz`, published next to the
  glibc one. It is a self-contained binary for minimal containers and embedded
  images, built without `pam`, and it is not a substitute for the glibc
  archive: no PAM (no interactive `passwd`; `chfn`/`chsh` root-only), no NSS,
  no yescrypt. `make dist-musl` reproduces it and CI builds it on every pull
  request. The trade-off is documented in
  [docs/PLATFORM-SUPPORT.md](docs/PLATFORM-SUPPORT.md), shipped inside the
  archive (#224)

### Fixed

- The lock loop no longer spins at 100% CPU when a stale `.lock` cannot be
  removed (e.g. made immutable), and a filesystem without hard links now fails
  immediately instead of waiting out the full 15-second timeout (#240)
- `passwd` can change a password again. The 0.2.2 build applied its Landlock
  sandbox before `pam_start`, which stopped Linux-PAM from loading
  `pam_unix.so` (*"Module is unknown"*, exit 10) for every caller, and the
  privilege drop for the PAM conversation spanned `pam_chauthtok`, so
  `pam_unix` could not rewrite `/etc/shadow` for a non-root caller either.
  The sandbox now covers only the direct-file paths (`-S`, lock/unlock/
  delete/expire, aging) with rules that also let NSS, `nscd` and `logger`
  work, and privileges are dropped for `pam_authenticate` alone
- The end-to-end image builds again (`make install` had stopped producing the
  multicall binary it installed) and its suite runs in CI on every pull
  request. It now changes a password through PAM as an unprivileged user and
  verifies the result by authenticating — root's `su` never asks for a
  password, so the previous PAM checks proved nothing
- A `..` in a `--prefix`, `-d` or `-k` argument, or in a home directory read
  from `/etc/passwd`, no longer aborts the tool (`unreachable!` in the path
  resolver); `useradd -d /home/../x` had written the account and then died
  before creating the home. `useradd` now rejects a relative or climbing
  `-d`/`-k` with exit 3
- Writes to account files go through a buffer instead of one `write(2)` per
  field
- Cross-building for `x86_64-unknown-linux-musl` no longer fails at link time.
  `shadow-core` asked for `-lcrypt` unconditionally; musl implements crypt(3)
  inside libc and has no libcrypt, so the linker fell through to the host's
  glibc libxcrypt (#224)

### Security

- `chfn` now honours `CHFN_RESTRICT` from login.defs: a non-root user may
  change only the GECOS sub-fields it lists (unset means none, per
  login.defs(5)), instead of any field. GECOS values are also rejected if they
  contain `=` or control characters, not only `:` and commas (#247)
- `chsh` refuses to change the shell of a restricted account — one whose
  current shell is not listed in `/etc/shells` — for a non-root caller, so a
  deliberately confined login cannot escape by pointing itself at a normal
  shell (#247)
- `pwck -s` and `grpck -s` no longer rewrite the files when a line failed to
  parse. Sorting works on the entries that parsed, so the write silently
  dropped every line the tool had just reported as invalid, along with all
  comments. They now report the errors and exit 2 without writing. `-r` and
  `-s` are also rejected together, as the man pages require (#246)
- `userdel -r` no longer deletes a home directory that the user does not own
  or that another account shares, unless `-f` is given (`userdel(8)` ties both
  to `-f`). It could previously erase a service account's root-owned
  `/srv/data`, or one of two accounts' shared home (#243)
- The account tools now take `/etc/.pwd.lock` (the `lckpwdf(3)` lock) in
  addition to the `.lock` files, so they exclude the rest of the system —
  `vipw`, `systemd-sysusers`, `libuser` and `pam_unix`'s own `passwd`. Before
  this, a password change racing a `useradd` could be silently lost. The lock
  is reference-counted per tree, so the several files one tool locks share one
  `fcntl` lock (#240)
- In the multicall layout, applets other than `passwd`, `chfn`, `chsh` and
  `newgrp` drop to the caller's uid before running. The setuid binary let any
  local user run `pwck -s` or `grpck -s` with euid 0 and rewrite
  `/etc/passwd`, `/etc/shadow`, `/etc/group` and `/etc/gshadow`. The two
  install layouts now have the same privilege model
- Rewritten account files keep their owner, group and SELinux label. The
  atomic writer created the replacement file as `root:<effective gid>`, so
  any administrative change turned `/etc/shadow` from `root:shadow` into
  `root:root` — breaking every sgid-`shadow` authenticator such as
  `unix_chkpwd` — and a rewrite performed by a setuid tool handed the file to
  the caller's group
- Every text field written to `passwd`, `shadow`, `group`, `gshadow`, `subuid`
  or `subgid` is validated: `:`, newlines and other control characters are
  refused by `useradd`, `usermod`, `groupadd` and `groupmod` (exit 3) and,
  as a last line of defence, by the `shadow-core` writers. `useradd -c` with
  a newline in the value could previously append an arbitrary `/etc/passwd`
  record
- `passwd --prefix` is root-only, like `--root`: it pointed a setuid binary
  at account files of the caller's choosing
- Core dumps are disabled with `PR_SET_DUMPABLE` in addition to
  `RLIMIT_CORE`; the limit alone is ignored when cores are piped to
  `systemd-coredump` or `apport`
- `chfn` and `chsh` now authenticate the caller before applying a change.
  Both are installed setuid-root and restricted non-root callers to their own
  account, but never verified who was asking — anyone with access to an
  unlocked session could change that user's login shell or GECOS field.
  Distributions already ship `/etc/pam.d/chfn` and `/etc/pam.d/chsh` for this
  (#226)

### Changed

- `usermod -l` refuses a login name that already exists (exit 9). Renaming
  onto an existing account produced two entries with the same name in
  `/etc/passwd` and `/etc/shadow` — `usermod -l root alice` gave a second
  `root` (#242)
- `usermod -e` accepts the `YYYY-MM-DD` form its man page documents, not only
  days since the epoch, so `usermod -e 2030-01-01` (what Ansible and most
  scripts pass) works. The date is parsed before anything is written, so an
  invalid one no longer leaves an already-committed passwd change behind.
  `useradd` and `usermod` now share one calendar implementation in
  `shadow-core::date` (#242)
- `userdel` now removes the user's private group (the `USERGROUPS_ENAB` group
  named after the login) when it has no other members, purges the user's
  `/etc/subuid` and `/etc/subgid` ranges so a later same-named user does not
  inherit them, and exits 6 (not 1) for a user that does not exist — with `-f`
  it tolerates the absence and cleans up whatever remains (#243)
- `groupmod -g` now updates `/etc/passwd`: users whose primary group is the
  one being renumbered follow it, instead of being left with a primary GID
  that no longer names a group. It also rejects GID `4294967295`
  (`(gid_t)-1`, the "no change" sentinel), and takes the passwd lock before
  the group lock so its lock order stays acyclic with `useradd`/`usermod`
  (#245)
- `groupadd -K` now honours any login.defs key, not only the four GID-range
  ones, and rejects malformed pairs the same way `useradd -K` does; both tools
  share one parser in `shadow-core` (#223)
- Without the `pam` feature, `chfn` and `chsh` refuse non-root invocations
  rather than applying an unauthenticated change. Every install path enables
  the feature; a static musl build would not — see
  [docs/PLATFORM-SUPPORT.md](docs/PLATFORM-SUPPORT.md)
- `PrivDrop`, the guard that lowers privileges for a PAM conversation, moved
  from `passwd` into `shadow-core` so every setuid tool uses one implementation
- CI lints and tests the `pam` code path, which the release binaries use but
  no job previously exercised
- Requesting the `pam` feature in a statically linked musl build is now a
  compile-time error instead of a binary whose authentication path can never
  work: Linux-PAM loads its modules with `dlopen`, which static musl lacks

### Removed

- `shadow-core`'s `selinux` module and feature flag. Nothing compiled it; the
  atomic writer now preserves the label itself

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
