<!-- spell-checker:ignore reimplementation setuid nscd subuid subgid gshadow -->
<div align="center">

# shadow

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/uutils/shadow/blob/main/LICENSE)
[![CI](https://github.com/uutils/shadow/actions/workflows/ci.yml/badge.svg)](https://github.com/uutils/shadow/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.94.0-blue)](https://github.com/uutils/shadow)

</div>

---

A memory-safe reimplementation of the Linux
[shadow-utils](https://github.com/shadow-maint/shadow) in
[Rust](http://www.rust-lang.org). shadow-utils (`useradd`, `passwd`,
`groupadd`, etc.) is the suite of setuid-root tools that manages user accounts,
passwords, and groups on every Linux system.

## Why

shadow-utils runs as **root or setuid-root on every Linux system**. It parses
user-supplied input, writes to `/etc/passwd`, `/etc/shadow`, `/etc/group`, and
has had recent CVEs (CVE-2023-4641: password leak in memory, CVE-2024-56433:
subuid collision enabling account takeover). Before this project there was
**no Rust reimplementation** — not in uutils, not in Prossimo/Trifecta, not on
crates.io.

[sudo-rs](https://github.com/trifectatechfoundation/sudo-rs) proved the model:
an independent Rust rewrite of a privilege-boundary tool can go from zero to
default-in-Ubuntu in under 3 years. This project follows that playbook.

## Goals

- **Drop-in replacement**: same flags, same exit codes, same output format as
  GNU shadow-utils. Differences are treated as bugs.
- **uutils compatible**: built on [`uucore`](https://crates.io/crates/uucore)
  with the standard `uumain()` / `uu_app()` API contract. Designed to merge
  into the uutils ecosystem.
- **Memory safe**: eliminate entire classes of vulnerabilities (buffer overflows,
  use-after-free, uninitialized memory) that affect the C original. Passwords
  zeroed in memory via `zeroize`.
- **Well-tested**: unit tests, property-based tests (`proptest`), integration
  tests, fuzz targets for all parsers. Tested on Debian, Alpine (musl), and
  Fedora (SELinux).
- **Hardened**: Landlock filesystem sandboxing, signal blocking during
  critical sections, core dump suppression, environment sanitization,
  privilege drop during PAM.
- **Auditable**: small dependency tree, `cargo-deny` license and advisory
  checks, no GPL dependencies.

## Status

| Tool | Status |
|------|--------|
| `passwd` | **All 16 flags implemented.** Drop-in for GNU passwd. PAM password change, Landlock sandboxing, `--root`, `--quiet`, `--stdin`. Output bit-for-bit identical with GNU. |
| `pwck` | **All checks implemented.** Drop-in for GNU pwck. Bit-for-bit identical output. |
| `useradd` | **Implemented.** UID/GID allocation, home dir + skel, shadow entry, group creation. |
| `userdel` | **Implemented.** Remove from all system files, optional home/mail cleanup. |
| `usermod` | **Implemented.** Modify all properties, group membership, lock/unlock, set pre-hashed password. |
| `chpasswd` | **Implemented.** Batch password change from stdin. |
| `chage` | **Implemented.** Password aging management, `-l` list mode. |
| `groupadd` | **Implemented.** Auto GID allocation, system groups, force mode. |
| `groupdel` | **Implemented.** Primary group usage check. |
| `groupmod` | **Implemented.** GID change, rename, password. |
| `grpck` | **Implemented.** Group/gshadow integrity verification. |
| `chfn` | **Implemented.** GECOS sub-field modification. |
| `chsh` | **Implemented.** Shell change with /etc/shells validation. |
| `newgrp` | **Implemented.** Effective group change with crypt verification. |
| `gpasswd` | **Implemented.** Group membership, administrators, and group password. |

## Building

### Requirements

- Rust (stable toolchain)
- Linux (PAM headers, SELinux headers optional)
- Docker + Docker Compose (for testing)

### Build

```shell
git clone https://github.com/uutils/shadow
cd shadow
docker compose build debian
docker compose run --rm debian cargo build --release
```

### Install

Default install: 15 standalone per-tool binaries with least-privilege setuid
layout matching GNU shadow-utils. Only `passwd`, `chfn`, `chsh`, `newgrp`,
`gpasswd` are installed setuid-root; the other 10 are plain `0755`.

```shell
sudo make install PREFIX=/usr/local
```

Alternative: single multicall binary with symlinks. Smaller footprint (~14×
disk savings). The binary is installed setuid-root so that `passwd`, `chfn`,
`chsh` and `newgrp` can serve unprivileged callers; every other applet drops
back to the caller's uid before it runs, so the privilege model is the same
as the per-tool layout. Intended for container/embedded use cases.

```shell
sudo make install-multicall PREFIX=/usr/local
```

#### From a release archive

Each [release](https://github.com/uutils/shadow/releases) publishes two
archives, each with a `.sha256` alongside. They contain the same `shadow-rs`
multicall binary but are **not interchangeable**:

| Archive | libc | Linking | Use it for |
|---|---|---|---|
| `uu_shadow-x86_64-unknown-linux-gnu.tar.gz` | glibc | dynamic | Any regular distribution. **This is the full build.** |
| `uu_shadow-x86_64-unknown-linux-musl-static.tar.gz` | musl | static | Minimal containers and embedded images: local `/etc/passwd`, no directory service, no PAM stack. |

The static archive has no runtime dependencies, and pays for that with three
capabilities a static binary cannot have — none of them cosmetic for account
tools:

- **No PAM.** `passwd` cannot change a password interactively, and `chfn` /
  `chsh` are root-only (they authenticate the caller through PAM and fail
  closed without it).
- **No NSS.** Users from LDAP, SSSD, Active Directory or systemd-userdb are
  invisible to the five tools that look up the calling user.
- **No yescrypt (`$y$`).** The default password hash on Debian 12+ and
  Ubuntu 24.04 can be neither verified nor produced.

If any of those matter on the host, use the glibc archive.
[docs/PLATFORM-SUPPORT.md](docs/PLATFORM-SUPPORT.md) explains each gap, what
still works, and how the archive is built.

Either archive ships a plain binary — nothing is installed, symlinked, or made
setuid by extracting it. To deploy it the same way `make install-multicall`
would:

```shell
tar xzf uu_shadow-x86_64-unknown-linux-gnu.tar.gz   # or the -musl-static one
sudo install -o root -g root -m 4755 \
    uu_shadow-*/shadow-rs /usr/local/bin/shadow-rs
for tool in passwd chfn chsh newgrp gpasswd chage chpasswd groupadd groupdel \
            groupmod grpck pwck useradd userdel usermod; do
    sudo ln -sf shadow-rs "/usr/local/bin/$tool"
done
```

Mode `4755` is what the four self-service applets need; the others give the
privilege up before running. Run `shadow-rs --list` to see the applets a
given build contains, and `sha256sum -c uu_shadow-*.tar.gz.sha256` to verify
a download.

### Test

All builds and tests run inside Docker containers to isolate from the host
system. Three distros are tested to catch libc and PAM differences:

```shell
docker compose run --rm debian cargo test --workspace    # Debian Trixie (glibc)
docker compose run --rm alpine cargo test --workspace    # Alpine (musl libc)
docker compose run --rm fedora cargo test --workspace    # Fedora (SELinux enforcing)
```

### Lint

```shell
docker compose run --rm debian cargo clippy --workspace --all-targets -- -D warnings
docker compose run --rm debian cargo fmt --all --check
```

## Architecture

Cargo workspace monorepo built on [`uucore`](https://crates.io/crates/uucore):

```
src/bin/shadow-rs.rs     multicall binary (dispatches by argv[0])
        |
src/uu/{tool}/           individual tool crates (passwd, useradd, ...)
        |
   ┌────┴────┐
uucore    shadow-core    shared infrastructure + domain library
```

Tools use `uucore` for the standard uutils API (`UResult`, `#[uucore::main]`,
`show_error!`) and `shadow-core` for domain-specific functionality.

**shadow-core** provides:
- File parsers for `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`,
  `/etc/login.defs`, `/etc/subuid`, `/etc/subgid`
- Atomic file writes (lock, write tmp, fsync, rename, unlock, invalidate nscd)
  that keep the file's mode, owner, group and SELinux label
- PAM integration (feature-gated)
- Username/groupname and field validation (no `:` or control characters can
  reach a record)
- UID/GID allocation

Each **tool crate** exports `uumain()` and `uu_app()`, following
[uutils](https://github.com/uutils/coreutils) conventions exactly so a future
merge is frictionless.

## Docker Test Matrix

| Target | Base | libc | PAM | SELinux |
|--------|------|------|-----|---------|
| `debian` | `rust:latest` (Trixie) | glibc | Linux-PAM | headers |
| `alpine` | `rust:alpine` | musl | Linux-PAM | none |
| `fedora` | `fedora:latest` | glibc | Linux-PAM | enforcing |

The `alpine` image tests musl with dynamic linking, PAM included. The static
musl release archive is a different build — no PAM, no NSS, no yescrypt — and
has its own CI job that builds it and runs `shadow-core`'s unit tests against
static musl on every pull request. See
[docs/PLATFORM-SUPPORT.md](docs/PLATFORM-SUPPORT.md).

## Credits

Security patterns from [OpenBSD](https://cvsweb.openbsd.org/src/usr.bin/passwd/)
(ISC license). PAM integration patterns from
[sudo-rs](https://github.com/trifectatechfoundation/sudo-rs) (Apache-2.0/MIT).
uutils infrastructure via [`uucore`](https://crates.io/crates/uucore) (MIT).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Important**: uutils/shadow is developed under a strict GPL clean-room policy. Do
**not** read, reference, or feed into an LLM any code from
[shadow-maint/shadow](https://github.com/shadow-maint/shadow) (GPL-2.0+).
Reference only: POSIX specs, man pages, BSD-licensed implementations (FreeBSD,
OpenBSD, musl), and sudo-rs.

## License

uutils/shadow is licensed under the [MIT License](LICENSE).

GNU shadow-utils is licensed under the GPL 2.0 or later.
