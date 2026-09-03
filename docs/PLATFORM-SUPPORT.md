# Platform support

What shadow-rs builds and runs on, and where a build differs in behaviour.

The distinction that matters most is the C library. shadow-rs is tested on both
glibc and musl, but *tested on* and *released for* are not the same thing:
released archives are glibc, and a musl build is functionally reduced in three
specific ways described below.

## Release artifacts

| Target | Published | Linking |
|---|---|---|
| `x86_64-unknown-linux-gnu` | yes | dynamic (libpam, libcrypt, libc) |
| `x86_64-unknown-linux-musl` | no — see below | static |
| `aarch64-unknown-linux-gnu` | no — tracked in #222 | dynamic |

## Test matrix

CI builds and runs the full suite on three images, so musl regressions are
caught even though musl is not released:

| Image | Base | libc | PAM | SELinux |
|---|---|---|---|---|
| `debian` | `rust:latest` (Trixie) | glibc | Linux-PAM | headers |
| `alpine` | `rust:alpine` | musl | Linux-PAM | none |
| `fedora` | `fedora:latest` | glibc | Linux-PAM | enforcing |

## musl

A static musl binary **builds and runs**. What stops it being published is that
it is not equivalent to the glibc build — it loses three things, and for
account-management tools none of them is cosmetic.

### 1. No PAM

Linux-PAM loads its modules with `dlopen`. A fully static binary cannot do
that: musl's static `dlopen` is a stub that returns *"Dynamic loading not
supported"*, and Alpine ships no `libpam.a` to link against in the first place.

Effect: `passwd`'s interactive password change is unavailable. Everything else
is unaffected — `passwd -S/-l/-u/-d/-e/-n/-x/-w/-i` and the other 13 tools
reach `/etc/shadow` and crypt(3) directly.

### 2. No NSS

`shadow_core::process` resolves the calling user through `getpwuid_r`, used by
`passwd`, `chfn`, `chsh`, `chage` and `newgrp`.

glibc answers such lookups through its NSS module system, so it sees users from
LDAP, SSSD, Active Directory or systemd-userdb. musl has no NSS module system
and reads `/etc/passwd` directly. On a directory-joined host, those five tools
would not see network users at all.

### 3. No yescrypt (`$y$`)

musl's crypt(3) implements DES, MD5, SHA-256, SHA-512 (including
`rounds=`) and bcrypt, and produces byte-identical output to libxcrypt for all
of them. It does not implement yescrypt.

This is not a marginal format: **Debian 12+ and Ubuntu 24.04 use yescrypt as
the default password hash.** A musl build can neither verify nor produce `$y$`
hashes, so `newgrp` fails against a `$y$` group password and `chpasswd`
produces SHA-512 where the system default is yescrypt. The prefix guard in
`shadow_core::crypt` rejects the format explicitly rather than silently
falling back.

### Where musl is nonetheless the right choice

Minimal containers and embedded images: a local `/etc/passwd`, no directory
service, no PAM stack. There, none of the three gaps costs anything, and a
single static binary with no runtime dependencies is worth having.

If a musl archive is published it must be labelled as static, PAM-less,
NSS-less and without `$y$` — never presented as an alternative to the glibc
archive. Tracked in #224.

### Building for musl

The `#[link(name = "crypt")]` attribute in `shadow_core::crypt` emits
`-lcrypt`. Rust's self-contained musl sysroot has no `libcrypt.a`, so the
linker falls through to the host's glibc-built libxcrypt and fails on
glibc-only symbols. musl implements `crypt()` inside libc itself, so the
attribute simply should not be emitted for that target:

```rust
#[cfg_attr(not(target_env = "musl"), link(name = "crypt"))]
```

Alpine builds work today without this because `musl-dev` ships an empty
`libcrypt.a` that absorbs the flag.

Note that libxcrypt is **LGPL-2.1+**, so it cannot be vendored to fill the gap:
shadow-rs takes no GPL or LGPL dependencies. Pure-Rust alternatives exist
(`sha-crypt`, `yescrypt`, both MIT/Apache-2.0), but the yescrypt crate is
self-declared unaudited, which rules it out of a setuid-root path for now.

## Architectures

Only `x86_64` is published. aarch64 needs the target's system libraries for
crypt(3) and PAM, so it requires a cross-compilation setup or a native runner —
tracked in #222.
