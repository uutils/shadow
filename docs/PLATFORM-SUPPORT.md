# Platform support

What shadow-rs builds and runs on, which archives a release publishes, and
exactly where one build behaves differently from another.

The distinction that matters most is the C library. Every release publishes
glibc archives for two architectures and one static musl archive, and the two
kinds are **not interchangeable**: the glibc archives are the full build; the
static musl archive is a self-contained binary for containers and embedded
images that gives up three capabilities, each stated below. Its name carries a
`-static` suffix so the two are never confused.

## Release archives

| Archive | Architecture | libc | Linking | `pam` feature | Use it for |
|---|---|---|---|---|---|
| `uu_shadow-x86_64-unknown-linux-gnu.tar.gz` | x86-64 | glibc | dynamic (libpam, libcrypt, libc) | on | Any regular distribution install. The full build. |
| `uu_shadow-aarch64-unknown-linux-gnu.tar.gz` | arm64 | glibc | dynamic (libpam, libcrypt, libc) | on | The same build for arm64 servers and Apple-silicon containers. |
| `uu_shadow-x86_64-unknown-linux-musl-static.tar.gz` | x86-64 | musl | static, no runtime dependencies | off | Minimal containers and embedded images with a local `/etc/passwd`, no directory service and no PAM stack. |

Every archive ships a `.sha256` file in `sha256sum -c` format and contains the
`shadow-rs` multicall binary with `LICENSE`, `README.md` and `CHANGELOG.md`;
the musl archive also carries this document, so the trade-off travels with the
binary.

The glibc archives are dist's regular target builds with `features = ["pam"]`.
**arm64 is built on a native arm64 runner, not cross-compiled**, which is what
makes it straightforward: `shadow-core::crypt` links crypt(3) and the `pam`
feature links libpam, so a cross build would need an arm64 sysroot carrying
both, while a native runner installs them from apt like any other build.

The musl archive is produced differently. dist cannot vary features per target
and `pam` must be off for musl (see below), so it is built by `make dist-musl`
and attached as an extra artifact of the same release. Anyone can reproduce it
with that one command.

Both glibc archives are built inside an `ubuntu:22.04` container, so they run
on any system with **glibc 2.34 or newer** — Debian 12, Ubuntu 22.04, RHEL 9
and anything later. The runner itself is 24.04, because 22.04 runners are
being retired; building on it directly raised the floor to 2.39, since Rust's
`std` links `pidfd_spawnp` when the build host has it. Older systems than that
should use the static musl archive, which has no libc dependency at all.

## Test matrix

CI runs the full suite on three images:

| Image | Base | libc | PAM | SELinux |
|---|---|---|---|---|
| `debian` | `rust:1.98-trixie` | glibc | Linux-PAM | headers |
| `alpine` | `rust:1.98-alpine3.23` | musl (dynamic) | Linux-PAM | none |
| `fedora` | `fedora:44` | glibc | Linux-PAM | enforcing |

The base images are pinned. An unpinned tag lands a new toolchain on `main`
with no pull request to run it against, and clippy gains lints between Rust
releases; Renovate proposes the bumps instead.

The `alpine` image links musl dynamically and therefore *does* have PAM; it
tests musl's libc behaviour (no NSS, no yescrypt), not the static archive. The
static archive has its own job, `Static musl archive`, which on every pull
request runs `make dist-musl`, smoke-tests the result, runs `shadow-core`'s
unit tests against static musl, and checks that requesting `pam` there is
rejected at compile time. A tag is never the first time the archive is built.

## What the static musl build gives up

A static musl binary **builds and runs**; the whole test suite passes on musl.
What it cannot do is inherent to static linking and to musl, not to shadow-rs,
and for account-management tools none of it is cosmetic.

### 1. No PAM

Linux-PAM loads its modules with `dlopen(3)`. A fully static binary cannot do
that: musl's static `dlopen` is a stub that returns *"Dynamic loading not
supported"*, and no distribution ships a `libpam.a` to link against in the
first place. `shadow-core` refuses the `pam` feature on static musl with a
compile-time error, so the build cannot be misconfigured into a binary whose
authentication path never works.

Effect, and this is the heaviest of the three gaps:

- `passwd`'s interactive password change is unavailable and says so
  (*"PAM support is not compiled in"*).
- `chfn` and `chsh` become **root-only**. They authenticate the caller through
  PAM before applying a change, and a setuid-root tool must fail closed rather
  than apply an unverified one, so without PAM they refuse every non-root
  invocation outright.

Unaffected: `passwd -S/-l/-u/-d/-e/-n/-x/-w/-i`, `newgrp` (which authenticates
against the group password through crypt(3), not PAM), and the other eleven
tools, which are root-only anyway and reach `/etc/shadow` directly.

### 2. No NSS

`shadow_core::process` resolves the calling user through `getpwuid_r`, used by
`passwd`, `chfn`, `chsh`, `chage`, `newgrp` and `gpasswd`.

glibc answers such lookups through its NSS module system, so it sees users from
LDAP, SSSD, Active Directory or systemd-userdb. musl has no NSS module system
and reads `/etc/passwd` directly. On a directory-joined host those five tools
do not see network users at all.

### 3. No yescrypt (`$y$`)

musl's crypt(3) implements DES, MD5, SHA-256, SHA-512 (including `rounds=`)
and bcrypt, byte-identical to libxcrypt for all of them. It does not implement
yescrypt.

This is not a marginal format: **Debian 12+ and Ubuntu 24.04 use yescrypt as
the default password hash.** A musl build can neither verify nor produce `$y$`
hashes, so `newgrp` fails against a `$y$` group password and `chpasswd -c
YESCRYPT` is rejected. The prefix guard in `shadow_core::crypt` reports the
unsupported method explicitly; it never falls back to a weaker hash silently.
The default method is SHA-512, which is unaffected.

### Where the static build is the right choice

Minimal containers and embedded images: a local `/etc/passwd`, no directory
service, no PAM stack. There none of the three gaps costs anything, and a
single binary with no runtime dependencies is worth having. Anywhere one of
them matters, use the glibc archive.

## Building for musl

```shell
make dist-musl
```

The target adds the `x86_64-unknown-linux-musl` toolchain component, builds the
multicall binary in release mode with the lockfile enforced and without `pam`,
verifies that the binary has no `DT_NEEDED` entry, and writes the archive and
its checksum to `target/dist-musl/`.

Two details in the code make that work:

- **crypt(3) linkage.** On glibc systems crypt(3) lives in libcrypt (libxcrypt
  on Debian, Fedora and derivatives), so `shadow_core::crypt` asks for
  `-lcrypt`. musl implements `crypt()` inside libc and ships no libcrypt;
  Rust's self-contained musl sysroot has no `libcrypt.a` either, so the request
  would fall through to the host's glibc-built libxcrypt and fail on glibc-only
  symbols. The attribute is therefore `#[cfg_attr(not(target_env = "musl"),
  link(name = "crypt"))]`. (Alpine builds never hit this because `musl-dev`
  ships an empty `libcrypt.a` that absorbs the flag.)
- **`pam` guard.** `shadow_core::pam` emits `compile_error!` when built for
  musl with `crt-static`, the default for the musl target. Dynamic musl, as in
  the Alpine test image, is unaffected and links libpam normally.

libxcrypt itself is **LGPL-2.1+** and cannot be vendored to fill the yescrypt
gap: shadow-rs takes no GPL or LGPL dependencies. Pure-Rust alternatives exist
(`sha-crypt`, `yescrypt`, both MIT/Apache-2.0) and match libxcrypt output, but
the yescrypt crate is self-declared unaudited, which rules it out of a
setuid-root path for now.
