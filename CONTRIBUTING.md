<!-- spell-checker:ignore reimplementing setuid subuid subgid gshadow -->

# Contributing to shadow-rs

Thanks for wanting to contribute to shadow-rs! This document explains
everything you need to know.

Before you start, also check:

- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- [SECURITY.md](./SECURITY.md) for vulnerability reporting

> [!WARNING]
> shadow-rs is original code and **cannot contain any code from GNU
> shadow-utils** or other GPL-licensed implementations. This means that
> **we cannot accept any changes based on the
> [shadow-maint/shadow](https://github.com/shadow-maint/shadow) source
> code** (GPL-2.0+). To make sure that cannot happen, **you must not read
> or link to the GNU source code**. This includes paraphrasing or
> translating their logic, and feeding it into an LLM for translation.

## Safe Reference Sources

When implementing a tool, reference ONLY these sources:

| Source | License | Use |
|--------|---------|-----|
| [POSIX specification](https://pubs.opengroup.org/onlinepubs/9799919799/) | Open standard | Behavioral spec |
| Man pages (man7.org) | Documentation | Command options, file formats |
| [FreeBSD src](https://cgit.freebsd.org/src/) | BSD-2-Clause | Implementation patterns |
| [OpenBSD src](https://cvsweb.openbsd.org/src/) | ISC | Implementation patterns |
| [musl libc](https://musl.libc.org/) | MIT | pwd/grp/shadow C API |
| [sudo-rs](https://github.com/trifectatechfoundation/sudo-rs) | Apache-2.0 / MIT | PAM, privilege-dropping |

**Process**: Read the POSIX spec and man page for behavioral requirements,
then write an original implementation. Never search for or view the C source.

## Getting Started

### Requirements

- Docker and Docker Compose (all builds/tests run in containers)
- Git

### Setup

```shell
git clone https://github.com/uutils/shadow
cd shadow
docker compose build
./hooks/install.sh  # install pre-commit and pre-push hooks
```

The hooks are deliberately small. `pre-commit` checks formatting and runs
clippy; `pre-push` runs `make test` once, on Debian, and skips entirely for a
push that carries no new commits (a tag, a deletion, a branch the remote
already has). Everything else — MSRV, cargo-deny, the static musl archive, the
three-distro matrix as root, the GNU output comparison and the end-to-end
deployment image — runs in CI on the pull request, in parallel and with
retries. A hook that tried to match CI took minutes on every push and was
routed around with `--no-verify`, which protects nothing.

There is a second hook system, `.pre-commit-config.yaml`, run by pre-commit.ci
on the pull request. It does not overlap: whitespace, line endings, large
files, and the spell checker. The two are kept apart on purpose — file hygiene
needs no container, and the Rust checks need one.

### Building and Testing

`make check` is the single definition of what CI gates on — formatting, clippy
with and without `pam`, and the tests in both configurations. Run it in a
container; do not build on the host.

```shell
docker compose run --rm debian make check           # everything CI gates on
docker compose run --rm debian make test-gnu-compat # compare against GNU

docker compose run --rm debian cargo build          # build
docker compose run --rm debian cargo test --workspace  # test on Debian
docker compose run --rm alpine cargo test --workspace  # test on Alpine (musl)
docker compose run --rm fedora cargo test --workspace  # test on Fedora (SELinux)
```

All three must pass. The `alpine` image tests musl with dynamic linking; the
release also ships a *static* musl archive, built without PAM, which
`make dist-musl` reproduces and CI builds on every pull request. What that
build gives up is documented in
[docs/PLATFORM-SUPPORT.md](docs/PLATFORM-SUPPORT.md).

### Linting

```shell
docker compose run --rm debian cargo clippy --workspace --all-targets -- -D warnings
docker compose run --rm debian cargo fmt --all --check
```

## Design Goals

- **Drop-in replacement**: same flags, same exit codes, same output format as
  GNU shadow-utils. Differences with GNU are treated as bugs.
- **uutils compatible**: tools use `uucore` (`UResult<()>`, `#[uucore::main]`,
  `show_error!`) so they can be merged into the uutils ecosystem.
- **Memory safe**: no `.unwrap()`, no `panic!`, no `std::process::exit` in
  library code.
- **Well-tested**: unit tests, proptest, integration tests, fuzz targets.

## Our Rust Style

### Don't `panic!`

Never use `.unwrap()` or `panic!`. Use `unreachable!` only with a justifying
comment. Return errors via `UResult<()>`.

### Don't `exit`

Utilities must be embeddable. Return `UResult<()>` from `uumain`. The
`uucore::bin!()` macro handles `process::exit` in the generated `main()`.

### `unsafe`

Denied at the workspace level (`unsafe_code = "deny"`). Only three FFI boundary
modules are exempted: `shadow_core::pam` (PAM C library), `shadow_core::crypt`
(POSIX crypt(3)) and `shadow_core::process` (setuid, signal masks,
`getpwuid_r`). Every `unsafe` block must have a `// SAFETY:` comment.

### `str`, `OsStr` & `Path`

Use `OsStr` and `Path` for filesystem paths. Only convert to `String`/`str`
when you know the data is always valid UTF-8 (usernames, for example).

### Comments

Comments explain _why_, not _what_. If you need to describe what code does,
improve the naming instead.

## Commits

- Small, atomic commits — one logical change per commit
- Tool-prefixed messages: `passwd: fix buffer handling`
- Test commits: `tests/passwd: add aging test`
- Do not move code in the same commit as a behavior change

## Pull Requests

- One issue per PR, reference it: `Fixes #N`
- Title prefixed with tool name, under 70 characters
- Branch naming: `fix/N-short-description` or `feat/N-short-description`
- CI must pass (clippy, fmt, tests on all 3 distros)
- Keep PRs small and self-contained

## AI-Assisted Development

AI tools (Copilot, Claude, etc.) are allowed and treated like any other
development tool.

- All code must be understood, reviewed, and tested by human contributors
- **Clean-room rule is absolute** — never feed GPL source into an LLM
- Reference only: POSIX specs, man pages, BSD-licensed implementations
- If a PR is substantially AI-generated, note it (transparency, not a blocker)
- Quality is the gate — contributions are judged on correctness and test
  coverage, not authorship method

## Licensing

shadow-rs is distributed under the terms of the [MIT License](LICENSE).

Acceptable dependency licenses: MIT, Apache-2.0, ISC, BSD-2-Clause,
BSD-3-Clause, CC0-1.0, Unicode-3.0, Zlib, MPL-2.0.

**No GPL or LGPL dependencies, ever.**
