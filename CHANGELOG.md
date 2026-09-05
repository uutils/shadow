# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-09-05

### Added

- `aarch64-unknown-linux-gnu` release archive, published next to the x86-64
  one. It is built on a native arm64 runner rather than cross-compiled:
  `shadow-core::crypt` links crypt(3) and the `pam` feature links libpam, so a
  cross build would need an arm64 sysroot carrying both (#222)
- `chfn` and `chsh` prompt when no field option is given, showing the current
  value in brackets, as their man pages describe. Pressing ENTER keeps the
  value, and an all-ENTER run exits 0 without writing (#247)
- `chsh -s ''` selects the system default shell. passwd(5) gives the field no
  meaning of its own and `login` falls back to `/bin/sh`, so an empty field is
  the default rather than a program that does not exist (#247)
- `newgrp -` reinitializes the environment as at login, which newgrp(1)
  documents and which previously looked for a group named `-` (#248)
- `--prefix` on `chage` and `chpasswd`, so their behaviour can be exercised
  without touching the live files (#248)
- `make check` runs everything CI gates on, so the README, CONTRIBUTING, the
  git hooks and `ci.yml` stop each carrying their own copy of the command
  list (#250)
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

- `--root DIR` performs a real `chroot(2)` in every tool. Five did; the other
  eight folded it into the same resolver `--prefix` uses, so it only prefixed
  the files the tool itself opened. `useradd -R /mnt/target -m alice` created
  the home on the **host**, at `/home/alice`, and copied the skeleton from the
  host's `/etc/skel`; `userdel -r -R` resolved the home to delete against `/`
  (#270)
- `passwd -l` is idempotent. Locking twice left `!!`, and since `passwd -u`
  refuses to unlock an account that would stay locked, an account locked twice
  could not be unlocked with the tool at all (#250)
- `chage -l` prints what chage(1) prints. A last change of 0 is `passwd -e`'s
  "must change at next login" marker, not a date, so all three password lines
  read *password must be changed*; and expiry is disabled at a maximum age of
  10000 days, not 99999 (#248)
- `chage` and `passwd` exit 1 for an unknown login. chage(1) reserves 15 for
  "can't find the shadow password file" and 3 is an unexpected failure; a
  login the caller named that does not exist is neither (#248)
- `chage` exits 2 for a malformed date, the code for a bad option argument,
  rather than 3 (#248)
- `chpasswd` takes its default hashing scheme from `ENCRYPT_METHOD` in
  login.defs. It was hard-coded SHA-512, so on a distribution that sets
  YESCRYPT every password set through this tool was weaker than the one the
  same user would get from `passwd` (#248)
- `chpasswd` rejects the two flag pairs chpasswd(8) forbids: `-s` without `-c`
  and `-e` with `-c`. Both were accepted and silently did nothing (#248)
- `chpasswd` resolves every account in a batch before writing any, so an
  unknown login in the middle of a list no longer leaves the first half
  applied (#248)
- `login.defs` numbers are read in the radices login.defs(5) documents.
  Parsing decimal only was not a rejection but a misreading: `UID_MIN 01000`
  means 512 and came back as 1000, so `useradd` allocated from a range the
  administrator had reserved (#249)
- The aging arithmetic is checked. `chage -l` sums `lastchg + max + inactive`,
  three values read from a file anyone who can write `/etc/shadow` chooses;
  plain addition wraps in release builds and panics in debug ones (#248)
- Every tool takes the lock before reading the file it is about to rewrite.
  The order was written out by hand at thirty-odd call sites and `pwck -s` had
  it wrong, sorting entries read beforehand and so reverting a change another
  process made in between (#249)
- Rewriting an account file no longer deletes its comments, blank lines and
  NIS compatibility lines. Every tool dropped them on read, so the first
  `useradd`, `usermod`, `groupadd`… erased every comment in `/etc/passwd` and
  `/etc/group`; and because `+user`, `+@netgroup` and `-user` do not parse as
  records, on a host using `compat` in `nsswitch.conf` every tool failed
  outright. Those lines are now preserved and each one stays anchored to the
  entry it preceded, so a comment follows its account even when `pwck -s`
  reorders the file (#241)
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

- `chsh` tests `/etc/shells` membership before existence for a non-root
  caller. Installed setuid-root, its existence check answers with root's view
  of the filesystem, so a distinct "does not exist" reply made the tool an
  oracle for paths the caller cannot stat, one probe at a time. Membership is
  checked first and discloses nothing, `/etc/shells` being world-readable
  (#247)
- `chfn` and `chsh` validate the new value before the PAM conversation, so a
  refused value no longer costs the caller a password prompt (#247)
- No tool calls `setuid(0)` before writing. euid 0 is all the lock and the
  atomic write need; raising the *real* uid made `caller_is_root()` — which is
  deliberately real-uid based — answer true for every caller for the rest of
  the process (#247)
- Ctrl-C at a password prompt no longer leaves the terminal with echo off. The
  signal terminates without unwinding, so the guard's destructor never ran;
  the shared reader blocks `SIGINT`, `SIGQUIT` and `SIGTSTP` for the duration,
  which is what `readpassphrase(3)` does (#248)
- The copy of the password crypt(3) requires as a C string is owned in a
  zeroizing buffer. `CString::new` made it on the heap and freed it without
  zeroing, and the caller's `Zeroizing<String>` never learned about it (#248)
- The PAM response scrub uses volatile writes. Zeroing with `ptr::write_bytes`
  immediately before `free()` is a dead store the optimiser may delete,
  leaving the password in the heap (#248)
- `PAM_TTY` and `PAM_RUSER` are set on every PAM handle, so `pam_unix` and
  `pam_faillock` can record which terminal and which caller a failed
  authentication came from instead of logging `tty=?` (#248)
- UID and GID allocation asks the name service as well as the file, so an ID
  belonging to an LDAP, SSSD or systemd-homed account is never handed out
  locally — two accounts with one ID are indistinguishable to the kernel. A
  `--prefix` run deliberately does not ask: those files describe another
  system (#249)
- GitHub Actions are pinned by commit digest. A tag is a moving pointer, and
  whoever controls an action's repository can repoint it at any commit that
  then runs here with write access to the checkout (#250)
- `useradd` changes the ownership of a new home directory through a descriptor
  opened with `O_NOFOLLOW` rather than by path. Between the `mkdir` and the
  `chown`, anyone able to write the parent — a home under `/tmp`, or a shared
  base directory — could swap the directory for a symlink and be given its
  target (#244)
- `chpasswd` refuses an empty plaintext password. `alice:` on stdin hashed the
  empty string into a perfectly valid hash, so the account then logged in with
  a bare Enter; only `-e`, which takes a pre-computed field, may carry an
  empty value. It also stops trimming the line, so a password with trailing
  whitespace is stored as supplied rather than silently changed (#248)
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

- `make install` puts `passwd`, `chage`, `chfn`, `chsh` and `newgrp` in
  `bin` and the rest in `sbin`, the split the GNU package uses. All fourteen
  went to `sbin`, which is not on a normal user's PATH, so `passwd` was
  *command not found* for exactly the people it is setuid for (#250)
- Only the Cargo features that change linkage remain: `pam`, `crypt` and
  `landlock`. The five that gated dependency-free parsers made
  `cargo test -p shadow-core` compile a fraction of the crate and report a
  pass for it — it runs 181 tests now where it ran 20. Asking for `pam` no
  longer force-enables the three applets that can use it (#249)
- Audit records go straight to `/dev/log` instead of forking `/usr/bin/logger`
  for every event, and carry the terminal they came from (#249)
- The Docker base images and the GitHub Actions are pinned, so a new toolchain
  or distro release arrives as a reviewable pull request rather than landing
  on `main` unannounced (#250)
- The licence allow list in `deny.toml` is exactly what the dependency graph
  uses. A list wider than the graph means a crate arriving under a new licence
  passes silently (#250)
- The integration suite is one test binary rather than fourteen, and it spawns
  the real binary instead of calling `uumain` in-process, so it can assert on
  output and cannot leak process state between tests (#250)
- The pre-push hook runs the tests once, on Debian, and skips entirely for a
  push carrying no new commits. Reproducing CI took minutes on every push, so
  every push used `--no-verify` (#231)
- `grpck -q` reports errors again: every error print was suppressed along with
  the warnings, so `-q` hid exactly what `grpck(8)` says it keeps. A malformed
  or unreadable `/etc/gshadow` is now an error rather than "nothing to check",
  and members and administrators are checked against `/etc/passwd` (#246)
- `pwck` reports a relative home directory or login shell instead of resolving
  it against its own working directory and reporting on whatever was there,
  and a sort that cannot be written exits 6 as `pwck(8)` documents (#246)
- `groupadd` takes the group lock *before* reading `/etc/group`. The name
  check and the GID allocation ran on a snapshot taken beforehand, so two
  concurrent `groupadd -r` calls could allocate the same GID and two
  `groupadd www` could both decide the name was free (#245)
- `groupadd -U` and `groupmod -U`/`-a` set a group's member list, and
  `groupdel -f` removes a group that is a user's primary group and succeeds
  when the group does not exist — all four documented and all four previously
  a usage error (#245)
- `groupmod -p` writes the password into `/etc/group` when there is no
  `/etc/gshadow`, instead of silently doing nothing (#245)
- `groupdel` no longer leaves the deleted group behind in `/etc/gshadow` when
  it was the only entry there, and can delete the last group in `/etc/group`
  (#245)
- `usermod -g` takes a group name as well as a GID, and requires the group to
  exist (exit 6). A numeric GID naming no group was written through, leaving a
  primary group that does not exist (#242)
- `usermod -G ""` clears every supplementary membership, as `usermod(8)`
  documents, instead of reporting a group named `''` that does not exist;
  `-G` accepts GIDs as well as names, `-a` requires `-G`, and `/etc/gshadow`
  is kept in step with `/etc/group` on both `-G` and `-l` — leaving it behind
  is what `grpck` reports as "members differ" (#242)
- `usermod -l` combined with `-G` adds the **new** login to the groups; it
  used to add the old one, which no longer names an account (#242)
- `usermod -L` no longer prepends a second `!` to an already-locked password
  (a single `-U` could not undo that), and `-U` refuses to leave an account
  with no password at all instead of silently doing nothing (#242)
- Group errors from `usermod` report the codes `usermod(8)` documents: 6 for a
  group that does not exist, 10 for a failure to update the group file (#242)
- `useradd` reads `/etc/default/useradd`, and `useradd -D` with a value now
  saves it there instead of printing the defaults and changing nothing.
  `HOME`, `SHELL` and `SKEL` from that file take precedence over login.defs,
  so a site's configured shell is finally used (#244)
- `useradd` gains `-b/--base-dir` and `-P/--prefix`, and rejects UID
  `4294967295` (`(uid_t)-1`) (#244)
- `useradd -r` now matches `useradd(8)`: a system account gets no home
  directory (regardless of `CREATE_HOME`), no aging information in
  `/etc/shadow`, and no subordinate UID/GID ranges (#244)
- `useradd -g` and `-G` require the group to exist, named or numbered, and
  exit 6 when it does not. A numeric GID naming no group was accepted, leaving
  the account pointing at a group that did not exist; `-G` also rejected the
  numeric form the man page allows (#244)
- UIDs and GIDs are allocated past the highest already in use rather than in
  the first gap, so a new account no longer inherits a deleted one's ID — and
  its leftover files. The first free ID is still used once the range top is
  taken (#244)
- `useradd` honours `HOME_MODE` from login.defs and creates missing parent
  directories of the home, instead of always using `0700` and failing when the
  base directory does not exist (#244)
- Usernames and group names may contain upper case and end with `$`, both of
  which shadow-utils accepts — the latter is how Samba names machine accounts.
  Refusing them meant refusing accounts that exist on real systems (#244)
- The password-aging fields reject a negative day count other than `-1`.
  `chage -M -5` and `passwd -x -5` stored the value verbatim and left a
  nonsensical policy behind; they now exit 2 and 6 respectively, the codes
  their man pages give for an invalid option argument. `passwd -n/-x/-w/-i`
  also accept `-1` at last (clap rejected the leading hyphen) and treat it as
  "clear the field", the way `chage` already did (#248)
- `chpasswd` hashes before taking the `/etc/shadow` lock. A batch of yescrypt
  or high-`rounds=` hashes held the lock, with signals blocked, for the whole
  run (#248)
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

- The RPM spec and the `debian/` directory. Neither could build: `debian/` has
  no changelog at all, so `dpkg-buildpackage` stops before it starts, and the
  spec pinned an old version, the pre-transfer repository URL and a `%files`
  layout `make install` does not produce (#250)
- An unused, unpinned `cargo-nextest` download from every Docker image.
  Nothing in the repository runs it (#250)
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
