# Security Hardening Roadmap

Techniques adopted from OpenBSD and best practices for setuid-root tools.

## Implemented

### Privilege model

- [x] `caller_is_root()` uses `getuid()` not `geteuid()` for authorization
- [x] In the multicall layout, an applet outside `passwd`/`chfn`/`chsh`/`newgrp`
      drops to the caller's uid before running, so the single setuid binary has
      the same privilege model as the per-tool install — and fails closed if the
      kernel will not take the privilege away
- [x] `chfn` and `chsh` authenticate the caller through PAM before applying a
      change, and refuse every non-root use when PAM is not compiled in
- [x] `chfn` honours `CHFN_RESTRICT`; `chsh` refuses to change the shell of an
      account whose current shell is not listed in `/etc/shells`
- [x] `passwd --prefix` and `--root` are root-only: they point a setuid binary
      at files of the caller's choosing
- [x] User enumeration prevention (#49 — early permission check for non-root
      callers)
- [x] Privilege drop for the PAM *authentication* conversation in `chfn`/`chsh`
      (`PrivDrop` RAII, #39). `passwd` keeps euid 0 across `pam_chauthtok`:
      `pam_unix` needs it to run its helper and rewrite `/etc/shadow`, and keys
      the current-password prompt on the *real* uid, which stays the caller's
- [x] `initgroups()` in `newgrp` (prevent supplementary group leak across exec)

### File integrity

- [x] Atomic file writes with `fsync` + `rename`
- [x] Rewrites preserve the target's mode, **owner, group and SELinux label** —
      `/etc/shadow` stays `root:shadow 0640` instead of becoming `root:root`
      (which breaks every sgid-`shadow` authenticator) or being handed to a
      setuid caller's group
- [x] A symlinked target is resolved, so the file behind the link is replaced
      rather than the link itself
- [x] Temp files created with `0o600` (no world-readable window)
- [x] `TmpGuard` drop pattern (no leaked temp files)
- [x] `atomic_write` retry on stale temp file from prior crash
- [x] Zero-length output guard (#45 — in `atomic_write`)
- [x] Every text field written to an account file is validated: `:`, newlines
      and other control characters cannot reach a record, checked both by the
      tools (exit 3) and by the `shadow-core` writers
- [x] `pwck -s` / `grpck -s` refuse to rewrite a file in which any line failed
      to parse, instead of silently dropping the reported lines
- [x] `userdel -r` refuses a home the user does not own or that another account
      shares, unless `-f`
- [x] Path resolution is total: no `unreachable!()` reachable from a `--prefix`
      argument or a home directory read out of `/etc/passwd`

### Locking

- [x] Lock-via-hard-link (TOCTOU-resistant)
- [x] `/etc/.pwd.lock` taken as well, the `lckpwdf(3)` lock that `vipw`,
      `pwconv`, `libuser`, `systemd-sysusers` and `pam_unix` contend on, so a
      concurrent password change cannot be silently lost
- [x] Stale lock detection only on `ESRCH` (not `EPERM`), with a bounded wait
      rather than a spin when a stale lock cannot be removed
- [x] Signal blocking during file writes (#38 — `SignalBlocker` RAII), scoped to
      the critical section and dropped before long-running work
- [x] O_CLOEXEC on file descriptors (#50)
- [x] Umask reset (#51 — `UmaskGuard` RAII), `!Send`/`!Sync` via
      `PhantomData<Rc<()>>`

### Secrets

- [x] PAM delegation (no custom password hashing)
- [x] Password strings zeroed via `zeroize`, including the PAM buffers
- [x] `chpasswd` refuses an empty plaintext password, and stores the password
      exactly as supplied instead of trimming it
- [x] Hashing happens before the `/etc/shadow` lock is taken, so a batch of slow
      hashes no longer holds the lock with signals blocked
- [x] Core dumps suppressed with `PR_SET_DUMPABLE` **and** `RLIMIT_CORE=0` — the
      limit alone is ignored when cores are piped to a handler
- [x] Resource limit hardening (#44 — `raise_file_size_limit()`)

### Sandboxing and environment

- [x] Landlock filesystem restriction (#41) on the paths that read and write the
      shadow file directly. Deliberately **not** applied around a PAM
      conversation: `restrict_self` sets `no_new_privs`, which strips the setgid
      bit from `unix_chkpwd` and blocks `dlopen` of the PAM modules
- [x] Absolute paths for subprocess execution (`/usr/sbin/nscd`)
- [x] Environment sanitization for spawned children (#40 — `sanitized_env()`)
- [x] Targeted hardening in `newgrp` (no `RLIMIT_FSIZE` leak to the exec'd shell)
- [x] Centralized hardening in `shadow_core::hardening` (deduplicated across
      tools)

## Not yet implemented

### Terminal echo after an interrupt

Ctrl-C at a password prompt terminates without unwinding, so the `EchoGuard`
destructor does not run and the terminal is left with echo disabled. Blocking
`SIGINT`/`SIGQUIT`/`SIGTSTP` for the duration of the read — `readpassphrase(3)`
semantics — would fix it in one shared helper. Tracked in #248.

### Seccomp-BPF

Restrict syscalls to only what `passwd` needs after initialization. Complex but
effective — sudo-rs uses this approach.

### Process environment

`harden_process()` builds a sanitized environment for children but does not
modify the process's own; in-process PAM and NSS modules still see the caller's
environment. Tracked in #249.

## References

- OpenBSD pledge(2): https://man.openbsd.org/pledge.2
- OpenBSD unveil(2): https://man.openbsd.org/unveil.2
- Linux landlock: https://docs.kernel.org/userspace-api/landlock.html
- Linux seccomp: https://man7.org/linux/man-pages/man2/seccomp.2.html
- lckpwdf(3): https://man7.org/linux/man-pages/man3/lckpwdf.3.html
- sudo-rs security: https://github.com/trifectatechfoundation/sudo-rs
