# Security Policy

## Scope

shadow-rs reimplements setuid-root tools that write to `/etc/passwd`,
`/etc/shadow`, and `/etc/group`. Security vulnerabilities in this code can
lead to privilege escalation, account takeover, or system lockout.

We take security issues extremely seriously.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via GitHub's private vulnerability
reporting feature:

1. Go to https://github.com/uutils/shadow/security/advisories
2. Click "New draft security advisory"
3. Fill in the details

If private advisory reporting is unavailable, contact the maintainers
directly using a private channel (for example, the email address listed
in a maintainer's GitHub profile). Do not open a public GitHub issue for
security vulnerabilities.

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions / commits
- Impact assessment (privilege escalation, data leak, DoS, etc.)
- Suggested fix (if you have one)

## Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix and disclosure**: coordinated, typically within 30 days

## Supported Versions

Only the latest version on the `main` branch is supported during
pre-1.0 development.

## Security Design Principles

- **Memory safety**: Rust eliminates buffer overflows, use-after-free,
  and uninitialized memory reads
- **Password zeroing**: sensitive data is zeroed in memory via the
  `zeroize` crate before deallocation
- **Atomic file operations**: lock → write tmp → fsync → rename prevents
  partial writes and corruption
- **Stale lock detection**: PID-based detection prevents permanent lockout
  from crashed processes
- **PAM delegation**: password changes go through PAM — we do not implement
  our own password hashing
- **No GPL code**: clean-room implementation prevents license contamination
