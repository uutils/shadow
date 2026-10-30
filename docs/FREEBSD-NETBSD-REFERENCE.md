# FreeBSD/NetBSD Security Reference for shadow-rs

Analysis of FreeBSD's `pw` and NetBSD's user management implementations.
Both BSD-2-Clause licensed — safe to reference.

## FreeBSD `pw` Patterns

### What FreeBSD Does Differently

| Pattern | FreeBSD | shadow-rs | Action |
|---------|---------|-----------|--------|
| Username allows trailing `$` | Yes (Samba compat) | No | Consider adding for Samba/AD |
| Salt generation | `arc4random_uniform()` | PAM handles | N/A (PAM delegates hashing) |
| Password fd input (`-h FD`) | Yes | No | Low priority — niche use case |
| Password buffers not zeroed | Vulnerable | Fixed (zeroize) | We're ahead |
| No mlock() on passwords | Vulnerable | Not implemented | Future work |
| Selective config override | Sentinel values (-1) | Login.defs defaults | Already implemented |

### Key Takeaway

FreeBSD's `pw` is less hardened than OpenBSD's `passwd` — no explicit memory
zeroing, no mlock, no pledge/unveil equivalent. Our implementation with
`zeroize`, core dump suppression, and environment sanitization is already
ahead of FreeBSD's security posture.

### Patterns Worth Adopting

1. **Samba-compatible usernames**: Allow trailing `$` in usernames for
   Active Directory machine accounts. This is a common real-world need.

2. **Password input via fd**: The `-h FD` pattern allows passing passwords
   from a pipe without command-line exposure. Lower priority but useful for
   automation.

3. **mlock() for password buffers**: Neither FreeBSD nor our implementation
   uses `mlock()` to prevent password data from being swapped to disk.
   OpenBSD doesn't either (they rely on encrypted swap). Consider adding
   as defense-in-depth.

## NetBSD Patterns

NetBSD's user management follows similar patterns to FreeBSD. Key
differences:

- Uses `vipw(8)` for direct passwd editing (different approach)
- Stricter POSIX compliance in username validation
- Similar lack of memory hardening

## Recommendations for shadow-rs

All high-value items from BSD review are already tracked:

- **mlock()**: Future work (docs/SECURITY-HARDENING.md)
- **Samba usernames**: Could add `--badname` flag (matches upstream `useradd --badname`)
- **Password fd input**: Low priority feature

No critical security gaps found relative to FreeBSD/NetBSD implementations.
shadow-rs is already more hardened than both.

## References

- FreeBSD pw: https://cgit.freebsd.org/src/tree/usr.sbin/pw/
- NetBSD user management: https://cvsweb.netbsd.org/bsdweb.cgi/src/usr.sbin/user/
