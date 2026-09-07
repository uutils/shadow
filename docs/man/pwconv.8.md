# pwconv(8) - convert to and from shadow passwords and groups

## NAME

pwconv, pwunconv, grpconv, grpunconv - convert to and from shadow passwords
and groups

## SYNOPSIS

**pwconv** [*options*]

**pwunconv** [*options*]

**grpconv** [*options*]

**grpunconv** [*options*]

## DESCRIPTION

The **pwconv** command creates /etc/shadow from /etc/passwd and an optionally
existing /etc/shadow, moving the password hashes out of the world-readable
file. **pwunconv** does the reverse: it merges the hashes back into
/etc/passwd and removes /etc/shadow. **grpconv** and **grpunconv** do the same
for /etc/group and /etc/gshadow.

The four are one program with a selector. Each takes the same lock every other
tool in the suite takes, so nothing can interleave with the conversion, and
writes both files through the same validate-then-write transaction.

## WHAT pwconv DOES

For every line in /etc/passwd:

- A password field that is not `x` is a hash that got into /etc/passwd
  through a tool or an edit that did not know about /etc/shadow. It is moved
  to the shadow line — replacing the hash there if the line already exists,
  and dating the change — and the field is set to `x`.
- A line with no shadow line gets one. The hash is copied as it stands; the
  last-change date is today; and the minimum age, maximum age and warning
  period come from **PASS_MIN_DAYS**, **PASS_MAX_DAYS** and **PASS_WARN_AGE**
  in /etc/login.defs.

A shadow line for an account that no longer has a passwd line is dropped: a
stale line with a live hash is a password nobody can use but anyone with the
file could crack.

A system that is already consistent is left byte for byte alone.

If /etc/shadow did not exist it is created `0640`, owned by root and by the
`shadow` group of the tree being converted, which is how the distributions
ship it. Where that tree has no `shadow` group the file is left `0600 root`.

**grpconv** behaves the same way for the group files. A new /etc/gshadow line
starts with the membership /etc/group records and no administrators.

## WHAT pwunconv DOES

Every account with a shadow line gets that line's hash back in /etc/passwd.
An account with no shadow line keeps whatever /etc/passwd holds. Then
/etc/shadow is removed. Aging information has nowhere to go in /etc/passwd
and is lost, as it is with the GNU tool. A system with no /etc/shadow is
already in the requested state and is left alone.

**grpunconv** behaves the same way for the group files.

## ORDER OF WRITES

**pwconv** writes /etc/shadow before /etc/passwd: the hashes are copied into
the shadow file and only then replaced by `x`. A failure between the two writes
leaves them where they were, rather than nowhere. **pwunconv** writes
/etc/passwd before it removes /etc/shadow: for a moment the hashes exist twice,
which is recoverable, where the other order would have a moment with none.

## OPTIONS

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in *CHROOT_DIR* and use its configuration files.

**-P**, **--prefix** *PREFIX_DIR*
:   Convert the account files under *PREFIX_DIR* without chrooting.

## EXIT STATUS

**0**
:   Success.

**1**
:   The files could not be updated, or the caller is not root.

**2**
:   Invalid command syntax.

**3**
:   The **--root** directory could not be entered.

**5**
:   An account file is locked by another tool. Try again later.

## FILES

/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow
:   The files converted.

/etc/login.defs
:   **PASS_MIN_DAYS**, **PASS_MAX_DAYS** and **PASS_WARN_AGE** for new shadow
    lines.

## SEE ALSO

grpck(8), login.defs(5), pwck(8), shadow(5), gshadow(5)
