# passwd(1) - change user password

## NAME

passwd - change user password

## SYNOPSIS

**passwd** [*options*] [*LOGIN*]

## DESCRIPTION

The **passwd** command changes passwords for user accounts. A normal user
may only change the password for their own account; the superuser may
change the password for any account. **passwd** also changes the account
or associated password validity period.

When invoked without a LOGIN argument, **passwd** changes the password for
the current user. The options that change an account, **-d**, **-l**, **-u**,
**-e**, **-n**, **-x**, **-w** and **-i**, need a LOGIN, for root as well: without
one the exit status is 2.

A change made by **-l**, **-u**, **-d**, **-e** or an aging option prints
*passwd: password changed.* on standard output, unless **-q** is given.

## OPTIONS

**-a**, **--all**
:   Report password status on all accounts. Requires **-S** and no LOGIN.

**-d**, **--delete**
:   Delete the password for the named account. This makes the account
    passwordless.

**-e**, **--expire**
:   Immediately expire the password for the named account. This forces
    the user to change their password at next login.

**-i**, **--inactive** *INACTIVE*
:   Set the number of days of inactivity after a password has expired
    before the account is locked.

**-k**, **--keep-tokens**
:   Change password only if expired.

**-l**, **--lock**
:   Lock the password of the named account. This prepends a '!' to the
    encrypted password, effectively disabling the password.

**-n**, **--mindays** *MIN_DAYS*
:   Set the minimum number of days between password changes.

**-q**, **--quiet**
:   Quiet mode.

**-r**, **--repository** *REPOSITORY*
:   Change the password in *REPOSITORY*. Only *files* is supported, and it changes
    nothing. Anything else is refused, exit status 6, for any caller and before
    anything else is looked at.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory and use the configuration
    files from the *CHROOT_DIR* directory.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths.

**-S**, **--status**
:   Display account status information. The status information consists
    of 7 fields: login name, password status (L=locked, NP=no password,
    P=usable password), date of last password change, minimum age,
    maximum age, warning period, and inactivity period.

**-s**, **--stdin**
:   Read the new password token from standard input.

**-u**, **--unlock**
:   Unlock the password of the named account. This removes one '!' from the front
    of the encrypted password. A field with none is left as it is. If that would
    leave the field empty, nothing is written and the exit status is 3.

**-w**, **--warndays** *WARN_DAYS*
:   Set the number of days of warning before a password change is required.

**-x**, **--maxdays** *MAX_DAYS*
:   Set the maximum number of days a password remains valid.

**-d**, **-u** and **-l** can be combined, in any order. They are applied as
delete, then unlock, then lock, in one write: **-d -l** removes the hash and leaves
the account locked. **-e** and the aging options can go with them. **-S** and **-k**
cannot go with any of these, or with each other.

## EXIT STATUS

**0**
:   Success.

**1**
:   Permission denied or operation failed.

**2**
:   Conflicting options, or a required one missing.

**3**
:   An unexpected failure.

**4**
:   The shadow file is missing.

**5**
:   Password file busy.

**6**
:   An unknown option or an invalid argument to one.

**10**
:   PAM reported an error.

## FILES

/etc/passwd
:   User account information.

/etc/shadow
:   Secure user account information.

## SEE ALSO

chage(1), chpasswd(8), login.defs(5), shadow(5), pwck(8)
