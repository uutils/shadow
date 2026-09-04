# chage(1) - change user password expiry information

## NAME

chage - change user password expiry information

## SYNOPSIS

**chage** [*options*] *LOGIN*

## DESCRIPTION

The **chage** command changes the password aging fields of a user account:
when the password was last changed, how long it may be kept, when the account
itself expires. The fields live in /etc/shadow (see **shadow**(5)) and are
counted in **days since 1970-01-01**, not in dates.

**chage -l** prints those fields in a readable form and is the only mode a
normal user may run, and only for their own account. Every other mode requires
the superuser.

## OPTIONS

**-d**, **--lastday** *LAST_DAY*
:   Record *LAST_DAY* as the date of the last password change. Accepts
    **YYYY-MM-DD** or a number of days since the epoch. **-1** clears the
    field. A last day of **0** forces a password change at the next login.

**-E**, **--expiredate** *EXPIRE_DATE*
:   Expire the account on *EXPIRE_DATE*, in the same two forms. **-1** removes
    the expiry. An expired account is refused a login even with a valid
    password.

**-I**, **--inactive** *INACTIVE*
:   Disable the account *INACTIVE* days after its password expires. **-1**
    removes the inactivity period.

**-l**, **--list**
:   Print the aging information. Cannot be combined with any field option.

**-m**, **--mindays** *MIN_DAYS*
:   Require at least *MIN_DAYS* between password changes. **0** allows a change
    at any time; **-1** clears the field.

**-M**, **--maxdays** *MAX_DAYS*
:   Require a password change at least every *MAX_DAYS*. **-1** clears the
    field. See the note on 10000 below.

**-P**, **--prefix** *PREFIX_DIR*
:   Read and write the account files under *PREFIX_DIR* instead of /etc.
    Only the superuser may use this option.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory. Only the superuser may use
    this option.

**-W**, **--warndays** *WARN_DAYS*
:   Warn the user *WARN_DAYS* before the password expires. **-1** clears the
    field.

**--help**
:   Print a usage summary and exit.

**--version**
:   Print the version and exit.

## VALUE RESTRICTIONS

Every day count is either a non-negative number or **-1**, which clears the
field. A value such as **-5** is rejected rather than written: a negative
aging field is not a policy any reader can act on, and it would silently change
how the account behaves.

A date that does not exist is rejected rather than rolled over: **2025-02-29**
and **2025-04-31** are errors, not 1 March and 1 May.

## THE -l OUTPUT

```
Last password change                                    : Jan 01, 2026
Password expires                                        : Apr 01, 2026
Password inactive                                       : May 01, 2026
Account expires                                         : never
Minimum number of days between password change          : 0
Maximum number of days between password change          : 90
Number of days of warning before password expires       : 7
```

Two rules govern what appears in place of a date:

**A last change of 0** is the "must change at next login" marker that
**passwd -e** writes. It is not a date, and it makes the two dates derived from
it meaningless as well, so the first three lines all read *password must be
changed*. The account expiry is a separate field and keeps its own value.

**A maximum age of 10000 days or more** disables password expiry: the password
and inactive lines read *never*. A maximum of 9999 still produces a date.

An unset field prints *never* on a date line and **-1** on a day-count line.
A field holding a value too large to be a date -- anything with write access to
/etc/shadow can put one there -- also prints *never* rather than an arithmetic
artefact.

## EXIT STATUS

**0**
:   Success.

**1**
:   Permission denied, or the login does not exist.

**2**
:   Invalid command syntax, or an out-of-range value.

**3**
:   An unexpected failure.

**5**
:   /etc/shadow is locked by another process.

**15**
:   /etc/shadow could not be read. This code is for the *file*; a missing
    *account* is exit 1.

## FILES

/etc/passwd
:   User account information.

/etc/shadow
:   Password aging fields.

## EXAMPLES

Show what a password policy currently is:

```
$ chage -l ada
```

Require a change every 90 days, with a week of warning, and force one now:

```
# chage -M 90 -W 7 -d 0 ada
```

Retire an account on a date without deleting it:

```
# chage -E 2026-12-31 contractor
```

Remove every aging restriction:

```
# chage -m -1 -M -1 -W -1 -I -1 -E -1 ada
```

## SEE ALSO

passwd(1), passwd(5), shadow(5), usermod(8)
