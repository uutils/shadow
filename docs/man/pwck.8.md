# pwck(8) - verify integrity of password files

## NAME

pwck - verify integrity of password files

## SYNOPSIS

**pwck** [*options*] [*passwd* [*shadow*]]

## DESCRIPTION

The **pwck** command verifies the integrity of the system authentication
information. It checks that all entries in /etc/passwd and /etc/shadow
have the proper format and contain valid data.

Checks performed include:

- Correct number of fields
- Unique and valid user names
- Valid user and group identifiers
- Valid primary group
- Valid home directory
- Valid login shell
- Matching passwd/shadow entries

Files with no problem produce no output. Each problem gets a line on standard
output, and then **pwck** prints *pwck: no changes*, also on standard output, and
exits 2; the files are not rewritten. A file that cannot be opened is reported on
standard error. There is no check on the size of an ID: **nobody** at 65534 is
not a problem.

## OPTIONS

**-q**, **--quiet**
:   Do not check for a primary group, a home directory or a login shell that does
    not exist, a password field other than *x*, or a last password change in the
    future. None of those is a problem then: nothing is printed for them, and the
    exit status does not change. The other checks stay.

**-r**, **--read-only**
:   Display errors and warnings but do not modify files.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

**-s**, **--sort**
:   Sort entries by UID.

## EXIT STATUS

**0**
:   Success.

**1**
:   Invalid command syntax.

**2**
:   One or more bad password entries.

**3**
:   Cannot open files.

**4**
:   Cannot lock files.

**5**
:   Cannot update files.

**6**
:   Cannot sort files.

## DIFFERENCES FROM UPSTREAM SHADOW

Compared with the **pwck** of Ubuntu 26.04's *passwd* package, 1:4.17.4-2ubuntu3.

**Nothing is repaired.** An entry that is bad or has no match gets one line,
without upstream's offer to delete it or add what is missing. The files are only
rewritten by **-s**.

**Comments and blank lines are not bad entries.** Upstream reports them, and exits
2. Here they are kept, and **-s** moves each with the entry it precedes.

**A relative home or shell is a problem.** Upstream resolves it against the
directory **pwck** runs in, so the answer depends on where that is. Here it is
reported and the exit status is 2, unless **-q** is given.

**-s checks first.** Upstream sorts whatever it finds, exit 0. Here a problem is
reported, the exit status is 2, and nothing is sorted: a line that cannot be parsed
has no place in a sorted file.

**A missing file is not a lock failure.** Nothing is locked unless **-s** is given,
so a *passwd* file that is not there is exit 3 in every mode; upstream exits 4
without **-r**. A *shadow* file that is not there means no shadow file, exit 0.

**A shadow file open to others gets a warning.** With a mode other than 0600 or
0640, **pwck** warns on standard error unless **-q** is given. It is not a problem,
and the exit status does not change. Upstream does not check.

**-b**/**--badname** is not implemented, and is refused as an unknown option,
exit 1.

## FILES

/etc/passwd
:   User account information.

/etc/shadow
:   Secure user account information.

/etc/group
:   Group account information.

## SEE ALSO

passwd(5), shadow(5), grpck(8)
