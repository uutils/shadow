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

Files with no problem produce no output. After an error, **pwck** prints
*pwck: no changes* on standard output, with **-q** as well, and exits 2; the files
are not rewritten. A warning alone does neither. There is no check on the size of
an ID: **nobody** at 65534 is not a problem.

## OPTIONS

**-q**, **--quiet**
:   Report only errors, suppress warnings.

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

Problems are reported on standard error, where upstream uses standard output, and
in a shorter form: a duplicate entry gets one line, without upstream's offer to
delete it. With **-q** a primary group that does not exist is still a problem,
exit 2; upstream reports nothing and exits 0. **-b**/**--badname** is not
implemented, and is refused as an unknown option, exit 1.

## FILES

/etc/passwd
:   User account information.

/etc/shadow
:   Secure user account information.

/etc/group
:   Group account information.

## SEE ALSO

passwd(5), shadow(5), grpck(8)
