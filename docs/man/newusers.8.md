# newusers(8) - create or update users in batch

## NAME

newusers - create or update users in batch

## SYNOPSIS

**newusers** [*options*]

## DESCRIPTION

The **newusers** command reads a file of user account descriptions from
standard input and uses it to create new accounts, or to update accounts that
already exist. Each line is of the form:

```
pw_name:pw_passwd:pw_uid:pw_gid:pw_gecos:pw_dir:pw_shell
```

Exactly seven fields, the same as a line of /etc/passwd, with the plaintext
password where the placeholder would be. Six fields or eight are both an
invalid line: one lost to a stray colon would describe a different account than
the one intended.

For each line **newusers** writes the /etc/passwd record, a hashed /etc/shadow
record, a group where one is needed, and the home directory.

## ALL OR NOTHING

Every line is parsed, every name validated, every group resolved and every
password hashed **before** any file is written. A batch with one bad line
leaves the system exactly as it was, including for the good lines above it.

That is the property that makes it safe to feed this tool a generated file:
the failure mode is "nothing happened", not "the first two hundred accounts
exist and the rest do not".

The account files are then written in one locked transaction. Home directories
are created afterwards: a directory that cannot be created is worth reporting,
but the accounts are already correct, and undoing them would be a larger
surprise than a missing directory.

## FIELDS

*pw_name*
:   The login name. An existing account of that name is updated rather than
    refused.

*pw_passwd*
:   The password, in clear text. It is hashed with the scheme from
    **ENCRYPT_METHOD** in /etc/login.defs unless **-c** names another. This
    field may not be empty; see DIFFERENCES FROM GNU SHADOW.

*pw_uid*
:   Empty to allocate one from the range in /etc/login.defs. On an account
    that already exists, empty keeps the ID it has -- reallocating would orphan
    every file the account owns.

*pw_gid*
:   Empty for a group of the user's own, created if it is not already there.
    A number names a group directly, and one is created carrying the user's
    name if no group has that ID. A name must already exist.

*pw_gecos*, *pw_dir*, *pw_shell*
:   Written as given. An empty *pw_dir* means the account gets no home
    directory; otherwise the directory is created with mode 0700, owned by the
    new account, and /etc/skel is copied into it.

## OPTIONS

**-b**, **--badname**
:   Allow login names that fail the portability rules. The checks that stop a
    name from corrupting the file -- a colon, a newline, a leading `-` -- still
    apply, which is what makes the flag safe to offer. Useful for the
    domain-qualified names a directory join produces.

**-c**, **--crypt-method** *METHOD*
:   Use *METHOD* to hash the passwords. Supported: **SHA256**, **SHA512**,
    **YESCRYPT**.

**-r**, **--system**
:   Create system accounts, allocating from the system ID range.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in *CHROOT_DIR* and use its configuration files.

**-P**, **--prefix** *PREFIX_DIR*
:   Read and write the account files under *PREFIX_DIR* without chrooting.

## DIFFERENCES FROM GNU SHADOW

**An empty password field is refused**, before anything is written. Hashing an
empty string produces a valid hash that a bare Enter matches -- an account
anyone can log into, not an account with no password. GNU passes the empty
field to PAM, which refuses it *after* the account has been created, leaving a
half-made account behind.

**A *pw_gid* naming a group that does not exist is refused.** GNU falls back to
the user's own ID and creates no group at all, so the account is left pointing
at a GID that is not there -- which **grpck**(8) then reports. Naming a group
that is not there is a mistake worth reporting at the time.

**A missing parent directory is created**, as **useradd**(8) does with **-b**.
GNU's **newusers** fails there, which makes it behave differently from GNU's
own **useradd** for the same home path.

**-c NONE**, **-c MD5** and **-c DES** are refused, as they are by
**chpasswd**(8) and **chgpasswd**(8) here.

## EXIT STATUS

**0**
:   Success. Empty input succeeds having done nothing.

**1**
:   The accounts could not be created. Nothing was written.

**2**
:   Invalid command syntax.

**3**
:   The **--root** directory could not be entered.

## FILES

/etc/passwd
:   User account information.

/etc/shadow
:   Secure user account information.

/etc/group
:   Group account information.

/etc/login.defs
:   Shadow password suite configuration: ID ranges and **ENCRYPT_METHOD**.

/etc/skel
:   Skeleton copied into each new home directory.

## EXAMPLES

Create three accounts from a generated file:

```
# newusers < new-accounts.txt
```

where the file holds:

```
alice:correct horse:::Alice Adams:/home/alice:/bin/bash
bob:battery staple:::Bob Brown:/home/bob:/bin/bash
svc-web:generated:::Web service::/usr/sbin/nologin
```

Create service accounts from the system range:

```
# newusers -r < services.txt
```

## SEE ALSO

chgpasswd(8), chpasswd(8), groupadd(8), login.defs(5), passwd(5), useradd(8)
