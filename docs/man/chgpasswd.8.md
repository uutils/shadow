# chgpasswd(8) - update group passwords in batch mode

## NAME

chgpasswd - update group passwords in batch mode

## SYNOPSIS

**chgpasswd** [*options*]

## DESCRIPTION

The **chgpasswd** command reads a list of group and password pairs from
standard input and uses it to update a set of existing groups. It is
**chpasswd**(8)'s counterpart for groups.

Each line is of the form:

```
group_name:password
```

Only the first colon separates the two fields, so a password may itself
contain colons — though one written into /etc/gshadow would split the line and
corrupt the file, and is refused.

By default the supplied passwords are in clear text and are hashed before
being stored. The scheme comes from **ENCRYPT_METHOD** in /etc/login.defs, so
group passwords are hashed the same way as everything else on the host.

## ALL OR NOTHING

Every line is parsed, every named group is resolved, and every password is
hashed **before** any file is written. A batch naming one group that does not
exist changes nothing at all, rather than applying the lines before the bad
one and stopping.

The account files are then written in one locked transaction, so a concurrent
**gpasswd**(1) or **groupmod**(8) cannot interleave with it.

## WHERE THE PASSWORD IS STORED

On a system with /etc/gshadow, the hash is written there and the group's
password field in /etc/group is set to `x`, which is what marks the password
as living in the shadowed file. /etc/group is world-readable; /etc/gshadow is
not.

On a system without /etc/gshadow, the hash is written into /etc/group itself.
**chgpasswd** does not create a gshadow file: doing so would change how every
other tool on the host reads group passwords.

A group present in /etc/group with no /etc/gshadow line gets one, carrying the
membership /etc/group already records.

## OPTIONS

**-c**, **--crypt-method** *METHOD*
:   Use *METHOD* to hash the passwords instead of the configured default.
    Supported: **SHA256**, **SHA512**, **YESCRYPT**.

**-e**, **--encrypted**
:   The supplied passwords are already hashed and are stored verbatim. This is
    the only mode that may write an empty field, which is how a group password
    is cleared.

**-m**, **--md5**
:   Rejected. See DIFFERENCES FROM GNU SHADOW below.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in *CHROOT_DIR* and use its configuration files.

**-s**, **--sha-rounds** *ROUNDS*
:   Iteration count for the SHA-2 schemes. Requires **-c**: a rounds count
    without a scheme that takes one is meaningless, and ignoring it silently
    would write a password the caller did not ask for.

**-P**, **--prefix** *PREFIX_DIR*
:   Read and write the account files under *PREFIX_DIR* without chrooting.

## DIFFERENCES FROM GNU SHADOW

**-m** and **-c MD5**, and **-c DES**, are refused rather than honoured. Both
schemes are broken, and a group password hashed with either is worth little
more than none at all.

**-c NONE** is refused. GNU accepts it and stores the password as clear text
in /etc/gshadow. If a field really is to be written verbatim, **-e** does that
explicitly.

An empty password in plaintext mode is refused: hashing an empty string
produces a valid hash that a bare Enter matches, which is a group anyone can
enter, not a group with no password.

## EXIT STATUS

**0**
:   Success. Empty input succeeds having done nothing.

**1**
:   The passwords could not be changed. Nothing was written.

**2**
:   Invalid command syntax.

**3**
:   The **--root** directory could not be entered.

## FILES

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

/etc/login.defs
:   Shadow password suite configuration, read for **ENCRYPT_METHOD**.

## EXAMPLES

Set one group password:

```
# echo 'staff:correct horse battery staple' | chgpasswd
```

Apply a batch from a file, choosing the scheme:

```
# chgpasswd -c SHA512 < group-passwords.txt
```

Clear a group's password:

```
# echo 'staff:' | chgpasswd -e
```

## SEE ALSO

chpasswd(8), gpasswd(1), group(5), gshadow(5), login.defs(5), newgrp(1), sg(1)
