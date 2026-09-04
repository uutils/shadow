# chpasswd(8) - update passwords in batch mode

## NAME

chpasswd - update passwords in batch mode

## SYNOPSIS

**chpasswd** [*options*]

## DESCRIPTION

The **chpasswd** command reads a list of *user*:*password* pairs from standard
input and applies them to /etc/shadow. It is the tool for provisioning: one
invocation sets any number of passwords, and either all of them are written or
none are.

Only the superuser may run it.

By default the passwords are plaintext and are hashed before being stored. With
**-e** they are already-hashed fields and are stored verbatim.

## INPUT FORMAT

One pair per line:

```
alice:a long passphrase
bob:another one
```

The username is everything before the **first** colon; the password is
everything after it, **verbatim**. Trailing whitespace is part of the password.
A password containing a colon needs no quoting or escaping, because only the
first colon separates. Blank lines are skipped. A line with no colon, or with
an empty username, is an error.

An empty plaintext password is refused. Hashing an empty string produces a
perfectly valid hash, and the account would then accept a bare ENTER as its
password. Locking an account is what **passwd -l** is for. With **-e** an empty
field is allowed, since that is how `!` and `*` style locks are written.

## OPTIONS

**-c**, **--crypt-method** *METHOD*
:   Hash with *METHOD*: **SHA256**, **SHA512** or **YESCRYPT**. Overrides the
    system default. **MD5** and **DES** are refused rather than silently
    downgraded.

**-e**, **--encrypted**
:   The supplied passwords are already hashed and are stored as given. Mutually
    exclusive with **-c** and **-m**.

**-m**, **--md5**
:   Refused. MD5 is not a usable password hash; use **-c SHA512**.

**-P**, **--prefix** *PREFIX_DIR*
:   Read and write the account files under *PREFIX_DIR* instead of /etc.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

**-s**, **--sha-rounds** *ROUNDS*
:   Iteration count for the SHA-2 schemes. Requires **-c**: a rounds count
    without a scheme names nothing, and ignoring it would write a password the
    caller did not ask for. Not accepted with YESCRYPT, which takes no rounds
    parameter.

**--help**
:   Print a usage summary and exit.

**--version**
:   Print the version and exit.

## CONFIGURATION

The default hashing scheme is **ENCRYPT_METHOD** from /etc/login.defs, which is
how a distribution chooses one for the whole system. Debian and its derivatives
set YESCRYPT. **-c** overrides it for one run.

If /etc/login.defs is unreadable, names no method, or names one this build will
not write, SHA-512 is used. A misconfigured file does not stop a password
change.

## HOW A BATCH IS APPLIED

The passwords are hashed **before** the /etc/shadow lock is taken. A modern
hash is deliberately slow, and hashing under the lock would hold it, with
signals blocked, for as long as the whole batch took.

Every account named in the input is then resolved before any of them is
written. An unknown login anywhere in the batch aborts the run with the file
untouched, rather than applying the first half of a list. The file is replaced
atomically, so a reader either sees all the changes or none.

## EXIT STATUS

**0**
:   Success.

**1**
:   Permission denied, malformed input, an unknown login, or a failure to read
    or write /etc/shadow.

**2**
:   Invalid command syntax.

## FILES

/etc/shadow
:   Hashed passwords.

/etc/login.defs
:   Read for **ENCRYPT_METHOD**.

## EXAMPLES

Set several passwords at once:

```
# chpasswd <<'EOF'
alice:correct horse battery staple
bob:a different passphrase
EOF
```

Restore hashes taken from a backup, unchanged:

```
# chpasswd -e < hashes.txt
```

Choose the scheme and cost explicitly:

```
# echo 'alice:a long passphrase' | chpasswd -c SHA512 -s 100000
```

## SEE ALSO

passwd(1), login.defs(5), shadow(5), useradd(8)
