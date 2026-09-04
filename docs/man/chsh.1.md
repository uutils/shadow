# chsh(1) - change login shell

## NAME

chsh - change login shell

## SYNOPSIS

**chsh** [*options*] [*LOGIN*]

## DESCRIPTION

The **chsh** command changes a user's login shell: the program **login**(1)
starts after a successful authentication, held in the last field of the
account's /etc/passwd record (see **passwd**(5)).

With no *LOGIN*, **chsh** operates on the account of the user running it.

If no **-s** option is given, **chsh** prompts for the new shell, showing the
current one in brackets. Pressing ENTER, or repeating the current value, makes
no change and exits successfully.

An empty shell field is not an error: **login** falls back to /bin/sh when the
field is empty, so an empty value selects the system default. Because an empty
answer at the prompt means "keep what I have", the default is selected with
**-s** '' rather than interactively.

## PERMISSIONS

A normal user may only change the login shell of their own account; the
superuser may change it for any account.

**chsh** is normally installed setuid-root, so it establishes *who is asking*
before it writes: a non-root caller must authenticate through the **chsh** PAM
service (typically /etc/pam.d/chsh, where **pam_rootok** admits root and the
system authentication stack prompts everyone else). Authentication happens
after the new shell has been checked and accepted, so a rejected shell never
costs the caller a password prompt.

A build without PAM support cannot verify the caller, so it refuses every
non-root invocation rather than applying an unauthenticated change.

### Restricted accounts

An account whose *current* login shell is not listed in /etc/shells is
restricted (see **shells**(5)) and may not change its shell at all. Without
this rule, an account deliberately confined to a shell kept out of /etc/shells,
such as /bin/rbash, could simply set itself a normal one and escape the
confinement. An account whose shell field is empty is not restricted: the empty
field is the system default, not a confinement.

An account with no /etc/passwd record, or whose record cannot be read, is
treated as restricted.

## OPTIONS

**-l**, **--list-shells**
:   Print the shells listed in /etc/shells, one per line, and exit.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory. Only the superuser may use
    this option: it points a setuid-root program at files of the caller's
    choosing.

**-s**, **--shell** *SHELL*
:   Set the login shell to *SHELL*. See VALUE RESTRICTIONS below.

**--help**
:   Print a usage summary and exit.

**--version**
:   Print the version and exit.

## VALUE RESTRICTIONS

A non-empty shell must be an absolute path and must exist.

A non-root caller must additionally name a shell listed in /etc/shells. If
/etc/shells is missing or contains no entries, only /bin/sh is implicitly
valid. The superuser is not restricted to the list, but the file must still
exist.

The two tests run in that order for a reason. **chsh** is setuid-root, so its
existence check answers with root's view of the filesystem. Were existence
tested first, a distinct "does not exist" reply would turn the program into an
oracle for paths the caller cannot otherwise stat, one probe at a time:

```
$ chsh -s /root/.ssh/id_ed25519
```

Testing the /etc/shells membership first means every unlisted path gets the
same answer whether or not it exists, and that answer discloses nothing:
/etc/shells is world-readable.

## EXIT STATUS

**0**
:   Success, including an interactive run answered with ENTER.

**1**
:   Permission denied, a restricted account, an invalid or unlisted shell, a
    missing account, or a failure to read or write /etc/passwd.

## FILES

/etc/passwd
:   User account information.

/etc/shells
:   List of valid login shells.

/etc/pam.d/chsh
:   PAM service used to authenticate a non-root caller.

## EXAMPLES

List the shells you may choose from:

```
$ chsh -l
/bin/sh
/bin/bash
/usr/bin/zsh
```

Change your own shell without being prompted:

```
$ chsh -s /usr/bin/zsh
```

Change it interactively:

```
$ chsh
Changing the login shell for ada
Enter the new value, or press ENTER for the default
	Login Shell [/bin/bash]: /usr/bin/zsh
```

Give a service account the system default shell, as root:

```
# chsh -s '' backup
```

## SEE ALSO

chfn(1), login(1), passwd(5), shells(5)
