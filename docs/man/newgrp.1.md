# newgrp(1) - log in to a new group

## NAME

newgrp - log in to a new group

## SYNOPSIS

**newgrp** [**-**] [*group*]

## DESCRIPTION

The **newgrp** command starts a new shell with *group* as the primary group.
Files the user creates in that shell belong to *group* without any need to
change permissions afterwards, which is the usual reason to run it.

With no *group*, the shell is started with the user's own primary group from
/etc/passwd, undoing an earlier **newgrp**.

The shell comes from the user's /etc/passwd record, never from **$SHELL**:
**newgrp** is installed setuid-root, and an environment variable is the
caller's to choose. Privileges are dropped to the caller's own user before the
shell is started, and the supplementary group list is rebuilt from scratch so
no membership leaks across the change.

**newgrp** replaces the current shell rather than nesting one inside it. Leave
the new group by exiting that shell.

## THE - OPERAND

A bare **-** as the first operand reinitializes the environment as though the
user had just logged in: the shell is a login shell, the working directory
becomes the home directory, and the environment is rebuilt with **HOME**,
**SHELL**, **USER**, **LOGNAME** and **PATH**. Terminal and locale settings
(**TERM**, **LANG**, **LC_**\*) are carried over, as they are at a real login.

Without **-**, the environment and the working directory are kept exactly as
they are, and the shell is **not** a login shell. This matters: a login shell
re-reads the profile files, so making every **newgrp** a login shell would run
them again, in an environment they had already been applied to, on each
invocation.

The **-** may only appear first, and only once. Anything else is a usage error
rather than a group named `-`.

## PERMISSIONS

A user may enter a group without a password if it is their primary group in
/etc/passwd, or if they are listed as a member of it in /etc/group.

Otherwise the group's password from /etc/gshadow is required, and the user is
prompted for it. A group whose password field is empty, `!`, `!!` or `*` has no
usable password, so a non-member is refused outright: those values mean "no
password access", not "no password needed".

Membership is read from /etc/group and the password from /etc/gshadow. The
member list in /etc/gshadow does not by itself grant access, matching the
behaviour of the shadow suite this replaces.

The superuser may enter any group without a password.

## OPERANDS

**-**
:   Reinitialize the environment as at login. Must come first.

*group*
:   The group to switch to. Defaults to the user's primary group.

## EXIT STATUS

**0**
:   Never returned on success: the process is replaced by the shell.

**1**
:   Usage error, unknown group, permission denied, wrong password, or the shell
    could not be started.

## FILES

/etc/passwd
:   User account information, including the shell and primary group.

/etc/group
:   Group membership.

/etc/gshadow
:   Group passwords.

## EXAMPLES

Work in the `docker` group for a while:

```
$ newgrp docker
$ id -gn
docker
$ exit
```

Start clean, as at login:

```
$ newgrp - docker
```

Go back to your own primary group:

```
$ newgrp
```

## SEE ALSO

group(5), gshadow(5), login(1), sg(1)
