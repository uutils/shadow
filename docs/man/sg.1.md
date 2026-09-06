# sg(1) - execute a command as a different group

## NAME

sg - execute a command as a different group

## SYNOPSIS

**sg** *group* [[**-c**] *command*]

## DESCRIPTION

The **sg** command runs *command* with *group* as the primary group. Files the
command creates belong to *group* without any need to change permissions
afterwards, which is the usual reason to run it.

**sg** is **newgrp**(1) for a single command. The two decide who may enter a
group by the same rules, move the process into it the same way, and differ only
in what follows: **newgrp** replaces the caller's shell and leaves them in the
new group until they exit it, while **sg** runs one command and is done. On
systems shipping the GNU shadow suite the two are the same binary, reached
through a symlink.

With no *command*, **sg** starts a shell, behaving as **newgrp** does.

The command is run by the shell named in the caller's /etc/passwd record, never
by **$SHELL**: **sg** is installed setuid-root, and an environment variable is
the caller's to choose. Privileges are dropped to the caller's own user before
the command is started.

The supplementary group list is rebuilt from the caller's own memberships, with
the group they started in added to it. Keeping that group is what stops the
switch from costing them access to their own files.

**sg** changes the group and nothing else. The user, the environment and the
working directory are the caller's throughout; it is not **su**(1).

## THE -c OPERAND

**-c** is optional and has no effect: `sg staff -c 'id -gn'` and
`sg staff 'id -gn'` are the same request. It is accepted because the GNU tool
accepts it, and scripts written against that tool pass it.

*command* is a single operand, so a command of more than one word must be
quoted. It is handed to the shell, which means shell syntax — pipes,
redirections, `&&` — works inside it. Operands after *command* are ignored.

## PERMISSIONS

A user may enter a group without a password if it is their primary group in
/etc/passwd, or if they are listed as a member of it in /etc/group.

Otherwise the group's password from /etc/gshadow is required, and the user is
prompted for it. A group whose password field is empty, `!`, `!!` or `*` has no
usable password, and a non-member is refused: those values mean "no password
access", not "no password needed".

The prompt appears either way. Refusing such a group without asking would be
quicker, but the presence or absence of a prompt would then tell any caller
which groups have passwords set, and that is a list of the ones worth
attacking.

Being named an administrator of a group in /etc/gshadow does not by itself
grant entry. An administrator may add themselves to the group with
**gpasswd**(1), and is then a member like any other.

The superuser may enter any group without a password.

## OPERANDS

*group*
:   The group to run the command in. Defaults to the caller's primary group.

**-c**
:   Optional, and ignored. Accepted for compatibility.

*command*
:   The command to run, as a single operand. Defaults to starting a shell.

## EXIT STATUS

**sg** replaces itself with the shell that runs *command*, so the status the
caller sees is the command's own — including the shell's **127** for a command
that could not be run. A script may test it exactly as if it had run the
command directly.

**1**
:   Unknown group, permission denied, wrong password, or the shell could not be
    started.

## FILES

/etc/passwd
:   User account information, including the shell and primary group.

/etc/group
:   Group membership.

/etc/gshadow
:   Group passwords.

## EXAMPLES

Create a file owned by the `staff` group:

```
$ sg staff -c 'touch report.txt'
$ ls -l report.txt
-rw-r--r-- 1 alice staff 0 Sep  6 11:04 report.txt
```

Check which group a command would run in:

```
$ sg docker 'id -gn'
docker
```

The command's exit status is the caller's:

```
$ sg staff -c 'test -w /srv/shared'
$ echo $?
0
```

## SEE ALSO

group(5), gshadow(5), gpasswd(1), newgrp(1)
