# vipw(8) - edit the password, group, shadow or gshadow file

## NAME

vipw, vigr - edit the password, group, shadow or gshadow file

## SYNOPSIS

**vipw** [*options*]

**vigr** [*options*]

## DESCRIPTION

The **vipw** and **vigr** commands edit /etc/passwd and /etc/group
respectively. With the **-s** flag they edit the shadow versions of those
files, /etc/shadow and /etc/gshadow. The two are one program: **vigr** is
**vipw** with the group file as its default.

The point of using them rather than an editor directly is the lock. **vipw**
takes the same lock every other tool in the suite takes, so a hand edit
cannot interleave with a **useradd**(8) running at the same moment — the other
tool waits — and the result is installed atomically, so a crash mid-write
cannot leave a half-written /etc/passwd.

The editor is taken from **VISUAL**, then **EDITOR**, then **vi**. The string
goes through the shell, so `EDITOR="emacs -nw"` works. Signals such as Ctrl-C
reach the editor normally; they do not reach **vipw**, which would otherwise
die holding the lock.

## HOW AN EDIT PROCEEDS

1. The lock is taken and the file copied to a working copy beside it,
   `/etc/passwd.edit`, with the same mode and ownership. A stale copy from a
   crashed run is replaced.
2. The editor runs on the working copy.
3. If the editor exits with an error, the working copy is removed and nothing
   is installed.
4. If the working copy is identical to the original, nothing is installed and
   *file is unchanged* is reported.
5. The working copy is parsed as the file it is meant to be. If it does not
   parse, it is **kept**, its location is printed, and the live file is left
   alone.
6. Otherwise the working copy's bytes are installed as they are — comments and
   blank lines included — and the companion file that usually has to change
   alongside is named.

## OPTIONS

**-g**, **--group**
:   Edit the group database.

**-p**, **--passwd**
:   Edit the passwd database.

**-s**, **--shadow**
:   Edit the shadow counterpart of the selected database.

**-q**, **--quiet**
:   Do not report an unchanged file or suggest the companion edit.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in *CHROOT_DIR* and use its configuration files.

**-P**, **--prefix** *PREFIX_DIR*
:   Edit the account files under *PREFIX_DIR* without chrooting.

## DIFFERENCES FROM GNU SHADOW

**The result is checked before it is installed.** GNU **vipw** installs
whatever the editor saved — a line with no colons, or a UID 0 account with an
empty password field — and leaves **pwck**(8) to find it later. Here a file the
rest of the suite could not parse is refused. The check is structural: it does
not judge the contents, and **pwck**(8) and **grpck**(8) remain the tools for
that. When it refuses, the edited copy is kept rather than discarded: an
administrator whose ten minutes of work vanished would use a raw editor next
time, which is the outcome this tool exists to prevent.

**Changes are detected by content, not by timestamp.** GNU compares
modification times in whole seconds, so an edit saved within the same second
as the copy was made is silently thrown away. Any edit that changes a byte is
installed here.

## EXIT STATUS

**0**
:   The file was installed, or was unchanged.

**1**
:   The editor failed, the result did not parse, the lock could not be taken,
    or the caller is not root. Nothing was installed.

**2**
:   Invalid command syntax.

**3**
:   The **--root** directory could not be entered.

## ENVIRONMENT

**VISUAL**, **EDITOR**
:   The editor, in that order of preference. An empty value counts as unset.

## FILES

/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow
:   The files edited.

/etc/passwd.edit *and so on*
:   The working copy, beside the file it copies. Left in place only when the
    edit was refused.

## SEE ALSO

group(5), grpck(8), passwd(5), pwck(8), shadow(5), useradd(8)
