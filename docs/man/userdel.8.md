# userdel(8) - delete a user account

## NAME

userdel - delete a user account and related files

## SYNOPSIS

**userdel** [*options*] *LOGIN*

## DESCRIPTION

The **userdel** command modifies the system account files, deleting all
entries that refer to the user name *LOGIN*. The named user must exist.

The user's entry is removed from /etc/passwd and /etc/shadow. The user
is also removed from membership lists in /etc/group and /etc/gshadow.

## OPTIONS

**-f**, **--force**
:   With **-r**, remove the home directory even if it is not owned by the user or
    is shared with another account, and the mail spool even if it is not owned by
    the user. A user that does not exist is still exit
    status 6.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths.

**-r**, **--remove**
:   Remove the user's home directory and mail spool. A home that is a btrfs
    subvolume, as **useradd --btrfs-subvolume-home** makes, is removed with it,
    and *Delete subvolume ID (commit): 'HOME'* is printed on standard output once
    the removal is committed, as upstream prints it. On a kernel older than 6.10,
    which does not tell the subvolume's ID, the line is not printed.

    A mail spool or home that is not there is not an error: *LOGIN mail spool
    (PATH) not found* and *LOGIN home directory (PATH) not found* are printed on
    standard error, in that order, and the exit status is unchanged.

    A mail spool the user does not own is kept unless **-f** is given: *SPOOL not
    owned by LOGIN, not removing* is printed on standard error, the home is still
    removed, and the exit status is 12. A spool that is a symbolic link is judged
    by the file it points to; the link is what is removed, never that file.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

**-Z**, **--selinux-user**
:   Remove the SELinux user mapping of the account by running **semanage login**.
    On a kernel without SELinux the exit status is 3, before anything else. If
    **semanage** is missing or fails it is 1, with the account removed. It cannot be
    used with **-P**.

## EXIT STATUS

**0**
:   Success.

**1**
:   Cannot update password file.

**2**
:   Invalid command syntax.

**6**
:   The user does not exist.

**10**
:   Cannot update group file.

**12**
:   Cannot remove home directory.

## FILES

/etc/passwd
:   User account information.

/etc/shadow
:   Secure user account information.

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

## SEE ALSO

useradd(8), usermod(8), groupdel(8)
