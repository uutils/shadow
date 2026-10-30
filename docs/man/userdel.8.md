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
    is shared with another account. A user that does not exist is still exit
    status 6.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths.

**-r**, **--remove**
:   Remove the user's home directory and mail spool.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

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

## DIFFERENCES FROM UPSTREAM SHADOW

**-Z**/**--selinux-user** is not implemented, and is refused as an unknown
option, exit 2.

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
