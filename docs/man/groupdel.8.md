# groupdel(8) - delete a group

## NAME

groupdel - delete a group

## SYNOPSIS

**groupdel** [*options*] *GROUP*

## DESCRIPTION

The **groupdel** command modifies the system account files, deleting all
entries that refer to *GROUP*. The named group must exist.

You may not remove the primary group of any existing user, unless you use
**-f**. Otherwise you must remove the user before you remove the group.

## OPTIONS

**-f**, **--force**
:   Delete the group even if it is a user's primary group. A group that does not
    exist is still exit status 6.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

## EXIT STATUS

**0**
:   Success.

**2**
:   Invalid command syntax.

**6**
:   Group does not exist.

**8**
:   Cannot remove a user's primary group.

**10**
:   Cannot update group file.

## FILES

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

## SEE ALSO

groupadd(8), groupmod(8), userdel(8)
