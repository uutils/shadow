# gpasswd(1) - administer /etc/group and /etc/gshadow

## NAME

gpasswd - administer /etc/group and /etc/gshadow

## SYNOPSIS

**gpasswd** [*options*] *group*

## DESCRIPTION

The **gpasswd** command administers `/etc/group` and `/etc/gshadow`.
Every group can have administrators, members, and a password.

System administrators can use the **-A** option to define group
administrator(s) and the **-M** option to define members. They have
all rights of group administrators and members.

**gpasswd** called by a group administrator with a group name only
prompts for the new password of the *group*.

If a password is set the members can still use **newgrp**(1) without a
password, and non-members must supply the password.

This tool is installed setuid-root so that a group administrator (a
user named in the gshadow administrators field) can add and remove
members and change the group password without being root. **-A** and
**-M** remain root-only.

### Notes about group passwords

Group passwords are an inherent security problem since more than one
person is permitted to know the password. However, groups are a useful
tool for permitting co-operation between different users.

## OPTIONS

Except for the **-A** and **-M** options, the options cannot be combined.

**-a**, **--add** *USER*
:   Add *USER* to the named group.

**-d**, **--delete** *USER*
:   Remove *USER* from the named group.

**-A**, **--administrators** *USER,...*
:   Set the list of administrative users. Root only. Requires
    `/etc/gshadow`. An empty list clears the administrators.

**-M**, **--members** *USER,...*
:   Set the list of group members. Root only. An empty list clears
    the members.

**-r**, **--remove-password**
:   Remove the password from the named group. The group password
    will be empty. Only group members will be allowed to use
    **newgrp** to join the named group.

**-R**, **--restrict**
:   Restrict access to the named group. The group password is set
    to "!". Only group members will be allowed to use **newgrp** to
    join the named group.

**-Q**, **--root** *CHROOT_DIR*
:   Locate the system files under *CHROOT_DIR* instead of `/`. Only
    absolute paths are supported. Root only.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths. Root only.

## EXIT STATUS

**0**
:   Success.

**1**
:   Permission denied.

**2**
:   Invalid command syntax.

**3**
:   Invalid argument to option, or specified group doesn't exist.

**10**
:   Can't update group file.

**17**
:   Shadow group file required for **-A**.

## FILES

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

/etc/login.defs
:   Shadow password suite configuration (`ENCRYPT_METHOD`,
    `SHA_CRYPT_MIN_ROUNDS`, `SHA_CRYPT_MAX_ROUNDS`).

## SEE ALSO

newgrp(1), groupadd(8), groupdel(8), groupmod(8), grpck(8), group(5),
gshadow(5)
