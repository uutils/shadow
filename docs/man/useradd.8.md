# useradd(8) - create a new user

## NAME

useradd - create a new user or update default new user information

## SYNOPSIS

**useradd** [*options*] *LOGIN*
**useradd** **-D** [*options*]

## DESCRIPTION

The **useradd** command creates a new user account using the values
specified on the command line plus the default values from the system.
The new user account will be entered into the system files as needed,
the home directory will be created, and initial files copied, depending
on the command line options.

When invoked with the **-D** flag, **useradd** displays or updates the
default values used for creating new accounts.

## OPTIONS

**-b**, **--base-dir** *BASE_DIR*
:   Base directory for the new account's home: without **-d**, the home is
    *BASE_DIR*/*LOGIN*.

**-c**, **--comment** *COMMENT*
:   Set the GECOS field of the new account.

**-d**, **--home-dir** *HOME_DIR*
:   Set the home directory of the new account.

**-D**, **--defaults**
:   Print or change default useradd configuration.

**-e**, **--expiredate** *EXPIRE_DATE*
:   Set the expiration date of the new account (YYYY-MM-DD). **-1** leaves it
    unset.

**-f**, **--inactive** *INACTIVE*
:   Set the password inactivity period of the new account. **-1** leaves it
    unset.

**-g**, **--gid** *GROUP*
:   Set the name or numeric ID of the primary group of the new account.

**-G**, **--groups** *GROUPS*
:   Set the list of supplementary groups of the new account (comma-separated).

**-k**, **--skel** *SKEL_DIR*
:   Specify the skeleton directory (default: /etc/skel).

**-K**, **--key** *KEY=VALUE*
:   Override a value from /etc/login.defs for this run, such as **UID_MIN**. May
    be repeated.

**-m**, **--create-home**
:   Create the user's home directory if it does not exist.

**-M**, **--no-create-home**
:   Do not create the user's home directory.

**-N**, **--no-user-group**
:   Do not create a group with the same name as the user.

**-o**, **--non-unique**
:   Allow creating users with duplicate (non-unique) UIDs. Requires **-u**.

**-p**, **--password** *PASSWORD*
:   Set the encrypted password of the new account.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths.

**-r**, **--system**
:   Create a system account. UIDs are handed out from the top of the system range
    down: one below the lowest system UID in use, starting at **SYS_UID_MAX**,
    and the highest free one when that reaches the bottom.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

**-s**, **--shell** *SHELL*
:   Set the login shell of the new account.

**-u**, **--uid** *UID*
:   Set the user ID of the new account.

**-U**, **--user-group**
:   Create a group with the same name as the user, even if **USERGROUPS_ENAB**
    in /etc/login.defs is *no*. Without **-U**, **-N** or **-g**, that setting
    decides, and it defaults to *yes*. Cannot be used with **-g** or **-N**; the
    exit status is 2.

**--badname**
:   Accept a name that would be refused, deprecated as it is upstream. A name that
    would not fit the file, one with a colon or a newline, is exit status 1.

**-F**, **--add-subids-for-system**
:   Add subordinate IDs for a system account too, which **-r** otherwise skips.

**--btrfs-subvolume-home**
:   With **-m**, make the home a btrfs subvolume. If the directory it goes in is not
    on btrfs the exit status is 12, with the account written. Without **-m** it does
    nothing.

## EXIT STATUS

**0**
:   Success.

**1**
:   Cannot update password file.

**2**
:   Invalid command syntax.

**3**
:   Invalid argument to option.

**4**
:   UID already in use (and no **-o**).

**6**
:   Specified group does not exist.

**9**
:   Username already in use.

**10**
:   Cannot update group file.

**12**
:   Cannot create home directory.

**19**
:   Invalid user name.

## SELINUX

**-Z**/**--selinux-user** *SEUSER* maps the new account to an SELinux user, with
**--selinux-range** *SERANGE* for its MLS range, by running **semanage login**. On a
kernel without SELinux **-Z** is exit status 3, before anything else. If **semanage**
is missing or fails the exit status is 14, with the account written. It cannot be
used with **-P**. **--selinux-range** without **-Z** is exit status 2.

## DIFFERENCES FROM UPSTREAM SHADOW

**--badname ""** is exit status 1. Upstream writes an entry with no name.

## FILES

/etc/passwd
:   User account information.

/etc/shadow
:   Secure user account information.

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

/etc/login.defs
:   Shadow password suite configuration.

/etc/default/useradd
:   Default values for account creation.

/etc/skel
:   Directory containing default files.

## SEE ALSO

userdel(8), usermod(8), groupadd(8), login.defs(5)
