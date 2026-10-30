# groupadd(8) - create a new group

## NAME

groupadd - create a new group

## SYNOPSIS

**groupadd** [*options*] *GROUP*

## DESCRIPTION

The **groupadd** command creates a new group account using the values
specified on the command line plus the default values from the system.
The new group will be entered into the system files (/etc/group and
/etc/gshadow) as needed.

## OPTIONS

**-f**, **--force**
:   Exit successfully if the group already exists, and cancel **-g** if
    the GID is already used (a new GID will be allocated instead).

**-g**, **--gid** *GID*
:   Use *GID* for the new group. **4294967295** is refused with exit status 3:
    it is (gid_t)-1, which **chown**(2) and **setresgid**(2) take as "no change".

**-K**, **--key** *KEY=VALUE*
:   Override /etc/login.defs defaults (GID_MIN, GID_MAX, SYS_GID_MIN,
    SYS_GID_MAX). Can be specified multiple times.

**-o**, **--non-unique**
:   Allow creating a group with a non-unique (duplicate) GID.

**-p**, **--password** *PASSWORD*
:   Set the encrypted password for the new group.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths.

**-r**, **--system**
:   Create a system group (allocated from the system GID range defined
    in /etc/login.defs). GIDs are handed out from the top of the range down:
    one below the lowest system GID in use, starting at **SYS_GID_MAX**, and the
    highest free one when that reaches the bottom.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

**-U**, **--users** *USERS*
:   Make the listed users (comma-separated) members of the new group, in
    /etc/group and /etc/gshadow. Every name has to be an existing user, from
    /etc/passwd or the name service, or under *PREFIX_DIR* with **-P**. Otherwise
    the exit status is 10 and no group is created. An empty name is not a user:
    an empty list and a stray comma are refused too.

## EXIT STATUS

**0**
:   Success.

**2**
:   Invalid command syntax.

**3**
:   Invalid argument to option.

**4**
:   GID already in use (and no **-o** or **-f**).

**9**
:   Group name already in use.

**10**
:   Cannot update group file, or a name given to **-U** is not a user.

## DIFFERENCES FROM UPSTREAM SHADOW

**-p** with a password that would break the file, one with a colon or a newline,
exits 10 like upstream and writes nothing. Upstream leaves the new group in
/etc/group with no entry in /etc/gshadow.

## FILES

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

/etc/login.defs
:   Shadow password suite configuration.

## SEE ALSO

groupdel(8), groupmod(8), login.defs(5)
