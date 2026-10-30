# groupmod(8) - modify a group definition

## NAME

groupmod - modify a group definition

## SYNOPSIS

**groupmod** [*options*] *GROUP*

## DESCRIPTION

The **groupmod** command modifies the definition of the specified
*GROUP* by modifying the appropriate entries in the group and gshadow
databases.

## OPTIONS

**-a**, **--append**
:   With **-U**, add the users to the member list instead of replacing it. Use
    only with **-U**; without it the exit status is 2.

**-g**, **--gid** *GID*
:   Change the group ID to *GID*. **4294967295** is refused with exit status 3:
    it is (gid_t)-1, which **chown**(2) and **setresgid**(2) take as "no change".

**-n**, **--new-name** *NEW_GROUP*
:   Change the name of the group to *NEW_GROUP*.

**-o**, **--non-unique**
:   Allow using a non-unique (duplicate) GID when used with **-g**.

**-p**, **--password** *PASSWORD*
:   Change the group password to the encrypted *PASSWORD*.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

**-U**, **--users** *USERS*
:   Set the group's member list (comma-separated), in /etc/group and in
    /etc/gshadow when that file exists.

## EXIT STATUS

**0**
:   Success.

**2**
:   Invalid command syntax.

**3**
:   Invalid argument to option.

**4**
:   GID already in use.

**6**
:   Group does not exist.

**9**
:   Group name already in use.

**10**
:   Cannot update group file.

## DIFFERENCES FROM UPSTREAM SHADOW

**-U** does not check its names: a user that does not exist is written to the
member list, where upstream exits 10 and changes nothing. An empty list clears
the members, where upstream exits 10. **-a** without **-U** is exit 2, where
upstream exits 0.

## FILES

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

## SEE ALSO

groupadd(8), groupdel(8)
