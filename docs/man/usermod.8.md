# usermod(8) - modify a user account

## NAME

usermod - modify a user account

## SYNOPSIS

**usermod** [*options*] *LOGIN*

## DESCRIPTION

The **usermod** command modifies the system account files to reflect the
changes that are specified on the command line.

## OPTIONS

**-a**, **--append**
:   Append the user to the supplementary group(s) specified by **-G**.
    Use only with the **-G** option.

**-c**, **--comment** *COMMENT*
:   Set the new value of the user's GECOS field.

**-d**, **--home** *HOME_DIR*
:   Set the new home directory for the user. It must be an absolute path. With
    **-u** or **-g**, files in this directory are the ones re-owned, if it
    exists and is the user's. The previous home is left as it is.

**-e**, **--expiredate** *EXPIRE_DATE*
:   Set the account expiration date.

**-f**, **--inactive** *INACTIVE*
:   Set the password inactive period.

**-g**, **--gid** *GROUP*
:   Set the new primary group ID (numeric).

**-G**, **--groups** *GROUPS*
:   Set the list of supplementary groups (comma-separated). If the **-a**
    option is not used, the user is removed from all groups not listed.

**-l**, **--login** *NEW_LOGIN*
:   Change the user's login name.

**-L**, **--lock**
:   Lock the user's password by prepending a '!' to the shadow password.

**-p**, **--password** *PASSWORD*
:   Set the user's password to the specified pre-hashed value. The hash
    must not contain ':', '\\n', or '\\r' characters.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

**-s**, **--shell** *SHELL*
:   Set the new login shell.

**-u**, **--uid** *UID*
:   Set the new numeric user ID. Files in the user's home owned by the old
    UID get the new one, as **-g** does for the old primary group. If part of
    the home could not be changed, the account is still updated and the exit
    status is 12.

**-U**, **--unlock**
:   Unlock the user's password by removing the '!' prefix from the
    shadow password.

## SUBORDINATE IDS

**-v**, **--add-subuids** *FIRST-LAST*
:   Grant the user the subordinate user IDs *FIRST* to *LAST*, inclusive, in
    /etc/subuid. A range the user already holds is not added again. May be
    repeated.

**-V**, **--del-subuids** *FIRST-LAST*
:   Revoke the range. An entry the range covers disappears; one it overlaps is
    trimmed, and one it cuts through the middle of is split, so the IDs on
    either side stay granted. A range the user never held is a no-op.

**-w**, **--add-subgids** *FIRST-LAST*, **-W**, **--del-subgids** *FIRST-LAST*
:   The same for subordinate group IDs and /etc/subgid.

An invalid range — reversed, not two numbers, above 2³²−1 — is refused with
exit status 3 before anything is written. Entries are keyed by the login name
given on the command line and are not renamed by **-l**: a range is a grant to
a name, and an administrator who renames the account re-grants it if that is
what they meant. Because **-V** is this option, **--version** has no short
form.

## EXIT STATUS

**0**
:   Success.

**1**
:   Cannot update password file.

**2**
:   Invalid command syntax.

**3**
:   Invalid argument to an option.

**4**
:   UID already in use.

**6**
:   User or group does not exist.

**9**
:   Login name already in use.

**10**
:   Cannot update the group file.

**12**
:   Cannot re-own the home directory. The account files were written.

## DIFFERENCES FROM UPSTREAM SHADOW

**A hard link to someone else's file keeps its group.** **-g** gives the new
group to whatever in the home is in the old one. A file with more than one name
that the user does not own is left as it is: it is the same inode as the name
its owner keeps it under, and the user may have linked it there. upstream
regroups it. The user's own files change however many names they have.

**A home spelled with a trailing slash is the same home.** A symlinked home is
not walked, exit 12. upstream does the same for */home/bob*, but for
*/home/bob/* it exits 0 and re-owns what the link points to. Here both are
refused.

**A failure does not stop the walk.** upstream stops at the first file it cannot
change and leaves the rest of the home. Here the rest is still re-owned, and the
exit status is 12 either way.

**Deleting a file during the walk is not a failure.** upstream exits 12 if an
entry vanishes while it runs. Here it exits 0, as what was deleted needs no new
owner. A directory the user replaces during the walk is treated the same way;
what took its place is re-owned, and not followed.

## FILES

/etc/passwd
:   User account information.

/etc/shadow
:   Secure user account information.

/etc/group
:   Group account information.

## SEE ALSO

useradd(8), userdel(8), groupmod(8), passwd(1)
