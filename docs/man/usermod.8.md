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
    Use only with the **-G** option; without it the exit status is 2.

**-c**, **--comment** *COMMENT*
:   Set the new value of the user's GECOS field.

**-d**, **--home** *HOME_DIR*
:   Set the new home directory for the user. It must be an absolute path, or
    empty for no home; a relative path is refused with exit status 3 and nothing
    is written. One trailing slash is removed: */x/* is stored as */x*, */x//* as
    */x/*, and */* stays */*. With **-u** or **-g**, files in this directory are
    the ones re-owned, if it exists and is the user's; if it is the user's but a
    symlink or not a directory, the exit status is 12. Without **-m**, the
    previous home is left as it is.

**-e**, **--expiredate** *EXPIRE_DATE*
:   Set the account expiration date, as YYYY-MM-DD or a number of days since the
    epoch. **-1** removes the date.

**-f**, **--inactive** *INACTIVE*
:   Set the password inactive period, in days. **-1** removes it.

**-g**, **--gid** *GROUP*
:   Set the new primary group, by name or numeric ID. The group must exist, or
    the exit status is 6. Files in the user's home in the old primary group get
    the new one.

**-G**, **--groups** *GROUPS*
:   Set the list of supplementary groups (comma-separated). If neither **-a**
    nor **-r** is used, the user is removed from all groups not listed.

**-l**, **--login** *NEW_LOGIN*
:   Change the user's login name.

**-L**, **--lock**
:   Lock the user's password by prepending a '!' to the shadow password.

**-m**, **--move-home**
:   Move the home directory to the path **-d** gives. Only valid with **-d**;
    without it the exit status is 2. The account files are written first, and
    stay written if the move fails. On the same filesystem the directory is
    renamed. Across filesystems it is copied, keeping owners, modes, times, the
    access ACL, hard links, symlinks, fifos and device nodes, and then removed;
    if the copy fails, what was copied is removed and the old home is left. A
    socket in the home fails the copy. A home that does not exist gets a warning
    and exit status 0. If the path is taken, or the old home is not a directory
    or is a symlink, the exit status is 12. With **-u** or **-g**, the home is
    re-owned at its new path, and is left as it was if the move did not happen.
    If **-d** names the current home nothing moves, and **-u** or **-g** re-own
    it where it is; the same path with a trailing slash counts as taken.

**-p**, **--password** *PASSWORD*
:   Set the user's password to the specified pre-hashed value. The hash
    must not contain ':', '\\n', or '\\r' characters.

**-P**, **--prefix** *PREFIX_DIR*
:   Use *PREFIX_DIR* as a prefix for system file paths.

**-r**, **--remove**
:   Remove the user from the supplementary groups listed with **-G**, in
    /etc/group and /etc/gshadow, and leave the other groups alone. A listed
    group the user is not in is not an error; one that does not exist is exit
    status 6. Requires **-G** and cannot be used with **-a**; either mistake is
    exit status 2.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

**-s**, **--shell** *SHELL*
:   Set the new login shell.

**-u**, **--uid** *UID*
:   Set the new numeric user ID. Files in the user's home owned by the old
    UID get the new one, as **-g** does for the old primary group. If part of
    the home could not be changed, the account is still updated and the exit
    status is 12. **4294967295** is refused with exit status 3: it is (uid_t)-1,
    which **chown**(2) and **setresuid**(2) take as "no change". A UID another
    account has is exit status 4.

**-U**, **--unlock**
:   Unlock the user's password by removing the '!' prefix from the
    shadow password. Exit status 3 if that would leave the password field empty.

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
:   Cannot move or re-own the home directory. The account files were written.

## DIFFERENCES FROM UPSTREAM SHADOW

Compared with the **usermod** of Ubuntu 26.04's *passwd* package,
1:4.17.4-2ubuntu3. Debian 13's 1:4.17.4-2 gives the same results.

**A hard link to someone else's file keeps its group.** **-g** gives the new
group to whatever in the home is in the old one. A file with more than one name
that the user does not own is left as it is: it is the same inode as the name
its owner keeps it under, and the user may have linked it there. Upstream
regroups it. The user's own files change however many names they have.

**A home spelled with a trailing slash is the same home.** A symlinked home is
not walked, exit 12. Upstream does the same for */home/bob*, but for
*/home/bob/* it exits 0 and re-owns what the link points to. Here both are
refused.

**A failure does not stop the walk.** Upstream stops at the first file it cannot
change and leaves the rest of the home. Here the rest is still re-owned, and the
exit status is 12 either way.

**Deleting a file during the walk is not a failure.** Upstream exits 12 if an
entry vanishes while it runs. Here it exits 0, as what was deleted needs no new
owner. A directory the user replaces during the walk is treated the same way;
what took its place is re-owned, and not followed.

**The set-user-ID bit goes when a copied home is re-owned.** **-m** with **-u**
or **-g** across filesystems clears the set-user-ID and set-group-ID bits of the
files that change hands, as a rename on one filesystem does with upstream too.
Upstream keeps them in the copied case. Here the copy is made first and re-owned
by the same walk as any other home, so both cases give the same result.

**A moved home that is not the user's is not walked.** **-m** with **-u** or
**-g** moves a home directory that belongs to someone else and re-owns nothing
in it, as **-u** and **-g** leave such a home alone without **-m**. Upstream
keeps that directory's owner but re-owns the user's files inside it when it
moves it.

**Unlocking to an empty password is refused.** **-U** on a password field that
holds only the lock exits 3 and changes nothing. Upstream exits 0.

**Some usage is stricter.** **-a** without **-G** is exit 2, and upstream exits
0. **-p** with a ':' in the hash is exit 3, and upstream exits 1.

**Running with no change to make succeeds.** *usermod LOGIN* with no option exits
0. Upstream prints *no options* and exits 2.

**Some options are not implemented.** **-o**/**--non-unique**,
**-b**/**--badname**, **-Z**/**--selinux-user** and **--selinux-range** are
refused as unknown options, exit 2.

## FILES

/etc/passwd
:   User account information.

/etc/shadow
:   Secure user account information.

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

/etc/subuid, /etc/subgid
:   Subordinate user and group IDs.

## SEE ALSO

useradd(8), userdel(8), groupmod(8), passwd(1)
