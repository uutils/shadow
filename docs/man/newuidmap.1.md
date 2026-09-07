# newuidmap(1) - set the user ID mapping of a user namespace

## NAME

newuidmap, newgidmap - set the user or group ID mapping of a user namespace

## SYNOPSIS

**newuidmap** [*pid*|**fd:***N*] *uid* *loweruid* *count* [*uid* *loweruid* *count* ...]

**newgidmap** [*pid*|**fd:***N*] *gid* *lowergid* *count* [*gid* *lowergid* *count* ...]

## DESCRIPTION

**newuidmap** writes /proc/*pid*/uid_map, the table that says which user IDs
inside the user namespace of process *pid* correspond to which user IDs
outside it. Each triple maps *count* IDs starting at *uid* inside the
namespace onto *count* IDs starting at *loweruid* outside it. **newgidmap**
does the same for group IDs and /proc/*pid*/gid_map.

The kernel lets an unprivileged process map exactly one ID into a namespace it
created: its own. Everything beyond that — the range of IDs a container needs
for its own users and groups — requires the privilege these helpers carry.
They are installed setuid-root for that, and they hand out that privilege
only within the ranges the administrator granted the caller in /etc/subuid
and /etc/subgid. Podman and rootless Docker call them for every container
they start.

The two are one program with a selector.

## WHAT IS CHECKED

Before anything is written:

- The command line must be a target followed by one or more triples of
  plain decimal numbers. A count of zero is refused as an overflow, as the
  GNU helper words it.
- Every requested outside range [*loweruid*, *loweruid*+*count*) must lie
  inside one range granted to the caller in /etc/subuid — an entry naming the
  caller by login name or by numeric UID — **or** be the caller's own ID
  mapped once. Root is not exempt from the /etc/subuid requirement, as
  newuidmap(1) has always said.
- The ranges may not overlap one another, on either side. The kernel refuses
  overlaps too, with nothing but `EINVAL`; the helper names them.
- The target process must belong to the caller: the owner of /proc/*pid* must
  be the caller's real UID and GID, and those must be the caller's account
  IDs. The message names all three on each side, so an administrator can see
  which disagrees.

Then the map file is opened *through the directory descriptor of
/proc/pid* and written in a single write, which is the only form the kernel
accepts. A namespace's map may be written once; a second attempt is refused
by the kernel and reported.

## THE fd:N FORM

A caller that has checked the target itself can pass **fd:***N*, a descriptor
it holds open on /proc/*pid*. The helper works through that descriptor, so a
process ID recycled between the caller's checks and the write cannot
redirect it to another process. A descriptor on anything but a /proc/*pid*
directory is a usage error.

## OPTIONS

**--help**
:   Display help and exit.

## EXIT STATUS

**0**
:   The map was written.

**1**
:   Usage error, a range not granted or overlapping, a target that is not the
    caller's or cannot be found, or a write the kernel refused. Nothing was
    written.

## FILES

/etc/subuid, /etc/subgid
:   The subordinate ID ranges granted to each user.

/proc/*pid*/uid_map, /proc/*pid*/gid_map
:   The files written.

## DIFFERENCES FROM THE GNU HELPERS

Overlapping ranges are refused with a message naming them; the GNU helper
passes them to the kernel and reports its `EINVAL`. Numbers must be plain
decimals: a negative count is a usage error here where the GNU helper folds
it into the overflow message. Neither changes any outcome the kernel would
have accepted.

## SEE ALSO

subuid(5), subgid(5), user_namespaces(7), usermod(8), unshare(1)
