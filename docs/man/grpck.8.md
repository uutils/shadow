# grpck(8) - verify integrity of group files

## NAME

grpck - verify integrity of group files

## SYNOPSIS

**grpck** [*options*] [*group* [*gshadow*]]

## DESCRIPTION

The **grpck** command verifies the integrity of the group information.
It checks that all entries in /etc/group and (optionally) /etc/gshadow
have the proper format and contain valid data.

Checks performed include:

- Correct number of fields
- Unique group names
- Valid GID values
- Valid group names
- Matching group/gshadow entries
- Members and administrators that exist, in both files
- A password field of *x* in /etc/group for a group in /etc/gshadow

Files with no problem produce no output. Each problem gets a line on standard
output, and then **grpck** prints *grpck: no changes*, also on standard output, and
exits 2; the files are not rewritten. A member listed in one file and not the other
gets a line too, but is not a problem: the exit status stays 0. A file that cannot
be opened is reported on standard error.

## OPTIONS

**-q**, **--quiet**
:   Accepted, and changes nothing: the report is the same with it.

**-r**, **--read-only**
:   Display errors and warnings but do not modify files.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

**-S**, **--silence-warnings**
:   Do not report a member listed in one file and not the other.

**-s**, **--sort**
:   Sort entries by GID.

## EXIT STATUS

**0**
:   Success.

**1**
:   Invalid command syntax.

**2**
:   One or more bad group entries.

**3**
:   Cannot open files.

**4**
:   Cannot lock files.

**5**
:   Cannot update files.

## DIFFERENCES FROM UPSTREAM SHADOW

Compared with the **grpck** of Ubuntu 26.04's *passwd* package, 1:4.17.4-2ubuntu3.

**Nothing is repaired.** An entry that is bad or has no match gets one line,
without upstream's offer to delete it or add what is missing. The files are only
rewritten by **-s**.

**Comments and blank lines are not bad entries.** Upstream reports them, and exits
2. Here they are kept, and **-s** moves each with the entry it precedes.

**-s checks first.** Upstream sorts whatever it finds, exit 0. Here a problem is
reported, the exit status is 2, and nothing is sorted: a line that cannot be parsed
has no place in a sorted file.

**A missing file is not a lock failure.** Nothing is locked unless **-s** is given,
so a *group* file that is not there is exit 3 in every mode; upstream exits 4
without **-r**. A *gshadow* file that is not there means no gshadow file, exit 0.


## FILES

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

## SEE ALSO

groupadd(8), groupdel(8), groupmod(8), pwck(8)
