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
- Matching group/gshadow entries

## OPTIONS

**-q**, **--quiet**
:   Report only errors, suppress warnings.

**-r**, **--read-only**
:   Display errors and warnings but do not modify files.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory.

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

Problems are reported on standard error, where upstream uses standard output, and
in a shorter form: a duplicate entry gets one line, without upstream's offer to
delete it. Nothing like upstream's *grpck: no changes* is printed. **-q** does
the job of upstream's **-S**/**--silence-warnings**, which is not accepted here.

## FILES

/etc/group
:   Group account information.

/etc/gshadow
:   Secure group account information.

## SEE ALSO

groupadd(8), groupdel(8), groupmod(8), pwck(8)
