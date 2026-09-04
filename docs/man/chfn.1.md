# chfn(1) - change user finger information

## NAME

chfn - change real user name and information

## SYNOPSIS

**chfn** [*options*] [*LOGIN*]

## DESCRIPTION

The **chfn** command changes a user's *finger information*: the full name,
office room number and phone numbers that **finger**(1) and similar tools
display. These are stored as comma-separated sub-fields of the GECOS field
of /etc/passwd (see **passwd**(5)):

```
Full Name,Room Number,Work Phone,Home Phone,Other
```

With no *LOGIN*, **chfn** operates on the account of the user running it.

If no field option is given, **chfn** prompts for each field it is allowed
to change, showing the current value in brackets. Pressing ENTER at a prompt
keeps the current value; an empty run makes no change and exits successfully.
Supply a field option to change one field without being prompted for the
others, or an empty argument (for example **-r** '') to clear a field.

## PERMISSIONS

A normal user may only change their own finger information, and only the
fields listed in **CHFN_RESTRICT** (see below). The superuser may change any
field of any account.

**chfn** is normally installed setuid-root, so it establishes *who is asking*
before it writes: a non-root caller must authenticate through the **chfn** PAM
service (typically /etc/pam.d/chfn, where **pam_rootok** admits root and the
system authentication stack prompts everyone else). Authentication happens
after the new values have been checked and accepted, so a rejected value never
costs the caller a password prompt.

A build without PAM support cannot verify the caller, so it refuses every
non-root invocation rather than applying an unauthenticated change.

## OPTIONS

**-f**, **--full-name** *FULL_NAME*
:   Change the user's full name.

**-h**, **--home-phone** *HOME_PHONE*
:   Change the user's home phone number.

**-o**, **--other** *OTHER*
:   Change the user's other GECOS information. Only the superuser may set this
    field, in any configuration; **CHFN_RESTRICT** cannot delegate it.

**-r**, **--room** *ROOM*
:   Change the user's room number.

**-R**, **--root** *CHROOT_DIR*
:   Apply changes in the *CHROOT_DIR* directory. Only the superuser may use
    this option: it points a setuid-root program at files of the caller's
    choosing.

**-w**, **--work-phone** *WORK_PHONE*
:   Change the user's office phone number.

**--help**
:   Print a usage summary and exit.

**--version**
:   Print the version and exit.

## VALUE RESTRICTIONS

Every value is checked before anything is locked or written. A value is
rejected if it contains a colon, a newline, or any other control character:
those would corrupt the record and could inject a second account into
/etc/passwd.

A comma or an equals sign is additionally rejected in every field except
*other*, the final sub-field. A comma would be read back as a sub-field
separator, silently shifting every following field.

## CONFIGURATION

**CHFN_RESTRICT** in /etc/login.defs (see **login.defs**(5)) lists which
fields a non-root user may change, as a string of letters:

| Letter | Field       |
|--------|-------------|
| **f**  | full name   |
| **r**  | room number |
| **w**  | work phone  |
| **h**  | home phone  |

The value **yes** is equivalent to **rwh**. If **CHFN_RESTRICT** is absent, or
/etc/login.defs cannot be read, non-root users may change nothing and only the
superuser can make changes.

In interactive mode a field the caller may not change is not prompted for, so
no answer is collected only to be refused. A non-root caller allowed no field
at all is told so immediately.

## EXIT STATUS

**0**
:   Success, including an interactive run in which every prompt was answered
    with ENTER.

**1**
:   Permission denied, an invalid value, a missing account, or a failure to
    read or write /etc/passwd.

## FILES

/etc/passwd
:   User account information.

/etc/login.defs
:   Shadow password suite configuration, read for **CHFN_RESTRICT**.

/etc/pam.d/chfn
:   PAM service used to authenticate a non-root caller.

## EXAMPLES

Change your own full name and office phone in one command:

```
$ chfn -f 'Ada Lovelace' -w '+44 20 7946 0958'
```

Review and change every field you are allowed to change:

```
$ chfn
Changing the user information for ada
Enter the new value, or press ENTER for the default
	Full Name [Ada Lovelace]:
	Room Number [C-101]: C-204
	Work Phone [+44 20 7946 0958]:
	Home Phone []:
```

Only the room number is written; the fields answered with ENTER keep their
current values.

Clear another user's room number as root:

```
# chfn -r '' ada
```

## SEE ALSO

chsh(1), finger(1), login.defs(5), passwd(5)
