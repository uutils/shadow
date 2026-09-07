# login(1) - begin a session on the system

## NAME

login - begin a session on the system

## SYNOPSIS

**login** [**-p**] [**-h** *host*] [**-H**] [[**-f**] *name*]

## DESCRIPTION

**login** is what **getty**(8) runs on a terminal once someone is there. It
establishes who they are and starts their session: it prompts for a login
name and, through PAM, a password; checks the account may log in; records the
login; hands the terminal to the user; and runs their login shell with a login
environment. When the shell exits, it closes the session and records the
logout.

It is run by root — by getty, or by a server such as **telnetd** that has
already authenticated its peer — and does nothing for anyone else: *Cannot
possibly work without effective root*. It is not setuid. It needs a
controlling terminal and refuses without one.

Two implementations of this program are in service: shadow-utils' on Ubuntu
20.04, 22.04 and 24.04 and Debian 12, and util-linux's from Debian 13 and
Ubuntu 25.10. This one implements the options and behaviour the two share, and
adds util-linux's **-H** and **--help**, which conflict with nothing.

## HOW A LOGIN PROCEEDS

1. The prompt is `hostname login: `, or `login: ` with **-H** or
   **LOGIN_PLAIN_PROMPT**. Any input typed ahead of the prompt is discarded, so
   a password typed early does not land in the name field in clear.
2. The name goes to the `login` PAM service. Without **-f** the stack
   authenticates it, which for a local account means a password prompt. A
   wrong password and an unknown name get the same answer, *Login incorrect*,
   after the same delay, so the answer reveals nothing about which accounts
   exist. After **LOGIN_RETRIES** failures **login** exits. **LOGIN_TIMEOUT**
   seconds after it started, if no login has succeeded, it exits.
3. The account is checked: expiry, and a password that must be changed, which
   is changed on the spot. An expired account is told *Your account has
   expired; please contact your system administrator.*
4. Credentials are established and the PAM session opened. Whatever the
   session stack exports — locale from **pam_env**, `XDG_*` from
   **pam_systemd** — becomes part of the environment.
5. The login is recorded in utmp and wtmp, with the remote host if **-h**
   named one, so **who**(1) and **last**(1) see it.
6. The terminal is given to the user: owner the account, group **TTYGROUP**
   where that group exists and the account's primary group otherwise, mode
   **TTYPERM**.
7. The shell named in the passwd record runs — `/bin/sh` if the field is
   empty — as the user, with `-` prefixed to its name so it behaves as a login
   shell, in the home directory. If the home is missing and **DEFAULT_HOME**
   is `yes`, the session starts in `/` with *No directory, logging in with
   HOME=/*; otherwise it is refused.
8. The shell runs as a child of **login**, not in its place, so that when it
   exits the session can be closed and the logout recorded. Signals aimed at
   the shell do not reach **login**.

## ENVIRONMENT

Without **-p** the caller's environment is discarded, except **TERM**,
**COLORTERM** and **NO_COLOR**, which a session inherits from the terminal.
With **-p** it is kept. Either way **HOME**, **SHELL**, **USER**, **LOGNAME**,
**MAIL** and **PATH** are set from the account: **PATH** is **ENV_SUPATH** for
root and **ENV_PATH** for everyone else, and **MAIL** is **MAIL_DIR**/*name*.
The PAM session's variables are applied last and win.

## OPTIONS

**-p**
:   Preserve the environment.

**-f**
:   Do not authenticate; the user is already authenticated. This is what
    getty's autologin uses. Requires *name*. Because authentication is
    skipped, so is everything the `auth` stack would do, including
    **pam_nologin**.

**-h** *host*
:   The remote host, recorded in utmp and passed to PAM as **PAM_RHOST**.

**-H**
:   Do not show the hostname in the prompt.

**--help**
:   Display help and exit. There is no **-h** for help: **-h** is the host,
    as it has been since telnetd.

**-r** *host*
:   The rlogin autologin protocol. Refused.

## CONFIGURATION

Read from /etc/login.defs. The defaults are login(1)'s.

**LOGIN_RETRIES** (3), **LOGIN_TIMEOUT** (60), **FAIL_DELAY** (0, added to
the delay the PAM stack already imposes), **TTYGROUP** (tty), **TTYPERM**
(0600), **ENV_PATH**, **ENV_SUPATH**, **MAIL_DIR** (/var/mail),
**DEFAULT_HOME** (yes), **HUSHLOGIN_FILE** (.hushlogin), **MOTD_FILE** (unset;
a colon-separated list printed unless the login is hushed — on most systems
**pam_motd** does this instead), **LOGIN_PLAIN_PROMPT** (no).

A login is *hushed* — no message of the day — when the file named by
**HUSHLOGIN_FILE** exists in the home directory, or /etc/hushlogins lists the
user or their shell.

## DIFFERENCES FROM THE GNU TOOLS

**-r** is refused rather than implemented. rlogin has been off every system
that matters for two decades.

The terminal is not hung up. util-linux's **login** calls **vhangup**(2) to
shake off any process still listening on the line; shadow's, which every
current LTS ships, does not. Getty owns the line before **login** runs, and
this program trusts that as shadow's does.

**lastlog** is not written. Debian 13 removed /var/log/lastlog; where it still
exists, **pam_lastlog** in the `login` service maintains it, as it does on
Ubuntu.

## EXIT STATUS

**0**
:   The session ran and the shell exited.

**1**
:   Not root, no terminal, authentication or account checks failed, the
    session could not be set up, or a usage error.

## FILES

/etc/passwd, /etc/shadow
:   Accounts, through the name service.

/etc/pam.d/login
:   The PAM service.

/etc/login.defs
:   Configuration; see above.

/etc/hushlogins, ~/.hushlogin
:   Suppress the message of the day.

/var/run/utmp, /var/log/wtmp
:   Login accounting.

## SEE ALSO

getty(8), login.defs(5), nologin(8), pam(8), passwd(5), su(1), who(1)
