# expiry(1) - check and enforce password expiration

## NAME

expiry - check and enforce password expiration policy

## SYNOPSIS

**expiry** [**-c**] [**-f**]

## DESCRIPTION

**expiry** looks at the calling user's own /etc/shadow line and does what
**login**(1) would do with it. When all is well it says nothing. When the
password is due to expire within its warning period it says so. When the
password has expired it says so and requires a new one on the spot, through
PAM, exactly as **passwd**(1) would. When the account itself has expired it
turns the caller away.

It exists for sessions that did not come through **login**: a display
manager, an ssh key, a **su** without a password. Shell profiles run
`expiry -c` so those sessions still meet the aging policy.

## OPTIONS

**-c**, **--check**
:   Check the caller's password expiration, and enforce what is found.

**-f**, **--force**
:   Force a password change if the caller's password has expired.

With either option the behaviour is the same, as it is in the GNU tool; with
neither, nothing is asked and the usage is printed. **-P**/**--prefix** reads
the account files under another directory and only reports, since a PAM
change would act on this system's account of the same name.

## WHAT IS DECIDED, IN ORDER

1. A locked password is a policy of its own and is not reported.
2. An expiration date in the past, or a password expired for longer than its
   inactivity period, means the account is disabled: *Your account has
   expired; please contact your system administrator.* Exit 1.
3. A last-change day of 0, or a password older than its maximum age, must be
   changed: *You are required to change your password immediately (password
   expired).* followed by the change. Exit 0 once it is made.
4. Inside the warning period: *Your password will expire in N days.* — or
   *tomorrow*, or *today*. Exit 0.
5. Otherwise, silence and exit 0.

A maximum age of 10000 days or more means never, as **chage -l** prints it.

## PRIVILEGES

The GNU suite installs **expiry** setgid **shadow**: enough to read
/etc/shadow, no more, and the password change runs through PAM as the caller.
The per-tool install here does the same. The single multicall binary keeps its
setuid privilege for **expiry**, having nothing narrower to offer, and reads
the one line it needs.

## EXIT STATUS

**0**
:   Nothing to enforce, a warning issued, or the required change made.

**1**
:   The account has expired, or the required change failed, or the account
    files could not be read.

**2**
:   Invalid command syntax, including neither **-c** nor **-f**.

## FILES

/etc/passwd, /etc/shadow
:   The caller's account and aging information.

/etc/pam.d/passwd
:   The PAM service the change goes through.

## SEE ALSO

chage(1), login(1), passwd(1), shadow(5)
