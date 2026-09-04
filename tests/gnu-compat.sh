#!/usr/bin/env bash
# GNU compatibility suite for shadow-rs.
#
# Runs our tool and the GNU tool on the same input and compares what they
# produce. This is the only check that compares against GNU directly; the Rust
# suite asserts against expectations written down by hand, which can drift from
# what GNU actually does.
#
# It compares two different things, deliberately:
#
#   * **Output**, where the format is a contract other software parses --
#     `passwd -S` and `chage -l`. A difference here breaks scripts.
#   * **Exit codes**, for the error paths. The messages are ours, but the codes
#     are part of the interface.
#
# `--help` output is *not* compared: ours comes from clap and is intentionally
# different. Only that both accept the flag.
#
# Usage: docker compose run --rm debian bash tests/gnu-compat.sh
# Requires: root, and the GNU shadow package installed alongside our build.

set -uo pipefail

PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() {
    printf "  ${GREEN}PASS${NC}: %s\n" "$1"
    PASS=$((PASS + 1))
}

fail() {
    printf "  ${RED}FAIL${NC}: %s\n" "$1"
    FAIL=$((FAIL + 1))
}

# Compare stdout+stderr of the two commands, byte for byte.
compare_output() {
    local name="$1" ours="$2" gnu="$3"
    local our_out gnu_out
    our_out=$(eval "$ours" 2>&1)
    gnu_out=$(eval "$gnu" 2>&1)
    if [ "$our_out" = "$gnu_out" ]; then
        pass "$name"
    else
        fail "$name"
        diff <(printf '%s\n' "$gnu_out") <(printf '%s\n' "$our_out") \
            | sed 's/^/      /' | head -20
    fi
}

# Assert a difference we mean to have: our code, GNU's code, and why.
#
# A deliberate divergence still has to be watched. Left out of the suite it
# would be indistinguishable from a regression the day it changed by accident.
expect_difference() {
    local name="$1" ours="$2" gnu="$3" want_our="$4" want_gnu="$5" why="$6"
    local our_rc=0 gnu_rc=0
    eval "$ours" >/dev/null 2>&1 || our_rc=$?
    eval "$gnu" >/dev/null 2>&1 || gnu_rc=$?
    if [ "$our_rc" = "$want_our" ] && [ "$gnu_rc" = "$want_gnu" ]; then
        pass "$name (ours=$our_rc, GNU=$gnu_rc, by design: $why)"
    else
        fail "$name: expected ours=$want_our GNU=$want_gnu, got ours=$our_rc GNU=$gnu_rc"
    fi
}

# Compare only the exit codes.
compare_exit() {
    local name="$1" ours="$2" gnu="$3"
    local our_rc=0 gnu_rc=0
    eval "$ours" >/dev/null 2>&1 || our_rc=$?
    eval "$gnu" >/dev/null 2>&1 || gnu_rc=$?
    if [ "$our_rc" = "$gnu_rc" ]; then
        pass "$name (exit $our_rc)"
    else
        fail "$name (ours=$our_rc, GNU=$gnu_rc)"
    fi
}

# ── Setup ───────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "error: this suite needs root; the GNU tools refuse otherwise" >&2
    exit 1
fi

for gnu in /usr/bin/passwd /usr/bin/chage /usr/sbin/pwck /usr/sbin/grpck; do
    if [ ! -x "$gnu" ]; then
        echo "error: $gnu is missing; install the GNU shadow package" >&2
        exit 1
    fi
done

cargo build --release --workspace --bins --exclude uu_shadow >/dev/null 2>&1 || {
    echo "error: build failed" >&2
    exit 1
}
RS=./target/release

# A throwaway account with known aging fields, so both tools describe exactly
# the same thing and the comparison is not at the mercy of whatever the image
# happens to contain.
PROBE=gnucompat_probe
/usr/sbin/userdel -r "$PROBE" >/dev/null 2>&1
/usr/sbin/useradd -M "$PROBE" >/dev/null 2>&1 || {
    echo "error: cannot create the probe account" >&2
    exit 1
}
cleanup() { /usr/sbin/userdel -r "$PROBE" >/dev/null 2>&1; }
trap cleanup EXIT

# ── passwd -S ───────────────────────────────────────────────────────
#
# `passwd -S` is parsed by monitoring and provisioning scripts, so its seven
# fields and their formatting are a contract.

echo "=== passwd -S ==="
for args in \
    "-d 2026-01-01 -m 0 -M 99999 -W 7" \
    "-d 0 -m 5 -M 90 -W 14 -I 30" \
    "-d -1 -m -1 -M -1 -W -1 -I -1" \
    "-d 2026-01-01 -M 10000" \
    "-d 2026-01-01 -M 9999 -E 2027-06-15"; do
    # shellcheck disable=SC2086
    /usr/bin/chage $args "$PROBE" >/dev/null 2>&1
    compare_output "passwd -S after chage $args" \
        "$RS/passwd -S $PROBE" "/usr/bin/passwd -S $PROBE"
done

compare_output "passwd -S root" "$RS/passwd -S root" "/usr/bin/passwd -S root"

# ── chage -l ────────────────────────────────────────────────────────
#
# The label column, the "password must be changed" wording and the threshold
# above which a maximum age reads "never" all have to match.

echo "=== chage -l ==="
for args in \
    "-d 2026-01-01 -m 0 -M 99999 -W 7 -I -1 -E -1" \
    "-d 0 -m 5 -M 90 -W 14 -I 30 -E 1970-01-01" \
    "-d 2026-01-01 -M 9999 -I -1 -E -1" \
    "-d 2026-01-01 -M 10000 -I -1 -E -1" \
    "-d 2026-01-01 -M 90 -I 30 -E 2027-06-15" \
    "-d -1 -m -1 -M -1 -W -1 -I -1 -E -1"; do
    # shellcheck disable=SC2086
    /usr/bin/chage $args "$PROBE" >/dev/null 2>&1
    compare_output "chage -l after chage $args" \
        "$RS/chage -l $PROBE" "/usr/bin/chage -l $PROBE"
done

# ── Exit codes on the error paths ───────────────────────────────────
#
# The messages are ours; the codes are the interface.

echo "=== exit codes ==="
compare_exit "passwd -S on an unknown login" \
    "$RS/passwd -S no_such_user_9f3a" "/usr/bin/passwd -S no_such_user_9f3a"
compare_exit "chage -l on an unknown login" \
    "$RS/chage -l no_such_user_9f3a" "/usr/bin/chage -l no_such_user_9f3a"
compare_exit "chage -M with a negative day count" \
    "$RS/chage -M -5 $PROBE" "/usr/bin/chage -M -5 $PROBE"

compare_exit "chage -l combined with a field option" \
    "$RS/chage -l -M 90 $PROBE" "/usr/bin/chage -l -M 90 $PROBE"
compare_exit "groupadd with no group name" \
    "$RS/groupadd" "/usr/sbin/groupadd"
compare_exit "groupdel on an unknown group" \
    "$RS/groupdel no_such_group_9f3a" "/usr/sbin/groupdel no_such_group_9f3a"
compare_exit "userdel on an unknown login" \
    "$RS/userdel no_such_user_9f3a" "/usr/sbin/userdel no_such_user_9f3a"
compare_exit "chpasswd -s without -c" \
    "echo x:y | $RS/chpasswd -s 5000" "echo x:y | /usr/sbin/chpasswd -s 5000"
compare_exit "chpasswd -e with -c" \
    "echo x:y | $RS/chpasswd -e -c SHA512" "echo x:y | /usr/sbin/chpasswd -e -c SHA512"

# ── Deliberate differences ──────────────────────────────────────────

echo "=== deliberate differences ==="
# GNU parses dates leniently and rolls them over: `chage -d 2025-02-29` stores
# 1 March, and `-d 2025-13-01` stores 1 January 2026. An administrator who
# typed one of those made a mistake, and silently storing a different date than
# the one they wrote is a poor answer for a field that governs when an account
# stops working. We refuse it instead; chage(1) in docs/man says so.
for date in 2025-02-29 2025-04-31 2025-13-01; do
    expect_difference "chage -d $date" \
        "$RS/chage -d $date $PROBE" "/usr/bin/chage -d $date $PROBE" \
        2 0 "an impossible date is refused, not rolled over"
done

# Both must accept --help; the text itself is ours.
echo "=== --help is accepted ==="
for pair in \
    "passwd:/usr/bin/passwd" \
    "chage:/usr/bin/chage" \
    "chfn:/usr/bin/chfn" \
    "chsh:/usr/bin/chsh" \
    "newgrp:/usr/bin/newgrp" \
    "useradd:/usr/sbin/useradd" \
    "userdel:/usr/sbin/userdel" \
    "usermod:/usr/sbin/usermod" \
    "groupadd:/usr/sbin/groupadd" \
    "groupdel:/usr/sbin/groupdel" \
    "groupmod:/usr/sbin/groupmod" \
    "chpasswd:/usr/sbin/chpasswd" \
    "pwck:/usr/sbin/pwck" \
    "grpck:/usr/sbin/grpck"; do
    tool="${pair%%:*}"
    gnu="${pair#*:}"
    compare_exit "$tool --help" "$RS/$tool --help" "$gnu --help"
done

# ── Results ─────────────────────────────────────────────────────────

echo ""
echo "=== Results ==="
printf "  ${GREEN}PASS: %d${NC}\n" "$PASS"
printf "  ${RED}FAIL: %d${NC}\n" "$FAIL"
[ "$FAIL" -eq 0 ]
