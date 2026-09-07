#!/usr/bin/env bash
# Run the aarch64 build and check it actually works.
#
# The release publishes an arm64 archive, and until this existed nothing ever
# executed one: CI builds it on a native arm64 runner and then ships it, so a
# broken arm64 binary would reach a user before anyone ran it. The x86-64
# archive is exercised by the whole test suite; this is the arm64 equivalent,
# reduced to the operations that touch every account file.
#
# The binary is cross-compiled and run under qemu's user-mode emulation with
# the cross toolchain's arm64 libraries as the loader path. That is enough to
# catch what actually breaks across architectures -- a wrong integer width, a
# struct layout assumption, an endianness slip in the crypt or PAM FFI -- none
# of which need a real arm64 machine to show up.
#
# Usage: docker compose run --rm debian make test-arm64

set -uo pipefail

PASS=0
FAIL=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

ok()   { printf "  ${GREEN}PASS${NC}: %s\n" "$1"; PASS=$((PASS + 1)); }
bad()  { printf "  ${RED}FAIL${NC}: %s\n" "$1"; FAIL=$((FAIL + 1)); }

check() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}

# Assert that a file matches an extended regular expression.
contains() {
    local name="$1" file="$2" pattern="$3"
    if grep -qE "$pattern" "$file"; then
        ok "$name"
    else
        bad "$name"
        sed 's/^/      /' "$file" | head -5
    fi
}

BIN="${ARM64_BIN:?ARM64_BIN must point at the cross-built binary}"
SYSROOT="${ARM64_SYSROOT:-/usr/aarch64-linux-gnu}"
QEMU=(qemu-aarch64-static -L "$SYSROOT")

if [ ! -x "$BIN" ]; then
    echo "error: $BIN is missing; run 'make build-arm64' first" >&2
    exit 1
fi

echo "=== the binary is arm64 and runs ==="
if file -b "$BIN" | grep -q 'ARM aarch64'; then
    ok "cross-compiled for ARM aarch64"
else
    bad "not an ARM aarch64 binary: $(file -b "$BIN")"
    exit 1
fi

version=$("${QEMU[@]}" "$BIN" --version 2>&1)
if [ -n "$version" ]; then ok "runs: $version"; else bad "would not run"; exit 1; fi

applets=$("${QEMU[@]}" "$BIN" --list 2>/dev/null | tail -n +2 | wc -l)
if [ "$applets" -ge 20 ]; then
    ok "carries $applets applets"
else
    bad "expected at least 20 applets, found $applets"
fi

# ── A prefix tree, so nothing here touches the container's own accounts ──

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/etc" "$T/home"
printf 'root:x:0:0:root:/root:/bin/sh\n'                    >"$T/etc/passwd"
printf 'root:!:19000:0:99999:7:::\n'                        >"$T/etc/shadow"
printf 'root:x:0:\nstaff:x:2000:\n'                         >"$T/etc/group"
printf 'root:!::\nstaff:!::\n'                              >"$T/etc/gshadow"
printf 'UID_MIN 1000\nGID_MIN 1000\nENCRYPT_METHOD SHA512\n' >"$T/etc/login.defs"
: >"$T/etc/subuid"
: >"$T/etc/subgid"

echo "=== account operations ==="
check "useradd -m -G staff" "${QEMU[@]}" "$BIN" useradd -P "$T" -m -G staff alice
contains "the account is in passwd" "$T/etc/passwd" '^alice:x:1000:'
contains "and in shadow, with aging from login.defs" "$T/etc/shadow" '^alice:!:[0-9]+:0:99999:7:'
contains "and in the supplementary group" "$T/etc/group" '^staff:x:2000:alice'
check "the home directory was created" test -d "$T/home/alice"

# crypt(3) is FFI, so it is the most likely thing to differ across
# architectures. A SHA-512 hash is 106 characters and starts with $6$.
echo 'alice:a long passphrase' | "${QEMU[@]}" "$BIN" chpasswd -P "$T" >/dev/null 2>&1
contains "chpasswd wrote a SHA-512 hash" "$T/etc/shadow" '^alice:\$6\$[./A-Za-z0-9]{8,}\$[./A-Za-z0-9]{86}:'

check "chage sets the aging fields" "${QEMU[@]}" "$BIN" chage -P "$T" -d 2026-01-01 -M 90 alice
aging=$("${QEMU[@]}" "$BIN" chage -P "$T" -l alice 2>/dev/null)
# The date arithmetic is pure integer maths and a good width canary.
if printf '%s' "$aging" | grep -q 'Jan 01, 2026' && printf '%s' "$aging" | grep -q 'Apr 01, 2026'; then
    ok "chage -l computes the dates correctly"
else
    bad "chage -l gave unexpected dates"
    printf '%s\n' "$aging" | sed 's/^/      /' | head -3
fi

check "gpasswd adds a member" "${QEMU[@]}" "$BIN" gpasswd -P "$T" -a alice staff
contains "gshadow carries the member" "$T/etc/gshadow" '^staff:[^:]*:[^:]*:alice'

check "usermod renames the account" "${QEMU[@]}" "$BIN" usermod -P "$T" -l ada alice
contains "the rename reached group" "$T/etc/group" '^staff:x:2000:ada'

check "userdel -r removes it" "${QEMU[@]}" "$BIN" userdel -P "$T" -r ada
if grep -q '^ada:' "$T/etc/passwd"; then
    bad "the account is still in passwd"
else
    ok "the account is gone from passwd"
fi

# sg cannot be driven against a prefix tree -- it switches the running
# process's groups and execs -- so this only checks that the applet links and
# starts under emulation. It is the only caller of getgroups/setgroups, and a
# wrong struct width there would show up as a failure to run at all.
check "sg starts" "${QEMU[@]}" "$BIN" sg --help
check "vipw starts" "${QEMU[@]}" "$BIN" vipw --help
check "vigr starts" "${QEMU[@]}" "$BIN" vigr --help

# newusers writes three files and a home directory from one line, so it
# exercises the allocator, crypt(3) and the fchown in shadow_core::home
# together -- the widest single check available here.
printf 'batched:a long passphrase:2500:2500:Batched::/bin/sh\n' \
    | "${QEMU[@]}" "$BIN" newusers -P "$T" >/dev/null 2>&1
contains "newusers created the account" "$T/etc/passwd" '^batched:x:2500:2500:'
contains "with a SHA-512 hash" "$T/etc/shadow" '^batched:\$6\$'
contains "and a group of its own" "$T/etc/group" '^batched:x:2500:' 

# pwck exits 2 for warnings, which a synthetic tree produces (no real shells),
# so anything up to 2 means it read and checked the files rather than failing.
"${QEMU[@]}" "$BIN" pwck -r "$T/etc/passwd" "$T/etc/shadow" >/dev/null 2>&1
rc=$?
if [ "$rc" -le 2 ]; then
    ok "pwck reads the files it just wrote (exit $rc)"
else
    bad "pwck exited $rc"
fi

echo ""
echo "=== Results ==="
printf "  ${GREEN}PASS: %d${NC}\n" "$PASS"
printf "  ${RED}FAIL: %d${NC}\n" "$FAIL"
[ "$FAIL" -eq 0 ]
