#!/usr/bin/env bash
# Verify the archives of a published release before anyone is told about it.
#
# A green pipeline is not a runnable binary. 0.3.0 shipped a glibc archive
# that would not start on Debian 12, and every static musl archive from 0.2.2
# to 0.4.0 aborted the moment an unprivileged user ran a setuid tool, because
# nothing ever ran one that way: the test suites run as root, where that path
# is skipped, and the deployment image is glibc. This script runs each archive
# the way a user will, in a container of the kind it is meant for.
#
# Usage: make verify-release TAG=0.5.0   (from the host; it drives docker)
#
# For each archive: the digest in its .sha256 file matches; the multicall
# binary reports the tag's version and 28 applets; the glibc archives need
# nothing newer than GLIBC_2.34 (Debian 12, Ubuntu 22.04, RHEL 9) and the
# static one needs no libc at all; installed setuid root and reached through a
# symlink, `passwd -S` answers an unprivileged user and a spoofed argv[0] is
# refused. The arm64 archive also runs tests/arm64-smoke.sh under qemu.
set -uo pipefail

TAG="${1:?usage: verify-release.sh TAG}"
REPO="${REPO:-uutils/shadow}"
REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
# The applet count the checked-out tree ships; an older tag is expected to
# fall short of it, which is a reason to check out that tag first.
APPLETS=$(grep -oE 'ALL_TOOLS: \[&str; [0-9]+\]' "$REPO_DIR/src/bin/shadow-rs.rs" | grep -oE '[0-9]+$')
APPLETS=${APPLETS:-28}
PASS=0
FAIL=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
ok()  { printf "  ${GREEN}PASS${NC}: %s\n" "$1"; PASS=$((PASS + 1)); }
bad() { printf "  ${RED}FAIL${NC}: %s\n" "$1"; FAIL=$((FAIL + 1)); }
# Assert that a string matches an extended regular expression.
expect() {
    local name="$1" got="$2" pattern="$3"
    if grep -qE "$pattern" <<<"$got"; then
        ok "$name"
    else
        bad "$name"
        sed 's/^/      got: /' <<<"$got" | head -5
    fi
}

X86="uu_shadow-x86_64-unknown-linux-gnu"
ARM="uu_shadow-aarch64-unknown-linux-gnu"
MUSL="uu_shadow-x86_64-unknown-linux-musl-static"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || exit 1

echo "=== release $TAG: assets ==="
if ! gh release download "$TAG" --repo "$REPO" --pattern '*.tar.gz' --pattern '*.tar.gz.sha256' >/dev/null 2>&1; then
    echo "error: could not download the assets of $TAG from $REPO" >&2
    exit 1
fi
for a in "$X86" "$ARM" "$MUSL"; do
    if [ -f "$a.tar.gz" ] && [ -f "$a.tar.gz.sha256" ]; then
        ok "$a.tar.gz and its .sha256 are published"
    else
        bad "$a.tar.gz or its .sha256 is missing"
        continue
    fi
    # dist writes `HASH *name`, `make dist-musl` writes `HASH  name`; compare
    # the digest itself rather than trust one tool's idea of the format.
    want=$(cut -c1-64 <"$a.tar.gz.sha256")
    have=$(sha256sum "$a.tar.gz" | cut -c1-64)
    if [ "$want" = "$have" ]; then ok "$a.tar.gz digest matches"; else bad "$a.tar.gz digest: file says $want, archive is $have"; fi
    mkdir -p "$a" && tar xzf "$a.tar.gz" -C "$a" --strip-components=1
done

# What every archive has to do once installed as `make install-multicall`
# installs it: setuid root, applets as symlinks, called by a user. Runs inside
# the target container; prints one `key=value` line per check.
probe='
set +e
cd /archive
echo "version=$(./shadow-rs --version 2>&1)"
echo "applets=$(./shadow-rs --list 2>/dev/null | grep -c "^ ")"
echo "floor=$(readelf -V shadow-rs 2>/dev/null | grep -oE "GLIBC_[0-9.]+" | sort -Vu | tail -1)"
echo "needed=$(readelf -d shadow-rs 2>/dev/null | grep -oE "\[lib[a-z0-9_.]+\]" | tr -d "[]" | tr "\n" " ")"
mkdir -p /usr/local/sbin /usr/local/bin
install -m 4755 -o root -g root shadow-rs /usr/local/sbin/shadow-rs
ln -sf /usr/local/sbin/shadow-rs /usr/local/bin/passwd
if command -v useradd >/dev/null; then useradd -m -s /bin/sh probe; else adduser -D -s /bin/sh probe; fi >/dev/null 2>&1
echo "status=$(su probe -s /bin/sh -c "/usr/local/bin/passwd -S" 2>&1)"
spoofsh=/bin/sh; [ -x /bin/bash ] && spoofsh=/bin/bash
echo "spoofed=$(su probe -s $spoofsh -c "exec -a chsh /usr/local/bin/passwd -S" 2>&1 | head -1)"
echo "doc=$(test -f PLATFORM-SUPPORT.md && echo shipped || echo missing)"
'

# Read the probe's output into checks. $1 names the archive, $2 says whether a
# glibc floor is expected, stdin is the probe output.
judge() {
    local name="$1" glibc="$2" out
    out=$(cat)
    expect "$name: reports version $TAG" "$out" "^version=.* ${TAG//./\\.}$"
    expect "$name: carries $APPLETS applets" "$out" "^applets=$APPLETS$"
    if [ "$glibc" = glibc ]; then
        expect "$name: needs nothing newer than GLIBC_2.34" "$out" "^floor=GLIBC_2\.(3[0-4]|[0-2][0-9])$"
        expect "$name: links libpam" "$out" "^needed=.*libpam\.so"
    else
        expect "$name: has no dynamic dependencies" "$out" "^needed= *$"
    fi
    expect "$name: setuid through a symlink, passwd -S answers a user" "$out" "^status=probe [A-Z]+ "
    expect "$name: a spoofed argv\[0\] is still refused" "$out" "^spoofed=.*does not match executed binary"
}

echo "=== $X86 on debian:12 (glibc 2.36, the oldest supported line) ==="
x86_out=$(docker run --rm -v "$WORK/$X86:/archive:ro" debian:12 bash -c \
    "apt-get -qq update >/dev/null && apt-get -qq install -y --no-install-recommends binutils libpam0g >/dev/null 2>&1; $probe" 2>&1)
judge "$X86" glibc <<<"$x86_out"

echo "=== $MUSL on alpine:3.23 ==="
musl_out=$(docker run --rm -v "$WORK/$MUSL:/archive:ro" alpine:3.23 sh -c \
    "apk add -q binutils >/dev/null 2>&1; $probe" 2>&1)
judge "$MUSL" static <<<"$musl_out"
expect "$MUSL: ships PLATFORM-SUPPORT.md" "$musl_out" "^doc=shipped$"

echo "=== $ARM under qemu, in the debian image (tests/arm64-smoke.sh) ==="
# The same packages `make build-arm64` installs, minus the compiler: the arm64
# runtime for pam and crypt, and qemu's user-mode emulator.
arm_out=$(docker compose -f "$REPO_DIR/docker-compose.yml" run --rm -T -v "$WORK/$ARM:/archive:ro" debian bash -c '
    (dpkg --add-architecture arm64 && apt-get -qq update && apt-get -qq install -y --no-install-recommends \
        gcc-aarch64-linux-gnu libpam0g:arm64 libcrypt1:arm64 qemu-user-static) >/tmp/apt.log 2>&1 || { tail -5 /tmp/apt.log; exit 1; }
    echo "arch=$(file -b /archive/shadow-rs | cut -d, -f2 | tr -d " ")"
    echo "floor=$(readelf -V /archive/shadow-rs | grep -oE "GLIBC_[0-9.]+" | sort -Vu | tail -1)"
    ARM64_BIN=/archive/shadow-rs bash tests/arm64-smoke.sh 2>&1 | sed "s/\x1b\[[0-9;]*m//g" | tail -2 | tr "\n" " "; echo' 2>&1 | grep -vE "^\s*Container ")
expect "$ARM: is an ARM aarch64 binary" "$arm_out" "^arch=ARMaarch64$"
expect "$ARM: needs nothing newer than GLIBC_2.34" "$arm_out" "^floor=GLIBC_2\.(3[0-4]|[0-2][0-9])$"
expect "$ARM: arm64 smoke suite passes under qemu" "$arm_out" "PASS: [0-9]+ +FAIL: 0"

echo
echo "verify-release $TAG: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
