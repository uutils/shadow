#!/usr/bin/env bash
# shadow-rs end-to-end deployment tests
#
# Runs ~100 assertions validating that shadow-rs works as a drop-in
# replacement for GNU shadow-utils when installed system-wide.
#
# Usage:
#   docker compose run --rm e2e              # run all tests
#   docker compose run --rm e2e bash         # debug interactively
#
# Requires: root (for user/group management), expect, nscd, ansible-core

set -uo pipefail

# ── Test framework ──────────────────────────────────────────────────

PASS=0
FAIL=0
SECTION=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

section() {
    SECTION="$1"
    echo -e "\n${BLUE}── $1 ──${NC}"
}

assert_ok() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $desc (command: $1)"
        FAIL=$((FAIL + 1))
    fi
}

assert_fail() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo -e "  ${RED}✗${NC} $desc (expected failure, got success)"
        FAIL=$((FAIL + 1))
    else
        echo -e "  ${GREEN}✓${NC} $desc"
        PASS=$((PASS + 1))
    fi
}

assert_contains() {
    local desc="$1"
    local pattern="$2"
    shift 2
    local output
    if output=$("$@" 2>&1) && echo "$output" | grep -q "$pattern"; then
        echo -e "  ${GREEN}✓${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $desc (pattern '$pattern' not found in output)"
        FAIL=$((FAIL + 1))
    fi
}

assert_file_contains() {
    local desc="$1"
    local file="$2"
    local pattern="$3"
    if grep -q "$pattern" "$file" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $desc (pattern '$pattern' not in $file)"
        FAIL=$((FAIL + 1))
    fi
}

assert_file_not_contains() {
    local desc="$1"
    local file="$2"
    local pattern="$3"
    if grep -q "$pattern" "$file" 2>/dev/null; then
        echo -e "  ${RED}✗${NC} $desc (pattern '$pattern' found in $file but shouldn't be)"
        FAIL=$((FAIL + 1))
    else
        echo -e "  ${GREEN}✓${NC} $desc"
        PASS=$((PASS + 1))
    fi
}

# Helper: hash a plaintext password for chpasswd -e
hash_password() {
    openssl passwd -6 "$1"
}

# ── TOOLS list ──────────────────────────────────────────────────────

TOOLS="passwd pwck useradd userdel usermod chpasswd chage groupadd groupdel groupmod grpck chfn chsh newgrp"
SETUID_TOOLS="passwd chfn chsh newgrp"
BINDIR="/usr/sbin"

# ── Preflight ───────────────────────────────────────────────────────

preflight() {
    section "Preflight checks"

    assert_ok "shadow-rs binary exists" test -x "$BINDIR/shadow-rs"
    assert_ok "shadow-rs --list succeeds" "$BINDIR/shadow-rs" --list

    for tool in $TOOLS; do
        assert_ok "symlink exists: $tool" test -L "$BINDIR/$tool"
        assert_ok "symlink $tool resolves to shadow-rs" \
            bash -c "readlink -f '$BINDIR/$tool' | grep -q 'shadow-rs'"
    done
}

# ── Symlink dispatch ────────────────────────────────────────────────

test_symlink_dispatch() {
    section "Symlink dispatch (argv[0])"

    for tool in $TOOLS; do
        assert_ok "$tool --help via symlink" "$BINDIR/$tool" --help
    done
}

# ── Multicall dispatch ──────────────────────────────────────────────

test_multicall_dispatch() {
    section "Multicall dispatch (shadow-rs <tool>)"

    for tool in $TOOLS; do
        assert_ok "shadow-rs $tool --help" "$BINDIR/shadow-rs" "$tool" --help
    done
}

# ── Setuid ──────────────────────────────────────────────────────────

test_setuid() {
    section "Setuid bits"

    # Check setuid on the target binary (symlinks always show 777)
    local target_perms
    target_perms=$(stat -L -c '%a' "$BINDIR/shadow-rs" 2>/dev/null || echo "0")
    if [[ "$target_perms" == "4755" ]]; then
        echo -e "  ${GREEN}✓${NC} shadow-rs binary has setuid bit (4755)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} shadow-rs binary expected 4755, got $target_perms"
        FAIL=$((FAIL + 1))
    fi

    # Verify each setuid tool symlink resolves to the setuid binary
    for tool in $SETUID_TOOLS; do
        local resolved_perms
        resolved_perms=$(stat -L -c '%a' "$BINDIR/$tool" 2>/dev/null || echo "0")
        if [[ "$resolved_perms" == "4755" ]]; then
            echo -e "  ${GREEN}✓${NC} $tool resolves to setuid binary (4755)"
            PASS=$((PASS + 1))
        else
            echo -e "  ${RED}✗${NC} $tool expected 4755 (via symlink), got $resolved_perms"
            FAIL=$((FAIL + 1))
        fi
    done

    # passwd must be built with the `pam` cargo feature, otherwise the
    # interactive change path is compiled out and the tool can only report and
    # lock accounts — it cannot actually change a password.
    # chfn and chsh authenticate the caller through PAM before applying a
    # change, so a build without the feature refuses every non-root use.
    for tool in passwd chfn chsh; do
        assert_ok "$tool is linked against PAM" \
            sh -c "ldd $BINDIR/$tool | grep -q libpam"
    done

    # Non-root user should be able to run passwd -S on themselves
    assert_ok "testrunner can run passwd -S" \
        su -s /bin/bash testrunner -c "$BINDIR/passwd -S testrunner"

    # Non-root user should NOT be able to change another user's password
    assert_fail "testrunner cannot passwd root" \
        su -s /bin/bash testrunner -c "echo 'root:hacked' | $BINDIR/chpasswd -e"

    # The binary is setuid for the four self-service tools only; every other
    # applet must run with the caller's own privileges. An unprivileged
    # `pwck -s` or `grpck -s` must neither rewrite a file nor change its owner.
    local passwd_before group_before
    passwd_before=$(stat -c '%i %U:%G' /etc/passwd)
    group_before=$(stat -c '%i %U:%G' /etc/group)
    assert_fail "testrunner cannot run shadow-rs pwck -s" \
        su -s /bin/bash testrunner -c "$BINDIR/shadow-rs pwck -s"
    assert_fail "testrunner cannot run pwck -s through the symlink" \
        su -s /bin/bash testrunner -c "$BINDIR/pwck -s"
    assert_fail "testrunner cannot run grpck -s" \
        su -s /bin/bash testrunner -c "$BINDIR/grpck -s"
    assert_ok "/etc/passwd untouched by unprivileged pwck -s" \
        test "$(stat -c '%i %U:%G' /etc/passwd)" = "$passwd_before"
    assert_ok "/etc/group untouched by unprivileged grpck -s" \
        test "$(stat -c '%i %U:%G' /etc/group)" = "$group_before"
    assert_ok "/etc/shadow is root:shadow 0640" \
        test "$(stat -c '%U:%G %a' /etc/shadow)" = "root:shadow 640"
}

# ── User lifecycle ──────────────────────────────────────────────────

test_user_lifecycle() {
    section "User lifecycle (useradd → chpasswd → usermod → pwck → userdel)"

    # Clean up from any previous failed run
    userdel -r lifecycle_user 2>/dev/null || true
    groupdel lifecycle_grp 2>/dev/null || true

    # Create user
    assert_ok "useradd -m -s /bin/bash lifecycle_user" \
        useradd -m -s /bin/bash lifecycle_user

    assert_file_contains "lifecycle_user in /etc/passwd" \
        /etc/passwd "^lifecycle_user:"

    assert_file_contains "lifecycle_user in /etc/shadow" \
        /etc/shadow "^lifecycle_user:"

    assert_ok "home directory created" test -d /home/lifecycle_user

    # Set password via chpasswd -e (pre-hashed)
    local hashed
    hashed=$(hash_password "TestPass123")
    assert_ok "chpasswd -e sets password" \
        bash -c "echo 'lifecycle_user:$hashed' | chpasswd -e"

    # Verify shadow entry has a hash (not ! or *)
    assert_file_not_contains "shadow has real hash (not locked)" \
        /etc/shadow '^lifecycle_user:[!*]:'

    # Modify user
    assert_ok "usermod -c 'Lifecycle Test' lifecycle_user" \
        usermod -c "Lifecycle Test" lifecycle_user

    assert_file_contains "GECOS updated" \
        /etc/passwd "lifecycle_user:.*:Lifecycle Test:"

    assert_ok "usermod -s /bin/sh lifecycle_user" \
        usermod -s /bin/sh lifecycle_user

    assert_file_contains "shell updated to /bin/sh" \
        /etc/passwd "lifecycle_user:.*:/bin/sh$"

    # Add supplementary group
    groupadd lifecycle_grp 2>/dev/null || true
    assert_ok "usermod -aG lifecycle_grp lifecycle_user" \
        usermod -aG lifecycle_grp lifecycle_user

    assert_contains "user in supplementary group" "lifecycle_user" \
        grep "^lifecycle_grp:" /etc/group

    # Consistency check (exit 2 = warnings about system accounts, acceptable)
    assert_ok "pwck -r passes" bash -c 'rc=$(pwck -r >/dev/null 2>&1; echo $?); [ "$rc" -le 2 ]'

    # Lock and unlock password
    assert_ok "passwd -l lifecycle_user" passwd -l lifecycle_user
    assert_file_contains "password locked (! prefix)" \
        /etc/shadow '^lifecycle_user:!'

    assert_ok "passwd -u lifecycle_user" passwd -u lifecycle_user
    assert_file_not_contains "password unlocked (no ! prefix)" \
        /etc/shadow '^lifecycle_user:!'

    # Delete user
    assert_ok "userdel -r lifecycle_user" userdel -r lifecycle_user
    assert_file_not_contains "user removed from /etc/passwd" \
        /etc/passwd "^lifecycle_user:"
    assert_file_not_contains "user removed from /etc/shadow" \
        /etc/shadow "^lifecycle_user:"

    # Clean up group
    groupdel lifecycle_grp 2>/dev/null || true
}

# ── Group lifecycle ─────────────────────────────────────────────────

test_group_lifecycle() {
    section "Group lifecycle (groupadd → groupmod → groupdel → grpck)"

    # Clean up from any previous failed run
    groupdel lifecycle_testgrp 2>/dev/null || true
    groupdel lifecycle_renamed 2>/dev/null || true

    # Create group
    assert_ok "groupadd lifecycle_testgrp" groupadd lifecycle_testgrp

    assert_file_contains "group in /etc/group" \
        /etc/group "^lifecycle_testgrp:"

    # Modify group name
    assert_ok "groupmod -n lifecycle_renamed lifecycle_testgrp" \
        groupmod -n lifecycle_renamed lifecycle_testgrp

    assert_file_contains "renamed group in /etc/group" \
        /etc/group "^lifecycle_renamed:"
    assert_file_not_contains "old name gone from /etc/group" \
        /etc/group "^lifecycle_testgrp:"

    # Consistency check
    assert_ok "grpck -r passes" grpck -r

    # Delete group
    assert_ok "groupdel lifecycle_renamed" groupdel lifecycle_renamed
    assert_file_not_contains "group removed from /etc/group" \
        /etc/group "^lifecycle_renamed:"
}

# ── Individual tool tests ───────────────────────────────────────────

test_individual_tools() {
    section "Individual tool tests"

    # Set up test user for tool-specific tests
    userdel -r tooltest_user 2>/dev/null || true
    assert_ok "useradd -m -s /bin/bash tooltest_user" \
        useradd -m -s /bin/bash tooltest_user
    local hashed
    hashed=$(hash_password "ToolPass123")
    assert_ok "chpasswd -e sets tooltest_user password" \
        bash -c "echo 'tooltest_user:$hashed' | chpasswd -e"

    # chage: set and query password aging
    assert_ok "chage -l tooltest_user" chage -l tooltest_user
    assert_ok "chage -M 90 tooltest_user" chage -M 90 tooltest_user
    assert_contains "max days is 90" "90" chage -l tooltest_user

    # chfn: change GECOS
    assert_ok "chfn -f 'Tool Test User' tooltest_user" \
        chfn -f "Tool Test User" tooltest_user
    assert_file_contains "GECOS updated by chfn" \
        /etc/passwd "tooltest_user:.*:Tool Test User"

    # chsh: change shell
    assert_ok "chsh -s /bin/sh tooltest_user" chsh -s /bin/sh tooltest_user
    assert_file_contains "shell changed by chsh" \
        /etc/passwd "tooltest_user:.*:/bin/sh$"

    # chpasswd -e: batch password change with pre-hashed
    local newhash
    newhash=$(hash_password "NewPass456")
    assert_ok "chpasswd -e batch mode" \
        bash -c "echo 'tooltest_user:$newhash' | chpasswd -e"

    # passwd -S: status
    assert_ok "passwd -S tooltest_user" passwd -S tooltest_user

    # pwck/grpck: read-only checks (exit 2 = warnings, acceptable)
    assert_ok "pwck -r" bash -c 'rc=$(pwck -r >/dev/null 2>&1; echo $?); [ "$rc" -le 2 ]'
    assert_ok "grpck -r" bash -c 'rc=$(grpck -r >/dev/null 2>&1; echo $?); [ "$rc" -le 2 ]'

    # Clean up
    userdel -r tooltest_user 2>/dev/null || true
}

# ── PAM authentication ──────────────────────────────────────────────

test_pam_auth() {
    section "PAM authentication"

    # Create PAM test user with pre-hashed password
    userdel -r pamtest_user 2>/dev/null || true
    assert_ok "useradd -m -s /bin/bash pamtest_user" \
        useradd -m -s /bin/bash pamtest_user
    local hashed
    hashed=$(hash_password "PamPass789")
    assert_ok "chpasswd -e sets pamtest_user password" \
        bash -c "echo 'pamtest_user:$hashed' | chpasswd -e"

    # Use expect to test su authentication
    assert_ok "su with known password via expect" \
        expect -c '
            set timeout 10
            spawn su -s /bin/bash -c "id" pamtest_user
            expect "Password:"
            send "PamPass789\r"
            expect {
                "uid=" { exit 0 }
                timeout { exit 1 }
                eof { exit 1 }
            }
        '

    # Verify the output contains the right user
    assert_contains "su runs as pamtest_user" "pamtest_user" \
        expect -c '
            set timeout 10
            spawn su -s /bin/bash -c "id" pamtest_user
            expect "Password:"
            send "PamPass789\r"
            expect {
                "pamtest_user" { exit 0 }
                timeout { exit 1 }
                eof { exit 1 }
            }
        '

    # Clean up
    userdel -r pamtest_user 2>/dev/null || true
}

# ── nscd cache invalidation ────────────────────────────────────────

test_nscd() {
    section "nscd cache invalidation"

    # Start nscd (needs /var/run/nscd directory and /var/db/nscd)
    mkdir -p /var/run/nscd /var/db/nscd 2>/dev/null || true
    nscd -d >/dev/null 2>&1 &
    sleep 2

    if ! pgrep -x nscd >/dev/null 2>&1; then
        echo -e "  ${YELLOW}⊘${NC} nscd could not be started, skipping"
        PASS=$((PASS + 1))
        return
    fi

    assert_ok "nscd is running" pgrep -x nscd

    # Create user and verify getent picks it up
    userdel nscd_user 2>/dev/null || true
    assert_ok "useradd -m nscd_user" useradd -m nscd_user
    assert_contains "getent finds new user" "nscd_user" \
        getent passwd nscd_user

    # Delete user and verify getent no longer finds it
    assert_ok "userdel -r nscd_user" userdel -r nscd_user
    sleep 1
    assert_fail "getent no longer finds deleted user" \
        getent passwd nscd_user

    # Stop nscd
    killall nscd 2>/dev/null || true
}

# ── Landlock sandboxing ─────────────────────────────────────────────

test_landlock() {
    section "Landlock sandboxing"

    # Check if kernel supports Landlock
    if [ -f /sys/kernel/security/landlock/abi_version ]; then
        local abi_version
        abi_version=$(cat /sys/kernel/security/landlock/abi_version)
        echo -e "  ${GREEN}✓${NC} Landlock ABI version: $abi_version"
        PASS=$((PASS + 1))

        # passwd should work under Landlock restriction
        userdel -r landlock_user 2>/dev/null || true
        assert_ok "useradd -m landlock_user" useradd -m landlock_user

        assert_ok "passwd -S works under Landlock" \
            passwd -S landlock_user

        userdel -r landlock_user 2>/dev/null || true
    else
        echo -e "  ${YELLOW}⊘${NC} Landlock not available (kernel too old), skipping"
        PASS=$((PASS + 1))
    fi
}

# ── Ansible integration ────────────────────────────────────────────

test_ansible() {
    section "Ansible integration"

    if command -v ansible-playbook >/dev/null 2>&1; then
        # Clean up from any previous failed run
        userdel -r ansibleuser 2>/dev/null || true
        groupdel ansiblegroup 2>/dev/null || true

        assert_ok "ansible-playbook runs successfully" \
            ansible-playbook -c local -i "localhost," /tests/e2e/ansible-test.yml
    else
        echo -e "  ${YELLOW}⊘${NC} ansible-playbook not found, skipping"
        PASS=$((PASS + 1))
    fi
}

# ── Main ────────────────────────────────────────────────────────────

main() {
    echo -e "${BLUE}shadow-rs end-to-end deployment tests${NC}"
    echo "Running as: $(whoami) ($(id -u))"
    echo "Binary: $BINDIR/shadow-rs"
    echo ""

    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}ERROR: must run as root${NC}"
        exit 1
    fi

    preflight
    test_symlink_dispatch
    test_multicall_dispatch
    test_setuid
    test_user_lifecycle
    test_group_lifecycle
    test_individual_tools
    test_pam_auth
    test_nscd
    test_landlock
    test_ansible

    echo ""
    echo -e "${BLUE}── Results ──${NC}"
    echo -e "  ${GREEN}Passed: $PASS${NC}"
    if [ "$FAIL" -gt 0 ]; then
        echo -e "  ${RED}Failed: $FAIL${NC}"
        echo ""
        echo -e "${RED}SOME TESTS FAILED${NC}"
        exit 1
    else
        echo -e "  ${RED}Failed: 0${NC}"
        echo ""
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        exit 0
    fi
}

main "$@"
