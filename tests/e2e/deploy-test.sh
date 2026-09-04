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

# The tools an unprivileged user runs are installed in bin, the rest in sbin,
# which is the split the GNU package uses: sbin is not on a normal user's
# PATH, so `passwd` there would be "command not found".
USER_TOOLS="passwd chfn chsh newgrp chage"
BINDIR="/usr/sbin"
USER_BINDIR="/usr/bin"

# Where a given tool's symlink was installed.
tool_path() {
    case " $USER_TOOLS " in
    *" $1 "*) echo "/usr/bin/$1" ;;
    *) echo "/usr/sbin/$1" ;;
    esac
}

# ── Preflight ───────────────────────────────────────────────────────

preflight() {
    section "Preflight checks"

    assert_ok "shadow-rs binary exists" test -x "$BINDIR/shadow-rs"
    assert_ok "shadow-rs --list succeeds" "$BINDIR/shadow-rs" --list

    for tool in $TOOLS; do
        local path
        path=$(tool_path "$tool")
        assert_ok "symlink exists: $path" test -L "$path"
        assert_ok "symlink $tool resolves to shadow-rs" \
            bash -c "readlink -f '$path' | grep -q 'shadow-rs'"
    done

    # An unprivileged user must be able to run their own tools by name.
    for tool in $USER_TOOLS; do
        assert_ok "$tool is on an unprivileged user's PATH" \
            su -s /bin/bash testrunner -c "command -v $tool >/dev/null"
    done
}

# ── Symlink dispatch ────────────────────────────────────────────────

test_symlink_dispatch() {
    section "Symlink dispatch (argv[0])"

    for tool in $TOOLS; do
        assert_ok "$tool --help via symlink" "$(tool_path "$tool")" --help
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
        resolved_perms=$(stat -L -c '%a' "$(tool_path "$tool")" 2>/dev/null || echo "0")
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
            sh -c "ldd $(tool_path "$tool") | grep -q libpam"
    done

    # Non-root user should be able to run passwd -S on themselves
    assert_ok "testrunner can run passwd -S" \
        su -s /bin/bash testrunner -c "$USER_BINDIR/passwd -S testrunner"

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
    # Every rewrite must leave the file as the distribution installed it;
    # unix_chkpwd and friends are sgid shadow and rely on it.
    assert_ok "/etc/shadow is still root:shadow 0640 after passwd -l" \
        test "$(stat -c '%U:%G %a' /etc/shadow)" = "root:shadow 640"

    # Locking twice must leave one marker: a second would need a second
    # unlock, and `passwd -u` refuses to unlock an account that would stay
    # locked, so the tool could not undo its own second lock.
    assert_ok "passwd -l lifecycle_user again" passwd -l lifecycle_user
    assert_ok "a second lock adds no second marker" \
        bash -c "! grep -q '^lifecycle_user:!!' /etc/shadow"

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

# Authenticate as $1 with password $2 through `su` run by testrunner. Root's
# own `su` never asks for a password (pam_rootok), so an unprivileged caller is
# the only way to make PAM actually verify one. Exit 0 = authenticated.
su_as_testrunner() {
    expect -c "
        set timeout 15
        log_user 0
        spawn su -s /bin/bash testrunner -c {su -s /bin/bash -c id $1}
        expect {
            -nocase {password:} { send \"$2\r\"; exp_continue }
            {uid=} { exit 0 }
            -nocase {failure} { exit 1 }
            eof { exit 2 }
            timeout { exit 3 }
        }
    "
}

# $1 changes their own password from $2 to $3 with our passwd, as themselves.
# Runs under `su -c`, which has no controlling terminal, so the prompts arrive
# on stdin/stderr — the path the conversation function must handle.
change_own_password() {
    expect -c "
        set timeout 20
        log_user 0
        spawn su -s /bin/bash $1 -c $USER_BINDIR/passwd
        expect {
            -nocase -re {current.*password:|\\(current\\).*:} { send \"$2\r\"; exp_continue }
            -nocase -re {new.*password:} { send \"$3\r\"; exp_continue }
            -nocase -re {(retype|again).*:} { send \"$3\r\"; exp_continue }
            -nocase {failure} { exit 10 }
            eof { catch wait result; exit [lindex \$result 3] }
            timeout { exit 99 }
        }
    "
}

# root sets $1's password to $2 with our passwd (no current password asked).
set_password_as_root() {
    expect -c "
        set timeout 20
        log_user 0
        spawn $USER_BINDIR/passwd $1
        expect {
            -nocase -re {new.*password:} { send \"$2\r\"; exp_continue }
            -nocase -re {(retype|again).*:} { send \"$2\r\"; exp_continue }
            eof { catch wait result; exit [lindex \$result 3] }
            timeout { exit 99 }
        }
    "
}

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

    assert_ok "known password authenticates through PAM" \
        su_as_testrunner pamtest_user PamPass789
    assert_fail "wrong password is rejected" \
        su_as_testrunner pamtest_user WrongPass000

    # The reason passwd is setuid: a user changes their own password. This is
    # pam_unix end to end — authenticate with the current password through
    # the unprivileged helper, then rewrite /etc/shadow with the privilege the
    # setuid bit provides.
    assert_ok "pamtest_user changes own password with passwd" \
        change_own_password pamtest_user PamPass789 NewPass456
    assert_ok "new password authenticates" \
        su_as_testrunner pamtest_user NewPass456
    assert_fail "old password no longer authenticates" \
        su_as_testrunner pamtest_user PamPass789
    assert_ok "/etc/shadow is still root:shadow 0640 after a PAM change" \
        test "$(stat -c '%U:%G %a' /etc/shadow)" = "root:shadow 640"

    assert_ok "root sets pamtest_user's password with passwd" \
        set_password_as_root pamtest_user RootSet321
    assert_ok "root-set password authenticates" \
        su_as_testrunner pamtest_user RootSet321

    # Clean up
    userdel -r pamtest_user 2>/dev/null || true
}

# ── Self-service tools: chfn and chsh ───────────────────────────────

# $1 runs chsh interactively as themselves, answering the shell prompt with $2
# and any password prompt with $3. Exits with chsh's own status.
chsh_interactive() {
    expect -c "
        set timeout 20
        log_user 0
        spawn su -s /bin/bash $1 -c $USER_BINDIR/chsh
        expect {
            -nocase -re {login shell.*:} { send \"$2\r\"; exp_continue }
            -nocase -re {password:} { send \"$3\r\"; exp_continue }
            eof { catch wait result; exit [lindex \$result 3] }
            timeout { exit 99 }
        }
    "
}

# $1 runs chfn interactively as themselves, answering the room prompt with $2,
# every other field with ENTER, and any password prompt with $3.
chfn_interactive() {
    expect -c "
        set timeout 20
        log_user 0
        spawn su -s /bin/bash $1 -c $USER_BINDIR/chfn
        expect {
            -nocase -re {room number.*:} { send \"$2\r\"; exp_continue }
            -nocase -re {(full name|work phone|home phone).*:} { send \"\r\"; exp_continue }
            -nocase -re {password:} { send \"$3\r\"; exp_continue }
            eof { catch wait result; exit [lindex \$result 3] }
            timeout { exit 99 }
        }
    "
}

# $1 asks chsh for shell $2 and must be refused *before* any password prompt:
# the value is checked first, so a rejected shell never costs a password.
# Exit 0 only if chsh failed and never prompted. $3 is the expected message.
chsh_refused_without_prompt() {
    expect -c "
        set timeout 20
        log_user 0
        spawn su -s /bin/bash $1 -c {$USER_BINDIR/chsh -s $2}
        expect {
            -nocase -re {password:} { exit 20 }
            -nocase {$3} { exp_continue }
            eof { catch wait result;
                  if {[lindex \$result 3] == 0} { exit 21 } else { exit 0 } }
            timeout { exit 99 }
        }
    "
}

# Same, but exit 0 only if the message does NOT appear.
chsh_message_absent() {
    expect -c "
        set timeout 20
        log_user 0
        spawn su -s /bin/bash $1 -c {$USER_BINDIR/chsh -s $2}
        expect {
            -nocase {$3} { exit 22 }
            eof { exit 0 }
            timeout { exit 99 }
        }
    "
}

test_self_service() {
    section "Self-service tools (chfn, chsh)"

    userdel -r selftest_user 2>/dev/null || true
    assert_ok "useradd -m -s /bin/bash selftest_user" \
        useradd -m -s /bin/bash selftest_user
    local hashed
    hashed=$(hash_password "SelfPass123")
    assert_ok "chpasswd -e sets selftest_user password" \
        bash -c "echo 'selftest_user:$hashed' | chpasswd -e"

    grep -q '^/bin/sh$' /etc/shells 2>/dev/null || echo /bin/sh >>/etc/shells
    grep -q '^/bin/bash$' /etc/shells 2>/dev/null || echo /bin/bash >>/etc/shells

    # A user changes their own shell with no -s: chsh prompts, PAM verifies.
    assert_ok "selftest_user changes own shell interactively" \
        chsh_interactive selftest_user /bin/sh SelfPass123
    assert_file_contains "interactive chsh wrote the new shell" \
        /etc/passwd "selftest_user:.*:/bin/sh$"

    # Pressing ENTER keeps the current value and is not an error.
    assert_ok "empty answer keeps the current shell" \
        chsh_interactive selftest_user "" SelfPass123
    assert_file_contains "shell unchanged after an empty answer" \
        /etc/passwd "selftest_user:.*:/bin/sh$"

    # chsh is setuid-root, so its existence check sees what root sees. A
    # non-root caller must get the same answer for an unlisted path whether or
    # not it exists, or the tool becomes a filesystem oracle.
    local secret=/root/.chsh-oracle-probe
    : >"$secret"
    chmod 600 "$secret"
    assert_ok "unlisted existing path under /root is refused as unlisted" \
        chsh_refused_without_prompt selftest_user "$secret" "is not listed"
    assert_ok "unlisted missing path under /root gives the same answer" \
        chsh_refused_without_prompt selftest_user /root/.chsh-absent "is not listed"
    assert_ok "existence of a /root path is never disclosed" \
        chsh_message_absent selftest_user "$secret" "does not exist"
    rm -f "$secret"

    # An empty shell field is the system default, not a missing program.
    assert_ok "root may set the empty shell" chsh -s "" selftest_user
    assert_file_contains "empty shell field written" \
        /etc/passwd "^selftest_user:.*:/home/selftest_user:$"
    assert_ok "chsh -s /bin/bash restores a shell" chsh -s /bin/bash selftest_user

    # chfn with no field option prompts for each field the caller may change.
    assert_ok "CHFN_RESTRICT=rwh in login.defs" \
        bash -c "sed -i '/^CHFN_RESTRICT/d' /etc/login.defs; echo 'CHFN_RESTRICT rwh' >>/etc/login.defs"
    assert_ok "selftest_user changes own room interactively" \
        chfn_interactive selftest_user B-217 SelfPass123
    assert_file_contains "interactive chfn wrote the room number" \
        /etc/passwd "selftest_user:.*:,B-217,"

    # 'f' is absent from CHFN_RESTRICT, so the full name is not the caller's
    # to change — and the refusal must arrive without a password prompt.
    assert_fail "selftest_user may not change the full name under CHFN_RESTRICT=rwh" \
        su -s /bin/bash selftest_user -c "$USER_BINDIR/chfn -f Nope </dev/null"
    assert_ok "root may still change the full name" \
        chfn -f "Self Test User" selftest_user
    assert_file_contains "root-set full name written" \
        /etc/passwd "selftest_user:.*:Self Test User,"

    userdel -r selftest_user 2>/dev/null || true
}

# ── Aging fields, batch input and newgrp ────────────────────────────

# Print the value column of one `chage -l` line, e.g. aging_field 2 alice
# for "Password expires".
aging_field() {
    chage -l "$2" | sed -n "$1p" | sed 's/.*: //'
}

test_aging_and_input() {
    section "Aging fields, batch input, newgrp"

    userdel -r aging_user 2>/dev/null || true
    assert_ok "useradd -m aging_user" useradd -m aging_user

    # A last-change day of 0 is `passwd -e`'s marker, not a date, and it makes
    # both derived dates meaningless too.
    assert_ok "chage -d 0 aging_user" chage -d 0 aging_user
    assert_ok "last change reports 'password must be changed'" \
        test "$(aging_field 1 aging_user)" = "password must be changed"
    assert_ok "password expiry reports 'password must be changed'" \
        test "$(aging_field 2 aging_user)" = "password must be changed"
    assert_ok "password inactive reports 'password must be changed'" \
        test "$(aging_field 3 aging_user)" = "password must be changed"

    # The threshold above which a maximum age means "no expiry" is 10000.
    assert_ok "chage -d 2026-01-01 -M 9999 aging_user" \
        chage -d 2026-01-01 -M 9999 aging_user
    assert_ok "max 9999 gives a real expiry date" \
        test "$(aging_field 2 aging_user)" = "May 18, 2053"
    assert_ok "chage -M 10000 aging_user" chage -M 10000 aging_user
    assert_ok "max 10000 means never" \
        test "$(aging_field 2 aging_user)" = "never"

    # -1 clears a field; anything else negative is a usage error.
    assert_ok "chage -M -1 clears the maximum" chage -M -1 aging_user
    assert_ok "cleared maximum reads back as -1" \
        test "$(aging_field 6 aging_user)" = "-1"
    assert_fail "chage -M -5 is refused" chage -M -5 aging_user
    assert_fail "chage -d -5 is refused" chage -d -5 aging_user

    # An unknown login is an ordinary failure (1), not "no shadow file" (15).
    assert_ok "chage -l on an unknown login exits 1" \
        bash -c 'chage -l no-such-user-4b2 >/dev/null 2>&1; [ "$?" -eq 1 ]'
    assert_ok "passwd -S on an unknown login exits 1" \
        bash -c 'passwd -S no-such-user-4b2 >/dev/null 2>&1; [ "$?" -eq 1 ]'

    # chpasswd takes its default hashing scheme from login.defs, as the rest
    # of the system does; hard-coding one wrote weaker hashes than configured.
    assert_ok "ENCRYPT_METHOD YESCRYPT in login.defs" \
        bash -c "sed -i '/^ENCRYPT_METHOD/d' /etc/login.defs; echo 'ENCRYPT_METHOD YESCRYPT' >>/etc/login.defs"
    assert_ok "chpasswd hashes aging_user" \
        bash -c "echo 'aging_user:BatchPass123' | chpasswd"
    assert_file_contains "chpasswd used yescrypt as configured" \
        /etc/shadow 'aging_user:\$y\$'
    assert_ok "ENCRYPT_METHOD SHA512 in login.defs" \
        bash -c "sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs"
    assert_ok "chpasswd hashes aging_user again" \
        bash -c "echo 'aging_user:BatchPass456' | chpasswd"
    assert_file_contains "chpasswd followed the changed configuration" \
        /etc/shadow 'aging_user:\$6\$'
    assert_ok "-c overrides the configured default" \
        bash -c "echo 'aging_user:BatchPass789' | chpasswd -c SHA256"
    assert_file_contains "explicit -c wins" /etc/shadow 'aging_user:\$5\$'

    # Flag combinations chpasswd(8) documents as errors.
    assert_ok "-s without -c is a usage error (exit 2)" \
        bash -c 'echo "aging_user:x" | chpasswd -s 5000 >/dev/null 2>&1; [ "$?" -eq 2 ]'
    assert_ok "-e with -c is a usage error (exit 2)" \
        bash -c 'echo "aging_user:x" | chpasswd -e -c SHA512 >/dev/null 2>&1; [ "$?" -eq 2 ]'

    # --prefix on chage and chpasswd, so their behaviour is testable without
    # touching the live files.
    local pfx
    pfx=$(mktemp -d)
    mkdir -p "$pfx/etc"
    printf 'pfxuser:x:4000:4000::/home/pfxuser:/bin/sh\n' >"$pfx/etc/passwd"
    printf 'pfxuser:!:19000:0:99999:7:::\n' >"$pfx/etc/shadow"
    assert_ok "chage --prefix reads the prefixed shadow file" \
        chage -P "$pfx" -l pfxuser
    assert_ok "chage --prefix writes the prefixed shadow file" \
        chage -P "$pfx" -M 42 pfxuser
    assert_file_contains "prefixed maximum age written" \
        "$pfx/etc/shadow" 'pfxuser:!:19000:0:42:'
    assert_ok "chpasswd --prefix writes the prefixed shadow file" \
        bash -c "echo 'pfxuser:PrefixPass1' | chpasswd -P '$pfx'"
    assert_ok "the live shadow file was untouched by --prefix" \
        bash -c "! grep -q '^pfxuser:' /etc/shadow"
    rm -rf "$pfx"

    # newgrp: without '-' the environment and working directory survive; with
    # '-' the shell is a login shell in a reinitialized environment.
    groupadd -f newgrp_grp >/dev/null 2>&1
    usermod -aG newgrp_grp aging_user
    assert_ok "newgrp switches the primary group" \
        bash -c "su -s /bin/bash aging_user -c 'echo id -gn | newgrp newgrp_grp' | grep -qx newgrp_grp"
    assert_ok "newgrp keeps the caller's environment" \
        bash -c "su -s /bin/bash aging_user -c 'MARKER=kept; export MARKER; echo \"echo \\\$MARKER\" | newgrp newgrp_grp' | grep -qx kept"
    assert_ok "newgrp - reinitializes the environment" \
        bash -c "su -s /bin/bash aging_user -c 'MARKER=kept; export MARKER; echo \"echo m=\\\$MARKER\" | newgrp - newgrp_grp' | grep -qx 'm='"
    assert_ok "newgrp - still switches the group" \
        bash -c "su -s /bin/bash aging_user -c 'echo id -gn | newgrp - newgrp_grp' | grep -qx newgrp_grp"
    assert_fail "newgrp rejects a misplaced dash" \
        su -s /bin/bash aging_user -c "newgrp newgrp_grp - </dev/null"

    groupdel newgrp_grp 2>/dev/null || true
    userdel -r aging_user 2>/dev/null || true
}

# ── Audit logging ───────────────────────────────────────────────────

test_audit_logging() {
    section "Audit logging"

    # The tools write their records straight to /dev/log rather than forking
    # `logger` for each event, so the test needs a daemon listening there.
    rsyslogd -n >/dev/null 2>&1 &
    local rsyslog_pid=$!
    sleep 2

    if [ ! -S /dev/log ]; then
        echo -e "  ${YELLOW}⊘${NC} no /dev/log socket, skipping"
        kill "$rsyslog_pid" 2>/dev/null || true
        return
    fi

    userdel -r audit_user 2>/dev/null || true
    assert_ok "useradd -m audit_user" useradd -m audit_user
    assert_ok "userdel -r audit_user" userdel -r audit_user
    sleep 1

    local log=/var/log/auth.log
    [ -f "$log" ] || log=/var/log/syslog
    assert_ok "syslog received the account creation" \
        bash -c "grep -q 'op=ADD_USER.*acct=\"audit_user\".*res=success' $log"
    assert_ok "syslog received the account deletion" \
        bash -c "grep -q 'op=DEL_USER.*acct=\"audit_user\"' $log"
    assert_ok "the record is tagged shadow-rs" \
        bash -c "grep -q 'shadow-rs\[[0-9]*\]:.*op=ADD_USER' $log"

    kill "$rsyslog_pid" 2>/dev/null || true
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
        # The mutation path spawns nscd/logger and rewrites the file inside
        # the sandbox; both have to be allowed by the rule set.
        assert_ok "passwd -l works under Landlock" passwd -l landlock_user
        assert_file_contains "lock applied under Landlock" \
            /etc/shadow '^landlock_user:!'
        assert_ok "passwd -u works under Landlock" passwd -u landlock_user
        assert_ok "passwd -x 90 works under Landlock" passwd -x 90 landlock_user
        assert_ok "unprivileged passwd -S works under Landlock" \
            su -s /bin/bash testrunner -c "passwd -S testrunner"

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
    test_self_service
    test_aging_and_input
    test_audit_logging
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
