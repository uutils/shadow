#!/usr/bin/env bash
# spell-checker:ignore timeformat tempdir ldd passwd pwck
#
# Benchmark script for shadow-rs vs upstream shadow.
#
# Compares performance, binary size, and shared library dependencies
# between shadow-rs (Rust) and upstream shadow (C) implementations.
#
# Usage:
#   docker compose run --rm debian bash benches/benchmark.sh
#
# Requirements:
#   - Must run inside Docker (needs both upstream shadow and shadow-rs)
#   - Must run as root (passwd -S and pwck require root or shadow access)
#
# The script builds shadow-rs in release mode, locates upstream shadow
# binaries, and runs comparative benchmarks.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PASSWD_STATUS_ITERS=1000
PWCK_ITERS=100

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33mWARN: %s\033[0m\n' "$*"; }
err()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*"; exit 1; }

# Print a separator line.
separator() { printf '%.0s-' {1..72}; printf '\n'; }

# Format bytes as human-readable.
human_size() {
    local bytes=$1
    if [ "$bytes" -ge 1048576 ]; then
        printf '%.1f MiB' "$(echo "$bytes / 1048576" | bc -l)"
    elif [ "$bytes" -ge 1024 ]; then
        printf '%.1f KiB' "$(echo "$bytes / 1024" | bc -l)"
    else
        printf '%d B' "$bytes"
    fi
}

# Time a command N times, report wall-clock total in seconds.
# Usage: bench_command <label> <iterations> <command...>
bench_command() {
    local label=$1
    local iters=$2
    shift 2

    log "Benchmarking: $label ($iters iterations)"

    local start end elapsed
    start=$(date +%s%N)
    for ((i = 0; i < iters; i++)); do
        "$@" >/dev/null 2>&1 || true
    done
    end=$(date +%s%N)

    elapsed=$(echo "scale=3; ($end - $start) / 1000000000" | bc)
    local per_iter
    per_iter=$(echo "scale=6; $elapsed / $iters" | bc)

    printf '  %-30s  total: %8ss  per-iter: %ss\n' "$label" "$elapsed" "$per_iter"
    echo "$elapsed"
}

# ---------------------------------------------------------------------------
# Locate binaries
# ---------------------------------------------------------------------------

find_upstream_binary() {
    local name=$1
    # Upstream shadow binaries are typically in /usr/sbin or /usr/bin.
    for path in /usr/sbin/"$name" /usr/bin/"$name" /sbin/"$name" /bin/"$name"; do
        if [ -x "$path" ]; then
            # Make sure it is NOT our shadow-rs binary (check for ELF or "shadow-rs").
            if ! file "$path" 2>/dev/null | grep -q 'statically linked\|shadow-rs'; then
                echo "$path"
                return 0
            fi
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Build shadow-rs
# ---------------------------------------------------------------------------

log "Building shadow-rs in release mode..."
cargo build --release --quiet 2>&1

SHADOW_RS_DIR="$(cargo metadata --format-version=1 --no-deps 2>/dev/null | \
    python3 -c 'import sys,json; print(json.load(sys.stdin)["target_directory"])' 2>/dev/null || \
    echo "target")/release"

# The multicall binary.
SHADOW_RS_BIN="$SHADOW_RS_DIR/shadow-rs"

if [ ! -x "$SHADOW_RS_BIN" ]; then
    # Try individual binaries.
    SHADOW_RS_BIN=""
fi

# Individual tool binaries (built by cargo as separate bins).
RS_PASSWD="$SHADOW_RS_DIR/passwd"
RS_PWCK="$SHADOW_RS_DIR/pwck"

# Fall back to the multicall binary if individual bins are not found.
if [ ! -x "$RS_PASSWD" ] && [ -x "$SHADOW_RS_DIR/shadow-rs" ]; then
    RS_PASSWD="$SHADOW_RS_DIR/shadow-rs"
fi
if [ ! -x "$RS_PWCK" ] && [ -x "$SHADOW_RS_DIR/shadow-rs" ]; then
    RS_PWCK="$SHADOW_RS_DIR/shadow-rs"
fi

# Locate upstream binaries.
UPSTREAM_PASSWD=$(find_upstream_binary passwd) || UPSTREAM_PASSWD=""
UPSTREAM_PWCK=$(find_upstream_binary pwck) || UPSTREAM_PWCK=""

separator
log "Binary locations:"
printf '  %-20s %s\n' "shadow-rs passwd:" "${RS_PASSWD:-NOT FOUND}"
printf '  %-20s %s\n' "shadow-rs pwck:" "${RS_PWCK:-NOT FOUND}"
printf '  %-20s %s\n' "upstream passwd:" "${UPSTREAM_PASSWD:-NOT FOUND}"
printf '  %-20s %s\n' "upstream pwck:" "${UPSTREAM_PWCK:-NOT FOUND}"
separator

# ---------------------------------------------------------------------------
# Binary size comparison
# ---------------------------------------------------------------------------

log "Binary size comparison"
printf '\n'
printf '  %-35s %12s\n' "Binary" "Size"
separator

report_size() {
    local label=$1
    local path=$2
    if [ -x "$path" ]; then
        local size
        size=$(stat --format='%s' "$path" 2>/dev/null || stat -f '%z' "$path" 2>/dev/null || echo 0)
        printf '  %-35s %12s (%d bytes)\n' "$label" "$(human_size "$size")" "$size"
    else
        printf '  %-35s %12s\n' "$label" "N/A"
    fi
}

report_size "shadow-rs multicall" "$SHADOW_RS_DIR/shadow-rs"
report_size "shadow-rs passwd" "$RS_PASSWD"
report_size "shadow-rs pwck" "$RS_PWCK"
report_size "upstream passwd" "$UPSTREAM_PASSWD"
report_size "upstream pwck" "$UPSTREAM_PWCK"
printf '\n'

# ---------------------------------------------------------------------------
# Shared library dependencies
# ---------------------------------------------------------------------------

log "Shared library dependencies"
printf '\n'

report_deps() {
    local label=$1
    local path=$2
    if [ -x "$path" ] && command -v ldd >/dev/null 2>&1; then
        local count
        count=$(ldd "$path" 2>/dev/null | grep -c '=>' || echo 0)
        printf '  %-35s %d shared libraries\n' "$label" "$count"
        ldd "$path" 2>/dev/null | sed 's/^/      /'
    elif [ -x "$path" ]; then
        printf '  %-35s (ldd not available)\n' "$label"
    else
        printf '  %-35s N/A\n' "$label"
    fi
    printf '\n'
}

report_deps "shadow-rs passwd" "$RS_PASSWD"
report_deps "upstream passwd" "$UPSTREAM_PASSWD"
separator

# ---------------------------------------------------------------------------
# Performance benchmarks
# ---------------------------------------------------------------------------

log "Performance benchmarks"
printf '\n'
printf '  Test: passwd -S root (%d iterations)\n' "$PASSWD_STATUS_ITERS"
printf '  Test: pwck -r        (%d iterations)\n' "$PWCK_ITERS"
printf '\n'
separator

# -- passwd -S root --

rs_passwd_time=""
upstream_passwd_time=""

if [ -x "$RS_PASSWD" ]; then
    rs_passwd_time=$(bench_command "shadow-rs: passwd -S root" "$PASSWD_STATUS_ITERS" "$RS_PASSWD" -S root)
fi

if [ -x "$UPSTREAM_PASSWD" ]; then
    upstream_passwd_time=$(bench_command "upstream: passwd -S root" "$PASSWD_STATUS_ITERS" "$UPSTREAM_PASSWD" -S root)
fi

printf '\n'

# -- pwck -r --

rs_pwck_time=""
upstream_pwck_time=""

if [ -x "$RS_PWCK" ]; then
    rs_pwck_time=$(bench_command "shadow-rs: pwck -r" "$PWCK_ITERS" "$RS_PWCK" -r)
fi

if [ -x "$UPSTREAM_PWCK" ]; then
    upstream_pwck_time=$(bench_command "upstream: pwck -r" "$PWCK_ITERS" "$UPSTREAM_PWCK" -r)
fi

printf '\n'

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

separator
log "SUMMARY"
printf '\n'
printf '  %-30s %12s %12s %12s\n' "Benchmark" "shadow-rs" "Upstream" "Ratio"
separator

compute_ratio() {
    local rs=$1
    local gnu=$2
    if [ -n "$rs" ] && [ -n "$gnu" ] && [ "$(echo "$gnu > 0" | bc)" -eq 1 ]; then
        printf '%.2fx' "$(echo "$rs / $gnu" | bc -l)"
    else
        echo "N/A"
    fi
}

ratio_passwd=$(compute_ratio "${rs_passwd_time:-}" "${upstream_passwd_time:-}")
ratio_pwck=$(compute_ratio "${rs_pwck_time:-}" "${upstream_pwck_time:-}")

printf '  %-30s %11ss %11ss %12s\n' \
    "passwd -S root (${PASSWD_STATUS_ITERS}x)" \
    "${rs_passwd_time:-N/A}" \
    "${upstream_passwd_time:-N/A}" \
    "$ratio_passwd"

printf '  %-30s %11ss %11ss %12s\n' \
    "pwck -r (${PWCK_ITERS}x)" \
    "${rs_pwck_time:-N/A}" \
    "${upstream_pwck_time:-N/A}" \
    "$ratio_pwck"

printf '\n'
separator
log "Benchmark complete."
