#!/usr/bin/env bash
# Publish every workspace crate whose version is not on crates.io yet.
#
# `cargo publish --workspace` orders the crates by dependency and verifies
# each one, but it refuses a version that is already uploaded, and a release
# rerun after a partial failure (a crate not yet authorised for Trusted
# Publishing, the new-crate rate limit) must skip what went through. So the
# crates.io index is asked first and those are excluded.
#
# Usage: publish-crates.sh [--dry-run]     (CARGO_REGISTRY_TOKEN in the env)
set -euo pipefail

dry=""
[ "${1:-}" = "--dry-run" ] && dry="--dry-run"

# The sparse index path for a crate name: crates.io's layout, documented in
# the Cargo registry reference.
index_path() {
    local n=$1
    case ${#n} in
        1) echo "1/$n" ;;
        2) echo "2/$n" ;;
        3) echo "3/${n:0:1}/$n" ;;
        *) echo "${n:0:2}/${n:2:2}/$n" ;;
    esac
}

exclude=()
while IFS=' ' read -r name version; do
    if curl -sf "https://index.crates.io/$(index_path "$name")" \
        | grep -qE "\"vers\":\"$version\""; then
        echo "already on crates.io: $name $version"
        exclude+=(--exclude "$name")
    else
        echo "to publish: $name $version"
    fi
done < <(cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; [print(p["name"], p["version"]) for p in json.load(sys.stdin)["packages"]]')

total=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["packages"]))')
if [ $(( ${#exclude[@]} / 2 )) -eq "$total" ]; then
    echo "nothing to publish"
    exit 0
fi

exec cargo publish --workspace --locked $dry "${exclude[@]}"
