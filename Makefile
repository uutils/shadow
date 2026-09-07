PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin

# Tools that need setuid-root to allow non-root callers (change own password,
# GECOS, shell, effective group, or administer a group as a group admin).
SETUID_TOOLS = passwd chfn chsh newgrp gpasswd sg

# Root-only tools (no setuid; fail at getuid() check for non-root callers).
ROOT_TOOLS = useradd userdel usermod chpasswd \
             groupadd groupdel groupmod pwck grpck

# Tools an ordinary user runs, and which therefore go in bin rather than sbin:
# sbin is not on a normal user's PATH, so `passwd` there is `command not
# found`. This is where GNU shadow puts them -- verified against the Debian
# package, which ships passwd, chage, chfn, chsh and newgrp in /usr/bin and
# everything else in /usr/sbin. chage is here for `chage -l`, the one mode a
# user may run on their own account.
USER_TOOLS = $(SETUID_TOOLS) chage

ALL_TOOLS = $(SETUID_TOOLS) $(ROOT_TOOLS) chage

.PHONY: all build build-multicall build-arm64 dist-musl check test test-gnu-compat test-arm64 install install-multicall uninstall clean

all: build

# `pam` is not a default cargo feature, so a plain build produces a `passwd`
# that refuses the interactive change path ("PAM support is not compiled in").
# Installed binaries must have it; the PAM headers are already listed as a
# build requirement in the README.
build:
	cargo build --release --workspace --bins --exclude uu_shadow \
		--features uu_passwd/pam,uu_chfn/pam,uu_chsh/pam

build-multicall:
	cargo build --release --bin shadow-rs --features pam

# Static musl archive, published as a release asset next to the glibc one
# (dist-workspace.toml runs this target; see issue #224). Built without `pam`:
# Linux-PAM dlopen()s its modules, which a static binary cannot do, and
# shadow-core refuses the combination at compile time. The archive name carries
# the "-static" label and docs/PLATFORM-SUPPORT.md, shipped inside, spells out
# what the build does and does not do.
MUSL_TARGET = x86_64-unknown-linux-musl
MUSL_ARCHIVE = uu_shadow-$(MUSL_TARGET)-static
MUSL_DIST_DIR = target/dist-musl

dist-musl:
	rustup target add $(MUSL_TARGET)
	cargo build --release --locked --bin shadow-rs --target $(MUSL_TARGET)
	@# A DT_NEEDED entry would mean a shared object slipped in and the archive
	@# is not the self-contained binary its name promises.
	@if readelf -d target/$(MUSL_TARGET)/release/shadow-rs | grep -q NEEDED; then \
		echo "error: shadow-rs is not statically linked" >&2; exit 1; \
	fi
	rm -rf $(MUSL_DIST_DIR)
	mkdir -p $(MUSL_DIST_DIR)/$(MUSL_ARCHIVE)
	cp target/$(MUSL_TARGET)/release/shadow-rs LICENSE README.md CHANGELOG.md \
		docs/PLATFORM-SUPPORT.md $(MUSL_DIST_DIR)/$(MUSL_ARCHIVE)/
	tar -C $(MUSL_DIST_DIR) --owner=0 --group=0 --numeric-owner \
		-czf $(MUSL_DIST_DIR)/$(MUSL_ARCHIVE).tar.gz $(MUSL_ARCHIVE)
	cd $(MUSL_DIST_DIR) && sha256sum $(MUSL_ARCHIVE).tar.gz > $(MUSL_ARCHIVE).tar.gz.sha256
	@echo "Built $(MUSL_DIST_DIR)/$(MUSL_ARCHIVE).tar.gz"

# Everything CI gates on, in one place, so the README, CONTRIBUTING, the git
# hooks and ci.yml stop each carrying their own copy of the command list.
# Run it inside a container: docker compose run --rm debian make check
check:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy --workspace --all-targets --features pam -- -D warnings
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	$(MAKE) test

# `install` ships binaries built with pam, so the tests must cover that build
# as well as the default one: the feature changes which code paths exist.
test:
	cargo test --workspace
	cargo test --workspace --features pam

ARM64_TARGET = aarch64-unknown-linux-gnu
ARM64_BIN = target/$(ARM64_TARGET)/release/shadow-rs

# Cross-build for arm64 and check the result actually runs.
#
# The release publishes an arm64 archive; nothing used to execute one, so a
# broken arm64 binary would reach a user before anyone ran it. The toolchain is
# installed here rather than baked into the image: it is 32 packages, and every
# other job would carry them for a check that is run occasionally.
build-arm64:
	dpkg --add-architecture arm64
	apt-get update
	apt-get install -y --no-install-recommends \
		gcc-aarch64-linux-gnu libpam0g-dev:arm64 libcrypt-dev:arm64 qemu-user-static
	rustup target add $(ARM64_TARGET)
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
		cargo build --release --locked --target $(ARM64_TARGET) --bin shadow-rs --features pam

# Runs under qemu user-mode emulation, which is enough to catch what actually
# differs across architectures: integer widths, struct layouts, and the crypt
# and PAM FFI boundaries.
test-arm64: build-arm64
	ARM64_BIN=$(ARM64_BIN) bash tests/arm64-smoke.sh

# Compare our output and exit codes against the GNU tools installed alongside.
# Needs root and the GNU shadow package, so it belongs in a container.
test-gnu-compat:
	bash tests/gnu-compat.sh

# Default install: 16 standalone per-tool binaries, with the setuid layout and
# the bin/sbin split GNU shadow-utils uses. Only $(SETUID_TOOLS) are setuid.
install: build
	@for tool in $(SETUID_TOOLS); do \
		install -Dm4755 target/release/$$tool $(DESTDIR)$(BINDIR)/$$tool || exit 1; \
	done
	@install -Dm0755 target/release/chage $(DESTDIR)$(BINDIR)/chage
	@for tool in $(ROOT_TOOLS); do \
		install -Dm0755 target/release/$$tool $(DESTDIR)$(SBINDIR)/$$tool || exit 1; \
	done
	@echo "Installed $(words $(ALL_TOOLS)) standalone binaries"
	@echo "  $(DESTDIR)$(BINDIR)/  setuid (4755): $(SETUID_TOOLS)"
	@echo "  $(DESTDIR)$(BINDIR)/  user (0755):   chage"
	@echo "  $(DESTDIR)$(SBINDIR)/ root (0755):   $(ROOT_TOOLS)"

# Opt-in install: single multicall binary with symlinks. Smaller footprint.
# The binary is installed setuid-root for $(SETUID_TOOLS); the other applets
# drop back to the caller's uid before running, so the privilege model matches
# the per-tool layout. Intended for container/embedded use.
install-multicall: build-multicall
	install -Dm4755 target/release/shadow-rs $(DESTDIR)$(SBINDIR)/shadow-rs
	@install -d $(DESTDIR)$(BINDIR)
	@for tool in $(USER_TOOLS); do \
		ln -sf $(SBINDIR)/shadow-rs $(DESTDIR)$(BINDIR)/$$tool || exit 1; \
	done
	@for tool in $(ROOT_TOOLS); do \
		ln -sf shadow-rs $(DESTDIR)$(SBINDIR)/$$tool || exit 1; \
	done
	@echo "Installed multicall shadow-rs to $(DESTDIR)$(SBINDIR)/ with"
	@echo "  $(words $(USER_TOOLS)) symlinks in $(DESTDIR)$(BINDIR)/: $(USER_TOOLS)"
	@echo "  $(words $(ROOT_TOOLS)) symlinks in $(DESTDIR)$(SBINDIR)/: $(ROOT_TOOLS)"

uninstall:
	@for tool in $(ALL_TOOLS); do \
		rm -f $(DESTDIR)$(BINDIR)/$$tool $(DESTDIR)$(SBINDIR)/$$tool; \
	done
	rm -f $(DESTDIR)$(BINDIR)/shadow-rs $(DESTDIR)$(SBINDIR)/shadow-rs
	@echo "Uninstalled shadow-rs from $(DESTDIR)$(BINDIR)/ and $(DESTDIR)$(SBINDIR)/"

clean:
	cargo clean
