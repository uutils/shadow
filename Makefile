PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin

# Tools that need setuid-root to allow non-root callers (change own password,
# GECOS, shell, effective group, or administer a group as a group admin).
SETUID_TOOLS = passwd chfn chsh newgrp gpasswd

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

.PHONY: all build build-multicall dist-musl check test test-gnu-compat install install-multicall uninstall clean

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

# Compare our output and exit codes against the GNU tools installed alongside.
# Needs root and the GNU shadow package, so it belongs in a container.
test-gnu-compat:
	bash tests/gnu-compat.sh

# Default install: 15 standalone per-tool binaries, with the setuid layout and
# the bin/sbin split GNU shadow-utils uses. Only passwd/chfn/chsh/newgrp are
# setuid.
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
# The binary is installed setuid-root for passwd/chfn/chsh/newgrp/gpasswd; the
# other applets drop back to the caller's uid before running, so the privilege
# model matches the per-tool layout. Intended for container/embedded use.
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
