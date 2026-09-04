PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/sbin

# Tools that need setuid-root to allow non-root callers (change own password,
# GECOS, shell, effective group).
SETUID_TOOLS = passwd chfn chsh newgrp

# Root-only tools (no setuid; fail at getuid() check for non-root callers).
ROOT_TOOLS = useradd userdel usermod chpasswd chage \
             groupadd groupdel groupmod pwck grpck

ALL_TOOLS = $(SETUID_TOOLS) $(ROOT_TOOLS)

.PHONY: all build build-multicall dist-musl test install install-multicall uninstall clean

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

test:
	cargo test --workspace

# Default install: 14 standalone per-tool binaries with least-privilege setuid
# layout matching GNU shadow-utils. Only passwd/chfn/chsh/newgrp are setuid.
install: build
	@for tool in $(SETUID_TOOLS); do \
		install -Dm4755 target/release/$$tool $(DESTDIR)$(BINDIR)/$$tool || exit 1; \
	done
	@for tool in $(ROOT_TOOLS); do \
		install -Dm0755 target/release/$$tool $(DESTDIR)$(BINDIR)/$$tool || exit 1; \
	done
	@echo "Installed $(words $(ALL_TOOLS)) standalone binaries to $(DESTDIR)$(BINDIR)/"
	@echo "  setuid (4755): $(SETUID_TOOLS)"
	@echo "  root-only (0755): $(ROOT_TOOLS)"

# Opt-in install: single multicall binary with symlinks. Smaller footprint but
# larger setuid attack surface — the binary is installed setuid-root, so all 14
# applets run with euid=root when invoked via symlink. Intended for
# container/embedded use where disk savings matter and attack surface does not.
install-multicall: build-multicall
	install -Dm4755 target/release/shadow-rs $(DESTDIR)$(BINDIR)/shadow-rs
	@for tool in $(ALL_TOOLS); do \
		ln -sf shadow-rs $(DESTDIR)$(BINDIR)/$$tool; \
	done
	@echo "Installed multicall shadow-rs + $(words $(ALL_TOOLS)) symlinks to $(DESTDIR)$(BINDIR)/"

uninstall:
	@for tool in $(ALL_TOOLS); do \
		rm -f $(DESTDIR)$(BINDIR)/$$tool; \
	done
	rm -f $(DESTDIR)$(BINDIR)/shadow-rs
	@echo "Uninstalled shadow-rs from $(DESTDIR)$(BINDIR)/"

clean:
	cargo clean
