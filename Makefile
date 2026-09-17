# Copyright (C) 2026 Nye Liu
# SPDX-License-Identifier: GPL-3.0-or-later

.PHONY: all test fmt clean changelog deb lintian FORCE

BINDIR := bin
GIT_VERSION := $(shell git describe --tags --abbrev=4 --dirty --always 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/nyet/bootstash/internal/version.Version=$(GIT_VERSION)
DEB_VERSION := $(shell sh scripts/deb-version.sh)
# -d: Build-Depends name a Debian golang-go; PATH go (setup-go / local) is enough.

all: $(BINDIR)/bootstashd $(BINDIR)/bootstash

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/bootstashd: FORCE | $(BINDIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/bootstashd

$(BINDIR)/bootstash: FORCE | $(BINDIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/bootstash

test:
	go test ./...

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './debian/*')

changelog:
	sh scripts/release-notes.sh debian > debian/changelog

# Artifacts land in the parent of the source tree (dpkg-buildpackage).
deb: changelog
	dpkg-buildpackage -b -us -uc -d

lintian:
	@set -- ../bootstash_$(DEB_VERSION)_*.changes; \
	if [ ! -e "$$1" ]; then \
		echo "lintian: no ../bootstash_$(DEB_VERSION)_*.changes (run make deb)" >&2; \
		exit 1; \
	fi; \
	lintian --fail-on warning "$$@"

clean:
	rm -rf $(BINDIR)

FORCE:
