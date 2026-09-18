# Building

How to compile bootstash and build the `.deb`. Changing behavior:
[`DEVELOPERS.md`](DEVELOPERS.md). Operators: [`README.md`](README.md),
[`QUICKSTART.md`](QUICKSTART.md), and the man pages. Tags and GitHub
releases: [`RELEASE.md`](RELEASE.md).

## Make targets

```
make          # bin/bootstashd (PAM), bin/bootstash-pam (setuid helper),
              # and bin/bootstash (CGO_ENABLED=0)
make test
make copyright  # refresh Go module list in debian/copyright
make packages   # all shipped archives (today: make deb)
make deb        # debian/changelog + dpkg-buildpackage -b → packages/
make lintian    # lintian --fail-on warning on that .changes
make clean      # bin/ only; keeps packages/
make distclean  # clean + packages/ + debian/changelog
                # (developer wipe; dpkg clean is make clean only)
```

No `vendor/`. `make packages` writes `packages/` (gitignored). Classic
debian-src parent directory:

```
make packages PKG_OUT=..
```

`PKG_OUT` may only be `packages` or `..`. `dpkg-buildpackage` itself
still writes `..`; `make deb` moves the files when the dest is
`packages/`. Bare `dpkg-buildpackage` is unchanged. CI calls
`make packages`. `make distclean` always removes `packages/`, never
`$PKG_OUT`.

`make deb` generates `debian/changelog` (gitignored). Raw
`dpkg-buildpackage` without `make deb` is unsupported.

## Dependencies

```
sudo apt-get update && sudo apt-get install -y \
  build-essential \
  golang-go \
  libpam0g-dev \
  pkg-config \
  git \
  python3 \
  dpkg-dev \
  debhelper \
  lintian \
  ca-certificates
```

`golang-go` must satisfy the `go` line in `go.mod`.

`git-cliff` is not in apt. Needed only for GitHub-style notes
(`scripts/release-notes.sh github`). `make deb` still writes
`debian/changelog` without it. Pick one:

Debian `cargo` package:

```
sudo apt-get install -y cargo
cargo install git-cliff
```

rustup:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install git-cliff
```

## Package install

`debian/` is the install path. Configure does not enable the unit.
If the daemon is already running it `try-restart`s after cert sync;
if it is down it starts only when `bootstash check-config` would
pass (same as `bootstashd -t`; first install without OIDC stays
down). Purge must not delete
`shared/` or `users/` (operator files). Leave data on purge.
