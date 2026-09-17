# Building

How to compile bootstash and build the `.deb`. Changing behavior:
[`DEVELOPERS.md`](DEVELOPERS.md). Operators: [`README.md`](README.md)
and the man pages. Tags and GitHub releases: [`RELEASE.md`](RELEASE.md).

## Make targets

```
make          # bin/bootstashd (PAM) and bin/bootstash (CGO_ENABLED=0)
make test
make deb      # debian/changelog + dpkg-buildpackage -b → parent of source
make lintian  # lintian --fail-on warning on that .changes
```

No `dist/`. No `vendor/`. `dpkg-buildpackage` writes
`../bootstash_*.deb` (and `.buildinfo` / `.changes`). CI calls these
targets; it does not inline `dpkg-buildpackage`.

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

`debian/` is the install path. No `systemctl enable --now` on
install. Purge must not delete `shared/` or `users/` (operator files).
Leave data on purge.
