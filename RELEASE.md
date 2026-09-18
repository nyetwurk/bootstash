# Release Process

GitHub Actions call `make test`, `make packages`, and `make lintian`. The
release attaches the `.deb`, not a zip of binaries.

## GitHub Workflows

### Triggers

- **push** to any branch — `make test`, `make packages`, `make lintian`;
  artifacts on the Actions run (not a release)
- **pull_request** to any branch — same as push
- **push** tags `v*` — same make targets, then a GitHub release

### Tag Rules

Only `vX.Y.Z` (release) and `vX.Y.Z-rcN` (prerelease). Lightweight is
fine. No `~` in tags.

- **`v1.1.1`** → published full release (Latest). Immutable git tag.
  Notes: last full release → this tag (RCs ignored), or first commit
  if none. Not a GitHub draft.
- **`v1.1.1-rc1`** → published prerelease (not Latest). May be
  force-moved and force-pushed. Notes: last full or RC tag → this
  tag, or first commit if none. Same `rcN` is the same Debian
  version; bump `N` if installed testers must see an upgrade. Not a
  GitHub draft.

Git tag `-rc` maps to Debian `~rc` (`v1.2.3-rc1` → `1.2.3~rc1`). A
release tag `v1.2.3` is Debian `1.2.3`. Untagged builds are
`0.0.0~git+describe` / `UNRELEASED`.

### Workflows

| Workflow | Runners | Output |
|----------|---------|--------|
| `release.yml` | ubuntu | On tag push: `.deb` + git-cliff notes |
| `build.yml` | `ubuntu-latest` | Push/PR: `.deb` → artifact |

`make packages` writes archives to `packages/` (today the `.deb`). The
daemon links against PAM (`libpam0g-dev` on the runner). Binary
version strings come from
`git describe --tags --abbrev=4 --dirty --always`.

---

## Release Notes with git-cliff

[git-cliff](https://git-cliff.org/) plus `scripts/release-notes.sh`.
`make deb` writes `debian/changelog` (gitignored) from the same commit
set. GitHub uses the markdown body in `cliff.toml`.

- **Conventional commits**: grouped by type; see `commit_parsers` in
  `cliff.toml`
- **Tag pattern**: `vX.Y.Z` and `vX.Y.Z-rcN`
- **CI**: `scripts/release-notes.sh github`. Full releases pass
  `--tag-pattern` so only `vX.Y.Z` tags bound the range (RCs are
  not version boundaries). RC releases keep RC tags as boundaries

```bash
sh scripts/release-notes.sh github
sh scripts/release-notes.sh debian
git cliff
```

---

## Creating a Release

```bash
git tag v0.1.0
git push origin v0.1.0
```

Or `v0.1.0-rc1`. Wait for `release.yml`, then confirm the `.deb` and
notes on the release page.

Local package smoke-test (no GitHub release):
[`BUILDING.md`](BUILDING.md).
