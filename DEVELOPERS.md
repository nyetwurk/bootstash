# Developers

For people and agents changing bootstash. Operators use **README.md**
and the man pages (`bootstashd(8)`, `bootstash(8)`, `bootstash(5)`).
Building the binaries and `.deb`: [`BUILDING.md`](BUILDING.md). This
is not a public Go API.

Do not add unseal, at-rest encryption, or per-request uid switching to
look like Vault. Keep the jail and CSRF. Do not promise more than
README “Expectations.”

## Constraints

- Go version is the `go` line in `go.mod`. No `toolchain` line.
  `golang.org/x` and OIDC/PAM modules only as needed. Not a library:
  rename exported types freely; nobody should import this module
- Public **Debian `.deb`**. How to build it: [`BUILDING.md`](BUILDING.md)
- One process UID (`bootstash`). HTTP isolation is a path jail
  (`openat`), not `setfsuid`. Do not serve `$HOME` as the PAM uid
- File API: GET (Range/206), PUT/POST upload, DELETE of own files and
  **empty** directories. No rename, no WebDAV
- Identity is `(issuer, sub)`, never email-as-path. v1 requires PAM
  link. Do not `useradd`. Do not grow a password/app-user table
- Google only in v1. A later IdP is a new adapter + helper-owned keys
  under `/etc/bootstash/`, not a new session model
- Not ACME. HTTPS uses operator `TLS_CERT` / `TLS_KEY`
- Not `/etc/bootstash.d/`. Not systemd `EnvironmentFile=` or empty
  `ConfigurationDirectory=`
- `ADMIN_USERS` is a PAM-name seam with **no extra HTTP powers** in v1

## Config

Load order: built-in (embed of `internal/config/defaults.conf`) /
`/usr/lib/bootstash/defaults.conf` (not a
conffile), then `/etc/default/bootstash` (empty conffile; operator
diffs only), then `/etc/bootstash/oidc-google` (helper-written; not a
conffile). Later scalars win. If the operator file mentions `BIND` at
all, those lines replace the packaged listen list. Secrets **cannot**
change `BIND`.

`bootstash provision-google` writes only the secrets file (`0640`
`root:bootstash`). It must not rewrite the operator file. Mode `0640`
so `User=bootstash` can read.

SIGHUP re-reads all three; on parse failure **keep the last good
config**. Same for a bad TLS pair (keep the previous cert).

## Process

`bootstashd` is `/usr/sbin/bootstashd`. CLI is `/usr/sbin/bootstash`
(no PAM, no HTTP). systemd: `Type=notify`, `User=bootstash`,
`SupplementaryGroups=ssl-cert`, `AmbientCapabilities` for bind /
`SO_BINDTODEVICE` / `CAP_CHOWN`. umask `007`. Startup log: version,
origin, binds, admins if set — never client secrets.

Honor `X-Forwarded-Proto` / `X-Forwarded-Host` only on **HTTP** binds
and only from a **trusted hop**. Ignore them on HTTPS.

## Bind

Repeatable `where:port` plus optional `/ipv4` or `/ipv6`. `where` is
`*`, an address, a CIDR, an interface, or `unix://path`. Port 0 is
rejected. Unix sockets are HTTP only.

- **ANY:** `0.0.0.0` and/or `::` (`*` means both unless a family
  suffix). Dual-stack may be two sockets
- **CIDR:** local **unicast** addresses in the prefix (skip loopback
  unless the prefix is loopback; skip link-local unless the CIDR is
  link-local). Empty match at start **fails**. Empty match on HUP:
  keep previous listeners. This is where we listen, **not** a client
  allowlist
- **Interface:** prefer `SO_BINDTODEVICE`. Missing iface at start:
  retry with backoff. Missing on HUP: keep old listeners
- `SO_REUSEADDR` on. Do not add `SO_REUSEPORT` unless a test needs it

## Data and jail

`$DATA` (default `/var/lib/bootstash`):

- `shared/` — linked users, HTTP read-only unless `SHARED_WRITABLE`
- `users/<pam_user>/` — that PAM user; HTTP read/write. `2770`
  `alice:bootstash` when `CAP_CHOWN` works
- `state/` — sessions, OIDC→PAM map, crypto key. `0700`, never HTTP

Every file `open`/`create`/`unlink` is `openat` from the jail root.
Reject `..`, NUL, and outbound symlinks. DELETE of a non-empty
directory is 409. Do not serve `state/`. CSRF (`Origin` or
`Sec-Fetch-Site` vs `PUBLIC_ORIGIN`) on every state-changing request.
New HTTP files `0660`, dirs `0770`.

Routes: `/login`, `/oidc/callback`, `/link`, `/unlink`, `/files/`,
`/home/`. Unlinked sessions only reach login, callback, and `/link`.
HTML is a few templates, phone-sized targets, packaged `:root` +
`prefers-color-scheme`. No SPA, no theme picker.

## Auth

OIDC first (Google issuer `https://accounts.google.com`). Then PAM
`POST /link` (`pam_authenticate` + `pam_acct_mgmt`, service
`bootstashd`). Link table: `(issuer, sub) → pam_user`. One subject maps
to at most one PAM user; one PAM user may have several subjects.

The helper prints `$PUBLIC_ORIGIN/oidc/callback` and console URLs. It
does **not** create the Google web client (`gcloud` cannot). It does
not create Unix users.

## Tests that matter

Jail, Alice/Bob, CSRF, oversize, shared write-off, unlinked cannot
read trees, Range, bad PAM, DELETE.
