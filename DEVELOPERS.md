# Developers

For people and agents changing bootstash. Operators use **README.md**,
[`QUICKSTART.md`](QUICKSTART.md), and the man pages (`bootstashd(8)`,
`bootstash(8)`, `bootstash(5)`).
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
- Not ACME. HTTPS uses `TLS_CERT` / `TLS_KEY`, or
  `/etc/bootstash/certs/<CERT_NAME>/`. `PUBLIC_ORIGIN` defaults from
  `CERT_NAME` (hook picks the only `live/` lineage when unset). Do
  not read `/etc/letsencrypt/live`. Never copy every `live/` cert.
- Not `/etc/bootstash.d/`. Not systemd `EnvironmentFile=` or empty
  `ConfigurationDirectory=`
- `ADMIN_USERS` is a PAM-name seam with **no extra HTTP powers** in v1

## Config

Load order: built-in (embed of `internal/config/default-dist`) /
`/usr/lib/bootstash/default-dist` (not a
conffile), then `/etc/default/bootstash` (conffile; commented keys match
`default-dist` or are unset/derived; operator diffs only), then
`/etc/bootstash/oidc-google.json` (helper-written; not a
conffile). Later scalars win. If the operator file mentions `BIND` at
all, those lines replace the packaged listen list. Secrets **cannot**
change `BIND`.

`bootstash provision-google` installs the Google console’s Web
application client JSON as `/etc/bootstash/oidc-google.json` (`0640`
`root:bootstash`). It must not rewrite the operator file. It prints
a four-step Google console recipe (project, branding, Web
application client, download JSON) from the loaded origin.

SIGHUP re-reads all three; on parse failure **keep the last good
config**. Same for a bad TLS pair (keep the previous cert).

If `CERT_NAME` is unset, the hook (root, can read `live/`) chooses
one: operator `CERT_NAME`, `PUBLIC_ORIGIN` host, `live/$(hostname
-f)`, or the only `live/` lineage. It copies that one directory
and may append a commented `# CERT_NAME=` hint (`hostname -f` or
only lineage). The daemon still derives the name unless the
operator uncomments it. The hook does not rewrite other keys or
`PUBLIC_ORIGIN`. The daemon cannot read `live/`; it treats an
explicit `CERT_NAME`, `certs/$(hostname -f)`, or the only
`certs/<name>/` pair as `CERT_NAME`. If `PUBLIC_ORIGIN` is unset,
it is `http(s)://$CERT_NAME:port`, else `hostname -f`. Omit ports
80 and 443. Do not use `localhost`. Several `live/` lineages and
no `CERT_NAME`: `sync` prints the list and copies nothing. No FQDN
alias. Operators do not cron the hook.

## Process

`bootstashd` is `/usr/sbin/bootstashd`. CLI is `/usr/sbin/bootstash`
(no PAM, no HTTP). systemd: `Type=notify`, `User=bootstash`,
`SupplementaryGroups=ssl-cert`, `AmbientCapabilities` for bind /
`SO_BINDTODEVICE` / `CAP_CHOWN`. umask `007`. Startup log: version,
origin, binds, admins if set — never client secrets. Package
configure never enables the unit and never stops it on upgrade.
After cert sync it `try-restart`s if already active, or starts if
`bootstash check-config` would pass (same as `bootstashd -t`).
First install without OIDC stays down.

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

The helper prints the four-step recipe and
`$PUBLIC_ORIGIN/oidc/callback`, then installs the downloaded
client JSON. It does **not** create the Google web client
(`gcloud` cannot). It does not create Unix users.

## Tests that matter

Jail, Alice/Bob, CSRF, oversize, shared write-off, unlinked cannot
read trees, Range, bad PAM, DELETE.
