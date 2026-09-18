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
  (`openat`), not `setfsuid`. Do not serve `$HOME` as the PAM uid.
  `POST /link` is the setuid helper (Auth). Do not set
  `NoNewPrivileges=`
- File API: GET (Range/206), PUT/POST upload, DELETE of own files and
  **empty** directories. No rename, no WebDAV
- Identity is `(issuer, sub)`, never email-as-path. v1 requires PAM
  link. Do not `useradd`. Do not grow a password/app-user table
- Google only in v1. A later IdP is a new adapter + helper-owned keys
  under `/etc/bootstash/`, not a new session model
- Not ACME. Packaged `TLS=auto` (`maybe` is the same): HTTPS from
  `TLS_CERT` / `TLS_KEY` or `/etc/bootstash/certs/<CERT_NAME>/` when
  both PEMs exist, otherwise HTTP. `TLS=no`: HTTP on TCP binds; the
  hook does not copy `live/` and removes dest PEMs under `certs/`
  (unused private key; `live/` stays). `PUBLIC_URL` defaults from
  `CERT_NAME` (hook picks the only `live/` lineage when unset;
  `http` when `TLS=no`). Do not read `/etc/letsencrypt/live`. Never
  copy every `live/` cert.
- Not `/etc/bootstash.d/`. Not systemd `EnvironmentFile=` or empty
  `ConfigurationDirectory=`
- `ADMIN_USERS` is a PAM-name seam with **no extra HTTP powers** in v1

## Config

Load order: built-in (embed of `internal/config/default-dist`) /
`/usr/lib/bootstash/default-dist` (not a
conffile; **every** key, including empty/derived), then
`/etc/default/bootstash` (conffile; `0644` `root:root` like other
`/etc/default` files; commented `DATA`, `BIND`,
`PUBLIC_URL`, `ADMIN_USERS`; operator diffs), then
`/etc/bootstash/oidc-google.json` (helper-written; not a
conffile). Later scalars win. If the operator file mentions `BIND` at
all, those lines replace the packaged listen list. Secrets **cannot**
change `BIND`. Do not invent a second set of scalar defaults in Go.

`bootstash provision-google` installs the Google console’s Web
application client JSON as `/etc/bootstash/oidc-google.json` (`0640`
`root:bootstash`). It must not rewrite the operator file. It prints
a four-step Google console recipe (project, branding, Web
application client, download JSON) from the loaded origin.

SIGHUP re-reads all three; on parse failure **keep the last good
config**. Same for a bad TLS pair (keep the previous cert).

If `CERT_NAME` is unset, the hook (root, can read `live/`) chooses
one: operator `CERT_NAME`, `PUBLIC_URL` host, `live/$(hostname
-f)`, or the only `live/` lineage. It copies that one directory
unless `TLS=no` (then it removes dest PEMs under `certs/`). It may
insert commented `# CERT_NAME=` and `# PUBLIC_URL=`
hints after the operator-file header (`hostname -f` or only
lineage). `PUBLIC_URL` is the value the daemon would derive. The daemon still derives both
unless the operator uncomments them. The hook does not rewrite
operator keys. The daemon cannot read `live/`; it treats an
explicit `CERT_NAME`, `certs/$(hostname -f)`, or the only
`certs/<name>/` pair as `CERT_NAME`. If `PUBLIC_URL` is unset,
it is `http(s)://$CERT_NAME:port`, else `hostname -f`. Omit ports
80 and 443. Do not use `localhost`. Several `live/` lineages and
no `CERT_NAME`: `sync` prints the list and copies nothing. No FQDN
alias. Operators do not cron the hook.

## Process

`bootstashd` is `/usr/sbin/bootstashd`. CLI is `/usr/sbin/bootstash`
(no PAM, no HTTP). systemd: `Type=notify`, `User=bootstash`,
`SupplementaryGroups=ssl-cert`, `AmbientCapabilities` for bind /
`SO_BINDTODEVICE` / `CAP_CHOWN` / `CAP_FSETID` / `CAP_FOWNER`
(`chown` otherwise drops cubby setgid). Do not set `NoNewPrivileges=` (the
PAM helper is setuid). umask `007`. Startup log: version,
origin, binds, `tls=no` when TLS is off, admins if set — never client
secrets. Package configure never enables the unit and never stops
it on upgrade.
After cert sync (copy, or dest PEM removal when `TLS=no`) it
`try-restart`s if already active, or starts if
`bootstash check-config` would pass (same as `bootstashd -t`).
First install without OIDC stays down.

Honor `X-Forwarded-Proto` / `X-Forwarded-Host` on requests that are
not already TLS (ignored when the socket is HTTPS). v1 does not
check a trusted hop.

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

`$DATA` (default `/var/lib/bootstash`, `0751` so the cubby owner
can traverse in):

- `shared/` — linked users, HTTP read-only unless `SHARED_WRITABLE`
- `users/<pam_user>/` — that PAM user; HTTP read/write. `2770`
  `alice:bootstash` when `CAP_CHOWN` works (`CAP_FSETID` so `chown`
  does not drop setgid; `CAP_FOWNER` so `chmod` after `chown`
  still works). Parent `users/` is `0711`
  so alice can copy in from a shell without listing other cubbies.
  Ordinary `cp` (not `cp -a`) so setgid group is `bootstash`.
  Do not `chown` to `bootstash`. Start/SIGHUP and each `/home`
  GET/HEAD also `chgrp` files on that path (and listing children)
  and set `0640`. Full-tree pass is start/SIGHUP only.
- `state/` — sessions, OIDC→PAM map, crypto key. `0700`, never HTTP

Every file `open`/`create`/`unlink` is `openat` from the jail root.
Reject `..`, NUL, and outbound symlinks. DELETE of a non-empty
directory is 409. Do not serve `state/`. CSRF (`Origin` or
`Sec-Fetch-Site` vs `PUBLIC_URL`) on every state-changing request.
New HTTP files `0660`, dirs `0770`.

Routes: `/login`, `/oidc/callback`, `/link`, `/unlink`, `/files/`,
`/home/`. Unlinked sessions only reach login, callback, and `/link`.
HTML is a few templates, phone-sized targets, packaged `:root` +
`prefers-color-scheme`. No SPA, no theme picker.

## Auth

OIDC first (Google issuer `https://accounts.google.com`). Then PAM
`POST /link`. The daemon (`User=bootstash`) does not call PAM in
process. It execs `/usr/lib/bootstash/pam` (setuid `4750`
`root:bootstash`, not on `PATH`): argv is service + username,
password on stdin, exit 0/1. The helper runs `pam_authenticate` +
`pam_acct_mgmt` for service `bootstashd` (`/etc/pam.d/bootstashd` is
`common-auth` + `common-account`, same as ssh). That is how
`pam_unix` works for a user other than `bootstash`. Do not put the
password on argv. Do not make the helper a daemon. Do not add an
operator man page (not a user command). `-pam-helper` overrides the
path for tests. If the binary is missing, the daemon falls back to
in-process PAM (dev only; `pam_unix` will fail unless root).

Link table: `(issuer, sub) → pam_user`. One subject maps
to at most one PAM user; one PAM user may have several subjects.

`bootstash provision-google` prints the four-step recipe and
`$PUBLIC_URL/oidc/callback`, then installs the downloaded
client JSON. It does **not** create the Google web client
(`gcloud` cannot). It does not create Unix users.

## Tests that matter

Jail, Alice/Bob, CSRF, oversize, shared write-off, unlinked cannot
read trees, Range, bad PAM, DELETE, cubby `0711`/`2770`/`0640`.
