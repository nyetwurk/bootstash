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
  (unused private key; `live/` stays). Hook pick order: operator
  `CERT_NAME`, `PUBLIC_URL` host, `live/$(hostname -f)`, or the only
  `live/` lineage. No rewrite of `/etc/default/bootstash`.
  `PUBLIC_URL` defaults from dest `CERT_NAME` (`http` when `TLS=no`).
  Do not read `/etc/letsencrypt/live`. Never copy every `live/` cert.
- Not `/etc/bootstash.d/`. Not systemd `EnvironmentFile=` or empty
  `ConfigurationDirectory=`
- `ADMIN_USERS` is a PAM-name seam with **no extra HTTP powers** in v1

## Config

Load order: built-in (embed of `internal/config/default-dist`) /
`/usr/lib/bootstash/default-dist` (not a
conffile; packaged operator keys, including empty/derived; not OIDC
client id/secret or `OIDC_CRYPTO`), then
`/etc/default/bootstash` (conffile; `0644` `root:root` like other
`/etc/default` files; commented `DATA`, `LISTEN`,
`PUBLIC_URL`, `ADMIN_USERS`; operator diffs; never OIDC secrets), then
`/etc/bootstash/oidc-google.json` (helper-written; not a
conffile). Later scalars win. If the operator file mentions `LISTEN` at
all, those lines replace the packaged listen list. Secrets **cannot**
change `LISTEN`. Do not invent a second set of scalar defaults in Go.

`bootstash provision-google` installs the Google console’s Web
application client JSON as `/etc/bootstash/oidc-google.json` (`0640`
`root:bootstash`). It must not rewrite the operator file. It prints
a four-step Google console recipe (project, branding, Web
application client, download JSON) from the loaded origin.

SIGHUP re-reads all three; on parse failure **keep the last good
config**. Same for a bad TLS pair (keep the previous cert).

The hook (root, can read `live/`) chooses one lineage, in order:
operator `CERT_NAME`, `PUBLIC_URL` host, `live/$(hostname -f)`, or
the only `live/` lineage. It copies that one directory
unless `TLS=no` (then it removes dest PEMs under `certs/`). It does
not rewrite the operator file. The daemon cannot read `live/`; it
treats an explicit `CERT_NAME`, `certs/$(hostname -f)`, or the only
`certs/<name>/` pair as `CERT_NAME`. If `PUBLIC_URL` is unset,
it is `http(s)://$CERT_NAME:port`, else `hostname -f`. Omit ports
80 and 443. Do not use `localhost`. Several `live/` lineages and
no chosen name: `sync` prints the list and copies nothing. A renew
of a name already in `certs/` still refreshes those PEMs when no
name is chosen. No FQDN alias. Operators do not cron the hook.

## Process

`bootstashd` is `/usr/sbin/bootstashd`. CLI is `/usr/sbin/bootstash`
(no PAM, no HTTP; `put` copies into the caller’s cubby without OIDC
secrets; `links` / `unlink` use `$DATA/state`). systemd: `Type=notify`, `User=bootstash`,
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

Do not rewrite the request from `X-Forwarded-Proto` /
`X-Forwarded-Host`. Browser origin is `PUBLIC_URL` (OIDC, CSRF,
cookies). A reverse proxy must set `PUBLIC_URL` to the URL the
browser uses; `Host` on the backend socket does not matter.
One origin. Extra DNS names `Redirect` at the proxy; do not
`ProxyPass` two names onto the same daemon. Layouts A (cubby
host) and B (VPN host), and why a 301 off `PUBLIC_URL` drops
Connect’s `Ovpn-WebAuth`: [`QUICKSTART.md`](QUICKSTART.md#origin-models).

## Listen

Repeatable `LISTEN=` `where:port` plus optional `/ipv4` or `/ipv6`. `where` is
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

- `users/<pam_user>/` — that PAM user; HTTP read/write. `2770`
  `alice:bootstash` when `CAP_CHOWN` works (`CAP_FSETID` so `chown`
  does not drop setgid; `CAP_FOWNER` so `chmod` after `chown`
  still works). Parent `users/` is `0711`
  so alice can copy in from a shell without listing other cubbies.
  `bootstash put` is that copy (files `0660`, dirs `2770`, no
  symlinks, not root). Ordinary `cp` (not `cp -a`) so setgid group
  is `bootstash`.
  Do not `chown` to `bootstash`. Start/SIGHUP and each `/home`
  GET/HEAD also `chgrp` files on that path (and listing children)
  and set `0640`, using `openat`/`O_NOFOLLOW`/`fchmod`/`fchown`
  (not pathname `chmod`). Full-tree pass is start/SIGHUP only.
- `state/` — sessions, OIDC→PAM map, crypto key. `0700`, never HTTP.
  Writes (including `sudo bootstash unlink`) chown files to the
  state directory owner so `User=bootstash` can still read them.
  Link and session mutations take `flock` on `state/.lock` so the
  CLI and daemon cannot interleave a revocation.

Every file `open`/`create`/`unlink` is `openat` from the jail root.
Reject `..`, NUL, and outbound symlinks. DELETE of a non-empty
directory is 409. Do not serve `state/`. CSRF (`Origin`, `Sec-Fetch-Site`, or
`Referer` vs `PUBLIC_URL`) on every state-changing request.
`Referrer-Policy` is `same-origin` so same-origin form POST still has
a Referer when Origin is missing (Sign out, upload, mkdir).
New HTTP files `0660`, dirs mkdirat `0770` (inherit setgid in a
cubby → `2770`). Do not fchmod cubby dirs: chmod(2) drops
`S_ISGID` when the caller is not in the directory’s group (alice
is not in `bootstash`) and lacks `CAP_FSETID`. PUT/POST write a sibling temp
then `renameat` so a failed upload keeps the old file.

Routes: `/login`, `/oidc/callback`, `/link`, `/logout`, `/home/`,
`/openvpn-api/profile`, `/rest/GetUserlogin`, `/rest/GetAutologin`.
HEAD `/openvpn-api/profile` is `200` with `Ovpn-WebAuth:
bootstash,external` (OpenVPN Connect URL import; `external` so
Google OIDC runs in a normal browser). Unauthenticated GET there is
`200` login HTML with that header (not a 302: Connect follows
redirects and would drop it) and sets a short-lived cookie so
OIDC/`/link` return to this URL. Linked browser GET (`Accept:
text/html`) is a page with `openvpn://import-profile/` plus a
one-time `?token=` URL (60s, two GETs, then 404; Connect fetches
that itself; no session cookie, no `Ovpn-WebAuth`) and a
`?download=1` save link (session cookie; attachment). Import and
token bytes get `# OVPN_ACCESS_SERVER_FRIENDLY_NAME` /
`setenv FRIENDLY_NAME` as `remote [filename]` (first OpenVPN
`remote` in the profile, then the cubby name; the paste origin is
still `PUBLIC_URL`). Cubby GET of `.ovpn` stays the file as
stored. One `.ovpn` (any name) or a single `client.ovpn` among
several: auto-open. Several without a unique `client.ovpn`: picker
(tap, no `location.replace`). None: empty message, not `/home/`.
Non-HTML linked GET (and `?download=1`) serves the picked profile
as `application/x-openvpn-profile` attachment, or 302 `/home/` if
there is no unique pick. `?embedded=true` is an HTML page that
`postMessage`s `PROFILE_DOWNLOAD_SUCCESS`. Probe and import
decisions log as `openvpn ...` (journalctl); token lines omit
`?token=`. GET `/rest/GetUserlogin` and `/rest/GetAutologin` are
`401` XML `Ovpn-WebAuth: bootstash,external` in the body and
header, no `WWW-Authenticate`. That is the spec bounce off Access
Server REST into the browser; not Basic Auth and not a profile.
GET/HEAD `/home` without a linked session redirects to `/login` (or
`/link` if the cookie is unlinked). Other methods return 401.
Unknown `?provider=` redirects to `/login`. GET `/logout` redirects
to `/`.
Unlinked sessions only reach login, callback, `/link`, `/logout`,
and `/openvpn-api/profile` (which sends them to `/link`).
v1 link table is `bootstash links` and `bootstash unlink USER`
(operator access to `$DATA/state`), not HTTP.
HTML **Sign out** is `POST /logout`: this session file and cookie only.
The PAM map stays. Not unlink.
HTML is a few templates, large targets (laptop, tablet, or phone),
packaged `:root` + `prefers-color-scheme`. No SPA, no second desktop
UI, no theme picker. Every response sets `nosniff`,
`Referrer-Policy: same-origin`, and
`Content-Security-Policy: frame-ancestors 'none'` (inline `/link`,
listing, and OpenVPN handoff JS stay; do not add a strict
`script-src` without a nonce).
File GET uses `mime.FormatMediaType` for `Content-Disposition`.
Listing file names have a copy-link control (clipboard API,
`execCommand` fallback, 44px; listing href, not an import token).
Init parses embedded `internal/web/mime.types` (Debian media-types /
IANA type-to-extension map) then `mime-local.types` (`.ovpn` →
`application/x-openvpn-profile`). Lookup is by extension at GET time;
`text/*` gets `charset=utf-8`. Unknown extensions stay
`application/octet-stream` (attachment). Do not use the host
`/etc/mime.types` or Go `mime.TypeByExtension` (those differ by
machine). Video, audio, image, PDF, and `.ovpn` are inline.
Unknown GET/HEAD routes and login failures are HTML (the login page,
or a small error page). Cubby HTML GET and form POST failures
redirect to the listing with a notice. Other methods stay
text/plain.

## Auth

OIDC first (Google issuer `https://accounts.google.com`). `/login`
sets a one-time oauth cookie (`__Host-bootstash-oauth` when
`PUBLIC_URL` is https, else `bootstash_oauth`) bound to the signed
state. AuthCodeURL adds PKCE S256; the verifier is stored in that
transaction. `/oidc/callback` requires the cookie, consumes the
transaction, and sends the verifier on Exchange. Then PAM
`POST /link`. `/link` rotates the session id and cookie. Other
sessions for that `(issuer, sub)` lose PAM when the mapping changes
to a different Unix name. The daemon
(`User=bootstash`) does not call PAM in process. It execs
`/usr/lib/bootstash/pam` (setuid `4750`
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
UID 0 is never linked (`POST /link` and the helper refuse it).

`bootstash provision-google` prints the four-step recipe and
`$PUBLIC_URL/oidc/callback`, then installs the downloaded
client JSON. It does **not** create the Google web client
(`gcloud` cannot). It does not create Unix users.

`bootstash links` prints `user issuer sub` (not email).
`bootstash unlink USER` drops every `(issuer, sub)` mapped to that
PAM name and clears `pam_user` on those sessions. The cubby stays.
Changing or disabling the Unix account does not drop the map.
Not an `ADMIN_USERS` HTTP power.

`bootstash put` copies files or directories into the caller’s cubby.
Not sudo. UID 0 is refused. Does not create the cubby. Does not read
OIDC secrets. Files `0660` (HTTP upload), dirs `2770` (cubby).

## Tests that matter

Jail, Alice/Bob, CSRF, oversize, unlinked cannot read trees, Range,
bad PAM, UID 0, DELETE, cubby `0711`/`2770`/`0640`, `links` / `unlink` PAM map,
`put` into the caller’s cubby, `POST /logout` keeps the map, PKCE,
session rotate on `/link`, relink drops other sessions, oauth login
cap, response headers, GET `/home` login redirect, HTML 404 / login-fail
pages, `.ovpn` MIME, HEAD `/openvpn-api/profile`, REST `Ovpn-WebAuth`
bounce, import `?token=` (no session, no `Ovpn-WebAuth`, titled
`remote [filename]`), picker HTML, `mime.types` parse,
`scripts/test-letsencrypt-deploy.py` (pick order, `TLS=no` purge,
renew of an already-installed dest).
