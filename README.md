# bootstash

A small daemon that is a **self-hosted cubby for bootstrap files**: after
you prove you are an existing Linux user, you **browse, download, and
upload** your own tree — keys, profiles, first-run artifacts — from
whatever browser you have on the road.

It is not a secrets engine (no unseal, leases, or KV API). Bind wherever
you want (loopback, LAN, a tunnel NIC, later a public address). v1 auth
is Google OIDC linked to PAM; other issuers can be added later.

**Install and first run:** [`QUICKSTART.md`](QUICKSTART.md). Config
keys: `bootstash(5)`.

## Expectations

This is a **convenience cubby**, not a hardened credential store. Do not
use it as the security boundary for high-assurance, regulated, or
hostile-tenant environments.

- Files on disk are ordinary POSIX (mode/owner). The daemon does **not**
  encrypt at rest or after unseal
- One service UID can read every tree it serves. HTTP isolation is a
  **path jail**, not per-request `setfsuid`
- Google (and later other IdPs) and a session cookie are “good enough
  for a laptop on the LAN,” not an HSM or policy engine
- A bug or stolen cookie is a bad day for those files. Keep crown jewels
  in OpenBao, `age`/`SOPS`, or not on this host
- Kits are **temporary**. Expiration (not v1) will delete aged HTTP
  uploads so this does not become a long-term archive. Until then, you
  still should not treat it as backup

If you need audit leases, Shamir unseal, or “compromise of the app server
must not yield plaintext,” this is the wrong program.

## Who it is for

Debian hosts that already have **PAM accounts**. The person using it is
a **road warrior**: laptop, tablet, or phone, away from the usual
shell.

Typical first session:

- Reach the daemon
- Sign in with Google
- Once: Linux username and password
- Download bootstrap files

Install is a **public `.deb`**.

## What you can do

- Sign in with Google
- Link that sign-in to your existing Linux account (the same one ssh
  already uses). Username + password, once
- Browse **your** folder that other people cannot see
- Download files, including large ones (Range so a browser can play or
  save them)
- Import an `.ovpn` from OpenVPN Connect: paste this cubby’s origin
  (`PUBLIC_URL`, not a file path). After Google, allow the page to
  open Connect (or tap **Open in OpenVPN Connect**). One file, or
  `client.ovpn` among several, imports itself. Several other `.ovpn`
  files: pick one on that page. Connect should show
  `vpn-host [filename]` (OpenVPN `remote` in the file, then the
  cubby name; the URL you paste is still `PUBLIC_URL`)
- Copy a file’s link from the listing (clipboard icon next to the
  name)
- Upload into **your** folder
- From a host login: `bootstash put` files into **your** folder (not sudo)
- Delete files (and empty folders) in **your** folder
- Sign out (this browser session; the Linux link stays)
- Later: **expiration** of HTTP-uploaded kit files so the tree does not
  accumulate forever

Later visits only need Google. Changing or disabling the Unix account
does not drop the map. The Linux password is not used again until an
operator runs `bootstash unlink` (that user's subjects must link
again).

Your Google email is not a folder name. Folders follow the linked Linux
username. Identity is the provider’s `(issuer, sub)`.

## Listen

One or more binds: an **interface**, a **CIDR** of local addresses,
**any** / one address, or a **Unix socket** (HTTP only, for a local
proxy).

TLS:

- `TLS=auto` (packaged): HTTPS when both PEMs exist under
  `/etc/bootstash/certs/` (Let’s Encrypt `live/` copied there)
- `TLS=no`: cleartext on TCP binds; the hook does not copy `live/`
  and dest PEMs are removed. A reverse proxy may terminate HTTPS

How to set `LISTEN`, `PUBLIC_URL`, and TLS:
[`QUICKSTART.md`](QUICKSTART.md). Google sign-in errors:
[OIDC troubleshooting](#oidc-troubleshooting).

## Your files vs everyone else's

One data volume (you choose the path):

- `users/<linux-username>/` — only that PAM user

The daemon runs as one service account so it can read those trees.
HTTP refuses paths outside your folder. Other Linux logins cannot
enter your cubby.

From a login, `bootstash put` copies into `users/<your-name>/` (not
root). Ordinary `cp` (not `cp -a`) also works. Do not `chown` to
`bootstash`.

- `$DATA` is `0751` so you can traverse in
- Parent `users/` is `0711` so you cannot list other cubbies
- Your cubby is `2770` `you:bootstash` (new files get group `bootstash`)
- Opening `/home` (or start/SIGHUP) sets group `bootstash` and `0640`

## What this is not

- Not a high-assurance or regulated credential store (see Expectations)
- Not OpenBao, HashiCorp Vault, or Vaultwarden (no unseal, KV API, or
  password-manager vault)
- Not a VPN, IdP, or account provisioner
- Not Samba, Nextcloud, or WebDAV (no collections, PROPFIND, or DAV
  clients). Upload is ordinary HTTP PUT/POST, not a sync product
- Not a long-term archive or backup (see expiration, post-v1)
- Not a public anonymous download site
- Not a reason to auto-create Unix users

Package: `bootstash`. Daemon: `bootstashd`. CLI: `bootstash`
(`provision-google`, `links`, `unlink`, `put`). Changing the code:
[`DEVELOPERS.md`](DEVELOPERS.md). Building: [`BUILDING.md`](BUILDING.md).

## OIDC troubleshooting

Sign-in sends Google to `$PUBLIC_URL/oidc/callback`. That string must
match a **Web application** Authorized redirect URI
character-for-character. Google never connects to you.
`bootstash provision-google` prints the URI from the loaded config.
`sudo bootstash check-config` prints `url=` (the origin the daemon
will send). Reload after changing `PUBLIC_URL` or installing
`/etc/bootstash/oidc-google.json`.

### Obvious issues

- First install without a Google client JSON stays down
- Desktop (`installed`) JSON is rejected; download the **Web
  application** client
- Consent screen in Testing: add your Google account as a test user,
  or Google returns `access_denied`
- Register the redirect URI on the **same** client whose JSON is in
  `/etc/bootstash/oidc-google.json`
- `PUBLIC_URL` is the URL the **browser** uses. The daemon ignores
  `X-Forwarded-*`. A reverse proxy must set `PUBLIC_URL` to the vhost
- Packaged listen is loopback. Binding only a tunnel NIC while the
  origin is a public `:443` vhost means the callback misses
- Finding certs does not move `LISTEN` to 443. Derived `PUBLIC_URL`
  keeps the listen port (omitted only for 80/443)
- `TLS=no` keeps TCP binds on HTTP. Write `PUBLIC_URL` as `https://…`
  when a proxy terminates TLS
- Google email is not a folder name. After OIDC, `POST /link` with an
  existing Linux user (not root)
- Changing or disabling the Unix account does not drop the map;
  `bootstash unlink` does
- Extra DNS names are a second origin. HTTPS cookies are `__Host-`
  and do not follow Apache `ServerAlias`. A separate vhost should
  `Redirect` to `PUBLIC_URL` (see
  `/usr/share/doc/bootstash/examples/apache-vhost.conf`)
- Sign-in page **Sign-in expired**: `PUBLIC_URL` scheme does not
  match how you reach the daemon (`https` uses `__Host-` cookies,
  which browsers refuse on HTTP), or you switched hostname
- Sign-in page **Sign-in failed**: client secret does not match the
  id, or the daemon was not reloaded after installing the JSON
- Sign-in page **Google is unavailable**: this host cannot reach
  `https://accounts.google.com`

### Error 400: `redirect_uri_mismatch`

Google shows this **before** the callback reaches bootstash:

```
Error 400: redirect_uri_mismatch

You can't sign in to this app because it doesn't comply with Google's
OAuth 2.0 policy.

If you're the app developer, register the redirect URI in the Google
Cloud Console.
Request details: redirect_uri=https://stash.example/oidc/callback
flowName=GeneralOAuthFlow
```

`redirect_uri` in Request details is what the daemon sent
(`$PUBLIC_URL` plus `/oidc/callback`). It is not registered, or it
differs by scheme, host, port, path, or a trailing slash.

Usual mismatches:

- `http` vs `https`
- Host (`hostname -f` vs `CERT_NAME` vs the vhost, or `www`)
- Port (`:8080` on the derived URL while the browser is on `:443`)
- Path is not exactly `/oidc/callback`
- The URI was pasted as a JavaScript origin, not a redirect URI
- `PUBLIC_URL` was changed after the client was created

Copy that `redirect_uri` (or `url=` from `check-config` plus
`/oidc/callback`) into **Authorized redirect URIs** on that Web
client. Leave other client fields empty. Sign in again. If you
changed `PUBLIC_URL`, `systemctl reload bootstash` so the daemon
sends the new URI.

## Known issues

`/etc/bootstash/certs/` is hook-managed. `letsencrypt-deploy` copies
Let’s Encrypt `live/` into `certs/<name>/`. Do not put your own PEMs
there: an existing dest dir is treated as wanted, so a later
`live/<name>` renew can overwrite them.

With no Let’s Encrypt lineage, `certs/` may be empty. That is HTTP
unless you set `TLS_CERT` / `TLS_KEY`.

Your own certs:

- Point `TLS_CERT` and `TLS_KEY` at files **outside** `certs/`
- The daemon skips discovery when both are set
- Under `TLS=auto`, the hook may still copy `live/` into `certs/`;
  unused dest keys are readable by `bootstash`
- `TLS=no` skips the copy and removes dest PEMs

Renaming the dest (for example `/etc/bootstash/lets-encrypt/`) is not
in v1.

## License

Copyright (C) 2026 Nye Liu. GPL-3.0-or-later. See
[LICENSE](LICENSE).
