# bootstash

A small daemon that is a **self-hosted cubby for bootstrap files**,
and a way to **import an `.ovpn` into OpenVPN Connect** by pasting
this cubby’s origin. After you prove you are an existing Linux user,
you browse, download, and upload your own tree — keys, profiles,
first-run artifacts — from whatever browser you have on the road.

It is not a secrets engine (no unseal, leases, or KV API). It is not
a VPN: it hands a profile to Connect; it does not terminate tunnels.
Bind wherever you want (loopback, LAN, a tunnel NIC, later a public
address). Sign-in is a list of identity providers (Google today).
PAM maps that auth onto a local Unix user's directory. With no
provider configured, the packaged default is a Unix username and
password. `PAM=no` with `ALLOWED_EMAILS` gives each verified address
its own cubby and no Unix password. Another issuer is another
provider, not a new session model.

- **Install and first run:** [`QUICKSTART.md`](QUICKSTART.md)
- **OpenVPN Connect:** [`OPENVPN.md`](OPENVPN.md) (paste `PUBLIC_URL`;
  import uses a short-lived unauthenticated URL)
- **Config:** `bootstash(5)`

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
- An OpenVPN import URL is temporary read access to that one `.ovpn`.
  It dies with the browser session that minted it (sign out or
  `bootstash unlink`), and it can show up in history or proxy logs.
  See [`OPENVPN.md`](OPENVPN.md)
- Cubby assets are **temporary**. Expiration (not yet shipped) will
  delete aged HTTP uploads so this does not become a long-term
  archive. Until then, you still should not treat it as backup

If you need audit leases, Shamir unseal, or “compromise of the app server
must not yield plaintext,” this is the wrong program.

## Who it is for

Debian hosts that already have **PAM accounts**. The person using it is
a **road warrior**: laptop, tablet, or phone, away from the usual
shell.

Typical first session when Google is configured:

- Reach the daemon
- Sign in with Google
- Once: Linux username and password
- Download bootstrap files, or paste this origin into OpenVPN Connect

With no identity provider, sign in with the Linux username and password.

Install is a **public `.deb`**. Paste `PUBLIC_URL` into OpenVPN
Connect: [`OPENVPN.md`](OPENVPN.md).

## What you can do

- Sign in with Google, then log in with your existing Linux account
  (the same one ssh already uses). Username + password, once
- Or sign in with that username and password when no identity provider
  is configured
- Browse **your** folder that other people cannot see
- Download files, including large ones (Range so a browser can play or
  save them)
- Copy a file’s link from the listing (clipboard icon next to the
  name)
- Upload into **your** folder
- From a host login: `bootstash put` copies every file into **your** folder (`-t` for a directory inside it; not sudo)
- Delete files (and empty folders) in **your** folder
- Sign out (this browser session; the map stays)

After that Unix login, later visits only need Google. Changing or
disabling the Unix account does not drop the map. The Linux password
is not used again until an operator runs `bootstash unlink` (that
user's subjects must log in again). A password-only login asks for
the Unix password each visit.

Your Google email is not a folder name. With PAM left on, folders
follow the Unix username (after Google, or the password login when
no identity provider is configured). With `PAM=no`, each verified
address is its own cubby, named by the SHA-256 of that address.
Identity for provider auth is `(issuer, sub)`.

## Listen

Binds (interface, CIDR, address, or a Unix socket) and TLS (`auto` or
`no`): [`QUICKSTART.md`](QUICKSTART.md). Google sign-in errors:
[OIDC troubleshooting](#oidc-troubleshooting).

## Your files vs everyone else's

One data volume (you choose the path): `users/<linux-username>/` for
that PAM user. The daemon runs as one service account so it can read
those trees. HTTP refuses paths outside your folder.

From a login, `bootstash put` (not sudo) copies every source into
your cubby. `-t` is the only directory inside it. Ordinary `cp`
also works. Modes and what not to `chown`:
[`QUICKSTART.md`](QUICKSTART.md) (Users and files).

## What this is not

- Not a high-assurance or regulated credential store (see Expectations)
- Not OpenBao, HashiCorp Vault, or Vaultwarden (no unseal, KV API, or
  password-manager vault)
- Not a VPN, IdP, or account provisioner (Connect import is
  [`OPENVPN.md`](OPENVPN.md))
- Not Samba, Nextcloud, or WebDAV (no collections, PROPFIND, or DAV
  clients). Upload is ordinary HTTP PUT/POST, not a sync product
- Not a long-term archive or backup (see expiration, not yet shipped)
- Not a public anonymous download site
- Not a reason to auto-create Unix users

Package: `bootstash`. Daemon: `bootstashd`. CLI: `bootstash`
(`provision-google`, `links`, `unlink`, `put`).

- Changing the code: [`DEVELOPERS.md`](DEVELOPERS.md)
- Building: [`BUILDING.md`](BUILDING.md)

## OIDC troubleshooting

Sign-in sends Google to `$PUBLIC_URL/oidc/callback`. That string must
match a **Web application** Authorized redirect URI
character-for-character. Google never connects to you.
`bootstash provision-google` prints the URI from the loaded config.
`sudo bootstash check-config` prints `url=` (the origin the daemon
will send). Reload after changing `PUBLIC_URL` or installing
`/etc/bootstash/oidc-google.json`.

### Obvious issues

- `PAM=no`, or `IDP=google`, without a Google client JSON stays down.
  The packaged default (`PAM=yes`, `IDP` unset) can start with no
  JSON: the login is a Unix username and password
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
- Google email is not a folder name. After a provider auth, `POST /login`
  with an existing Linux user (not root) when `PAM=yes`. `PAM=no` uses
  the email cubby and does not ask for a Unix password. With no provider,
  `/login` is that Unix password and there is no map row
- `ALLOWED_EMAILS` empty: whoever the Google client admits. If any
  address is set, an unlisted or unverified account is rejected at
  auth and does not reach the Unix password
- Changing or disabling the Unix account does not drop the map;
  `bootstash unlink` does
- Extra DNS names are a second origin. HTTPS cookies are `__Host-`
  and do not follow Apache `ServerAlias`. A separate vhost should
  `Redirect` to `PUBLIC_URL` (see
  `/usr/share/doc/bootstash/examples/apache-vhost.conf` and
  [`OPENVPN.md`](OPENVPN.md) Origin models)
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

Cert layout, hook-managed `certs/`, and your own PEMs:
[`QUICKSTART.md`](QUICKSTART.md) (TLS and Let’s Encrypt).
