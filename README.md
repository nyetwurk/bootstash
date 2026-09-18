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
- Upload into **your** folder
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

How to set `BIND`, `PUBLIC_URL`, and TLS:
[`QUICKSTART.md`](QUICKSTART.md).

## Your files vs everyone else's

One data volume (you choose the path):

- `users/<linux-username>/` — only that PAM user

The daemon runs as one service account so it can read those trees.
HTTP refuses paths outside your folder. Other Linux logins cannot
enter your cubby.

From a login you can drop files into `users/<your-name>/` with
ordinary `cp` (not `cp -a`). Do not `chown` to `bootstash`.

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
(`provision-google`, `links`, `unlink`). Changing the code:
[`DEVELOPERS.md`](DEVELOPERS.md). Building: [`BUILDING.md`](BUILDING.md).

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
