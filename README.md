# bootstash

A small daemon that is a **self-hosted cubby for bootstrap files**: after
you prove you are an existing Linux user, you **browse, download, and
upload** a shared tree (read) and your own tree (read/write) — keys,
profiles, first-run artifacts — in a phone browser.

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
  for a phone on the LAN,” not an HSM or policy engine
- A bug or stolen cookie is a bad day for those files. Keep crown jewels
  in OpenBao, `age`/`SOPS`, or not on this host
- Kits are **temporary**. Expiration (not v1) will delete aged HTTP
  uploads so this does not become a long-term archive. Until then, you
  still should not treat it as backup

If you need audit leases, Shamir unseal, or “compromise of the app server
must not yield plaintext,” this is the wrong program.

## Who it is for

Debian hosts that already have **PAM accounts**. Typical session: reach
the daemon → Google sign-in → (once) Linux username + password →
download bootstrap files. Packaged `TLS=auto` uses Let’s Encrypt
files on disk (copied into `/etc/bootstash/certs/`) when both PEMs
exist. `TLS=no` is cleartext (no dest copy; dest PEMs removed; a
reverse proxy may terminate HTTPS). See
[`QUICKSTART.md`](QUICKSTART.md). Install is a **public `.deb`**.

## What you can do

- Sign in with Google
- Link that sign-in to your existing Linux account (the same one ssh
  already uses). Username + password, once
- Browse a **shared** folder that every linked user can see (read)
- Browse **your** folder that other people cannot see
- Download files, including large ones (phones can play or save them)
- Upload into **your** folder (shared stays read-only unless you turn
  that on)
- Delete files (and empty folders) in **your** folder
- Later: **expiration** of HTTP-uploaded kit files so the tree does not
  accumulate forever

Later visits only need Google. The Linux password is not used again until
you unlink or re-link.

Your Google email is not a folder name. Folders follow the linked Linux
username. Identity is the provider’s `(issuer, sub)`.

## Listen

One or more binds: an **interface**, a **CIDR** of local addresses,
**any** / one address, or a **Unix socket** (HTTP only, for a local
proxy). How to set `BIND`, `PUBLIC_URL`, and TLS:
[`QUICKSTART.md`](QUICKSTART.md).

## Your files vs everyone else's

One data volume (you choose the path):

- `shared/` — any signed-in, linked user
- `users/<linux-username>/` — only that PAM user

The daemon runs as one service account so it can read those trees. The
cubby owner can drop files into `users/<their-name>/` from a login
(`$DATA` is `0751`; parent `users/` is `0711`; the cubby is `2770`
`you:bootstash`). Ordinary `cp` (not `cp -a`). Do not `chown` to
`bootstash`. Opening `/home` (or start/SIGHUP) sets group `bootstash`
and `0640`. Other Linux logins cannot enter your cubby. HTTP also
refuses paths outside your folder and `shared/`.

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

Package: `bootstash`. Daemon: `bootstashd`. CLI: `bootstash`. Changing
the code: [`DEVELOPERS.md`](DEVELOPERS.md). Building:
[`BUILDING.md`](BUILDING.md).

## Known issues

`/etc/bootstash/certs/` is for **hook-copied Let’s Encrypt** files
only (`letsencrypt-deploy` → `certs/<name>/`). Do not put your own
PEMs there: an existing dest dir is treated as wanted, so a later
`live/<name>` renew can overwrite them. With no Let’s Encrypt
lineage, that directory may be empty; that is HTTP unless you set
`TLS_CERT` / `TLS_KEY`.

Your own certs: point `TLS_CERT` and `TLS_KEY` at files **outside**
`certs/` (daemon already skips discovery when both are set). The
hook may still copy `live/` into `certs/` under `TLS=auto`; unused
dest keys are readable by `bootstash`. `TLS=no` skips the copy and
removes dest PEMs. A later rename of the dest (for example
`/etc/bootstash/lets-encrypt/`) is not in v1.

## License

Copyright (C) 2026 Nye Liu. GPL-3.0-or-later. See
[LICENSE](LICENSE).
