# bootstash

A small daemon that is a **self-hosted cubby for bootstrap files**: after
you prove you are an existing Linux user, you **browse, download, and
upload** a shared tree (read) and your own tree (read/write) — keys,
profiles, first-run artifacts — in a phone browser.

It is not a secrets engine (no unseal, leases, or KV API). Bind wherever
you want (loopback, LAN, a tunnel NIC, later a public address). v1 auth
is Google OIDC linked to PAM; other issuers can be added later.

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
download bootstrap files. TLS is either on a reverse proxy or Let’s
Encrypt files on disk. Install is a **public `.deb`**.

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

One or more binds:

- **Interface** — `eth0`, `wg0`, `tun0`, …
- **CIDR** — each local address in a prefix
- **Any** / **one address** / **Unix socket** (HTTP only, for a local proxy)

Each bind is HTTP (proxy terminates TLS) or HTTPS (operator-supplied
`fullchain.pem` / `privkey.pem`). Not an ACME client. **SIGHUP** /
`systemctl reload` rereads certs, `/etc/default/bootstash`,
`/etc/bootstash/oidc-google`, and interface/CIDR binds.

`PUBLIC_ORIGIN` is the URL the **phone’s browser** uses for the OIDC
callback (Google never connects to you). That name must resolve and reach
this daemon from the client. If you bind only a tunnel NIC but the origin
is a public `:443` vhost, the callback misses. Point the origin at where
the daemon actually listens (for example a VPN-only hostname), or bind
where that origin lands.

## Your files vs everyone else's

One data volume (you choose the path):

- `shared/` — any signed-in, linked user
- `users/<linux-username>/` — only that PAM user

The daemon runs as one service account so it can read those trees. Other
Linux logins cannot walk into your `users/...` directory. HTTP also refuses
paths outside your folder and `shared/`.

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

## Operations (short)

Install the `.deb`. Operator config, binds, TLS, and keys are in
`bootstash(5)`. The daemon is `bootstashd(8)`; the CLI is
`bootstash(8)`.

`/etc/default/bootstash` is **empty**; add only overrides (origin,
`BIND`). Then:

```
bootstash check-config
# or: bootstashd -t
bootstash provision-google
systemctl enable --now bootstash
```

`provision-google` cannot create the Google OAuth client (`gcloud` has
no API for that web client type) and does not edit
`/etc/default/bootstash`. Interface binds retry if the NIC is late.
`systemctl reload` is SIGHUP. Logs go to the journal. The service user
is in group `ssl-cert` when that package is installed (`Recommends:
ssl-cert`).

Package: `bootstash`. Daemon: `bootstashd`. CLI: `bootstash`. Changing
the code: [`DEVELOPERS.md`](DEVELOPERS.md). Building:
[`BUILDING.md`](BUILDING.md).

## License

Copyright (C) 2026 Nye Liu. GPL-3.0-or-later. See
[LICENSE](LICENSE).
