# Quick start

Install the `.deb`. This is the operator recipe. Product and
expectations: [`README.md`](README.md). Keys and files:
`bootstash(5)`. Daemon: `bootstashd(8)`. CLI: `bootstash(8)`.

`/etc/default/bootstash` ships with commented `DATA`, `BIND`,
`PUBLIC_URL`, and `ADMIN_USERS`. Add other overrides; packaged
values stay in
`/usr/lib/bootstash/default-dist`.
If configure detects a single `live/`
lineage (or `live/$(hostname -f)`), it inserts commented
`# CERT_NAME=` and `# PUBLIC_URL=` hints after the file header
(the URL the daemon would derive). The daemon still derives both
at runtime unless you uncomment them. If you delete the conffile, `dpkg -i` will not put it back;
configure restores the packaged pointer from
`/usr/lib/bootstash/default`, or use `dpkg --force-confmiss -i`.
Configure does not enable the unit. If the daemon is already
running it `try-restart`s after the cert copy; if it is down it
starts only when `bootstash check-config` would pass (same as
`bootstashd -t`). First install without a Google client id stays
down. Configure prints what is still needed (daemon not started or
not enabled on boot, no Google client id, loopback BIND, no copied
certs).

## Listen and origin

Packaged bind is `127.0.0.1:8080`. Set `BIND` before a phone can
reach you (interface, CIDR, address, `*`, or `unix://`).

`PUBLIC_URL` is the URL the **phone’s browser** uses for the OIDC
callback (Google never connects to you). When unset it is
`CERT_NAME` (see TLS) plus the first listen port, else
`hostname -f`. `https` if cert and key are present. That name must
resolve and reach this daemon. If you bind only a tunnel NIC but
the origin is a public `:443` vhost, the callback misses.

## TLS and Let’s Encrypt

Not an ACME client. Default files, when both exist:

- `/etc/bootstash/certs/<name>/fullchain.pem`
- `/etc/bootstash/certs/<name>/privkey.pem`

`name` is `CERT_NAME`. If that is unset, the hook picks
`live/$(hostname -f)` or the **only** `live/` lineage (it will not
guess when there are several). After the copy, the daemon uses that
directory as `CERT_NAME` and defaults `PUBLIC_URL` from it. Do
**not** point `TLS_CERT` / `TLS_KEY` at `/etc/letsencrypt/live`.

The packaged hook is `/usr/lib/bootstash/letsencrypt-deploy` (also
`/etc/letsencrypt/renewal-hooks/deploy/bootstash`). It copies **that
one** lineage, not every cert on the box.

- **Issue and renew:** certbot runs the hook for the chosen name.
  Unrelated lineages are skipped. Do not run it on a timer
- **Install and upgrade:** `letsencrypt-deploy sync`. One lineage on
  the box is enough; several lineages and no `CERT_NAME` **prints**
  the list
- **Force a name:** `CERT_NAME=stash.example` in
  `/etc/default/bootstash`, then
  `sudo /usr/lib/bootstash/letsencrypt-deploy sync`

Manual copy of one lineage (same as certbot’s environment):

```
RENEWED_LINEAGE=/etc/letsencrypt/live/stash.example \
RENEWED_DOMAINS=stash.example \
  /usr/lib/bootstash/letsencrypt-deploy
```

Then `systemctl reload bootstash` if the daemon is already up (the
hook does that when the service is active).

`ssl-cert` (`Recommends`) is only for `/etc/ssl/private`. Let’s
Encrypt files belong under `/etc/bootstash/certs/`.

## First run

```
# /etc/default/bootstash — BIND and origin if they are not the defaults
sudo bootstash check-config
# or: sudo bootstashd -t
sudo bootstash provision-google
sudo systemctl enable --now bootstash
```

`provision-google` cannot create the Google OAuth web client
(`gcloud` has no API for that type) and does not edit
`/etc/default/bootstash`. It prints recommended values for the
project, branding screen, and Web application client, plus the
redirect URI from the loaded config (`https` if PEMs exist; BIND
port stays). After you download the client JSON from the console,
it copies that file to `/etc/bootstash/oidc-google.json` (`-json` or a
prompted path).

Interface binds retry if the NIC is late. `systemctl reload` is
SIGHUP (certs, operator file, secrets, CIDR/interface binds). Logs
go to the journal.

## See also

Changing the code: [`DEVELOPERS.md`](DEVELOPERS.md). Building:
[`BUILDING.md`](BUILDING.md).
