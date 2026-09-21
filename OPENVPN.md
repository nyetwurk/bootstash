# OpenVPN Connect import

bootstash is a cubby, not a VPN. It does not terminate tunnels. It
hands an `.ovpn` already in **your** folder to [OpenVPN
Connect](https://openvpn.net/client/) on a phone or laptop.

Put the profile in the cubby first (`bootstash put`, upload, or
`cp`). Then paste this cubby’s origin (`PUBLIC_URL`) into Connect —
not a file path, and not OpenVPN `remote` unless those names are
the same.

- **Install:** [`QUICKSTART.md`](QUICKSTART.md)
- **Config:** `bootstash(5)`

## Import

Connect probes `HEAD` / `GET /openvpn-api/profile` on the origin you
paste. After Google and the one-time Linux link:

- One `.ovpn` (any name), or several with a unique `client.ovpn`:
  the page opens Connect (`openvpn://import-profile/…`)
- Several `.ovpn` files with no unique `client.ovpn`: picker; tap
  one (Connect is not opened automatically)
- None: a short empty message, not the file listing

The imported profile’s display name is `remote [filename]` (first
OpenVPN `remote` in the file, then the cubby name). The URL you
paste is still `PUBLIC_URL`. That is not the tunnel endpoint.

Cubby GET of `.ovpn` (the listing) is the file as stored, cookie
only. Save on the import page is an attachment with the Connect
MIME type.

## Capability URL

Connect cannot send the Google session cookie, so URL import uses a
one-time `?token=` HTTPS URL (60 seconds, two GETs, then 404).
Whoever has that URL can fetch **that one** `.ovpn` until it
expires. The clock starts when the import page is rendered (Chrome’s
“Open OpenVPN Connect?” prompt, Connect’s confirm, and a retry).
60 seconds is that handoff envelope, not “private.”

The `openvpn://` link is in the HTML tab. A screenshot, a copied
href, or Android intent extras can leak it for that window.

Cubby listing links still need the session cookie. They are not
this URL.

If you refuse any unauthenticated fetch, disable tokens (below).
Shorter TTL only 404s a slow tap.

## Disable tokens

- **User:** empty regular file `.bootstash-no-ovpn-token` in the
  **root** of your cubby (not a subfolder):

  ```bash
  printf '' > .bootstash-no-ovpn-token
  bootstash put ./.bootstash-no-ovpn-token
  ```

  Presence matters, not content. Remove the file to turn tokens back
  on.

- **Operator:** `OVPN_TOKEN=no` in `/etc/default/bootstash`, then
  `systemctl reload bootstash`. Whole site. Not a substitute for the
  user file.

When tokens are off:

- No `?token=` mint
- Operator off: Connect paste does **not** get `Ovpn-WebAuth` (no
  waiting spinner)
- User file only: Connect paste still opens a browser (the probe
  does not know who you are). After sign-in you get **Save**, not
  `openvpn://`. Cancel Connect’s spinner and import the saved file
- Listing, cookie Save, and cubby GET of `.ovpn` still work. Import
  the file in Connect (file picker). Do not expect paste-origin to
  finish

## Origin models

One `PUBLIC_URL`. Extra DNS names `Redirect` only. Do not
`ProxyPass` two names. Do not `ServerAlias`. HTTPS cookies are
host-only.

### A — cubby origin

`PUBLIC_URL=https://bootstash.example`. Browser and Connect talk to
that host. OpenVPN `remote` is a different name (`vpn.example`
UDP). Extra names (`bs`) 301 to bootstash. Sample vhost:
`/usr/share/doc/bootstash/examples/apache-vhost.conf`.

```mermaid
flowchart TB
  subgraph clients["Clients"]
    C[Connect]
    Br[Browser]
  end
  subgraph proxy["Reverse proxy — TLS terminates here"]
    P["Apache / nginx<br/>bootstash.example:443"]
  end
  subgraph daemon["bootstashd"]
    D["TLS=no<br/>127.0.0.1:8080"]
  end
  subgraph ovpn["OpenVPN"]
    V["vpn.example UDP"]
  end
  extra["bs.example"] -->|"301"| P
  C -->|"paste PUBLIC_URL"| P
  Br --> P
  P -->|"ProxyPass"| D
  C -.->|"tunnel"| V
```

### B — VPN origin

`PUBLIC_URL=https://vpn.example`. That name is the proxy
`ServerName`. Extra cubby names 301 **to vpn**. Connect pastes vpn.
Tunnel is still `remote vpn` UDP. The reverse proxy owns 443.
OpenVPN must **not** listen on TCP 443.

```mermaid
flowchart TB
  subgraph clients["Clients"]
    C[Connect]
    Br[Browser]
  end
  subgraph proxy["Reverse proxy — TLS terminates here"]
    P["Apache / nginx<br/>vpn.example:443"]
  end
  subgraph daemon["bootstashd"]
    D["TLS=no<br/>127.0.0.1:8080"]
  end
  subgraph ovpn["OpenVPN"]
    V["vpn.example UDP"]
  end
  extra["bootstash.example"] -->|"301"| P
  C -->|"paste PUBLIC_URL"| P
  Br --> P
  P -->|"ProxyPass"| D
  C -.->|"tunnel"| V
```

### TLS termination

Usual: the reverse proxy terminates TLS. Packaged listen is
loopback HTTP (`TLS=no`). Write `PUBLIC_URL` as `https://…`. The
daemon ignores `X-Forwarded-*`.

```mermaid
flowchart LR
  subgraph proxy["Reverse proxy — TLS terminates here"]
    P["Apache / nginx :443"]
  end
  subgraph daemon["bootstashd"]
    D["TLS=no"]
  end
  Client --> P
  P --> D
```

No proxy: bootstashd terminates TLS (`TLS=auto`, PEMs under
`certs/`). Finding certs does not move `LISTEN` to 443.

```mermaid
flowchart LR
  subgraph daemon["bootstashd — TLS terminates here"]
    D["TLS=auto"]
  end
  Client --> D
```

### OpenVPN port-share

OpenVPN `port-share` on TCP 443 multiplexes the tunnel and
forwards the rest to Apache. Same address, same port. Fine if you
do not expect full Connect integration (paste `PUBLIC_URL`,
`Ovpn-WebAuth`, capability URL). The cubby through Apache still
works; import the saved `.ovpn` in Connect’s file picker.

Also not origin models: two `ProxyPass` origins, `ServerAlias`.

```mermaid
flowchart TB
  subgraph share["TCP :443"]
    OV["OpenVPN port-share"]
    P[Apache]
  end
  subgraph daemon["bootstashd"]
    D[HTTP]
  end
  C[Connect / browser] --> OV
  OV -->|"not OpenVPN"| P
  P --> D
  C -.->|"tunnel"| OV
```

A 301 from the pasted host onto another name is the same class of
failure as a 302 to `/login`:

```mermaid
sequenceDiagram
  participant Connect
  participant vpn as vpn.example
  participant cubby as bootstash.example
  Connect->>vpn: HEAD /openvpn-api/profile
  vpn-->>Connect: 301 to cubby
  Note over Connect: follows redirect, drops Ovpn-WebAuth
  Connect->>cubby: HEAD /openvpn-api/profile
  cubby-->>Connect: 200 Ovpn-WebAuth
  Note over Connect: WebAuth never starts
```
