# xray-tproxy

A transparent proxy for a host or a LAN.
nftables captures traffic and hands it to one xray, which sends it out through a pool of subscription nodes behind a latency-picked balancer.

This repo is the merge of two that were being used together and kept drifting apart:
the tproxy ruleset, systemd units and installer from `xray-tproxy`, and the confdir generator, health check and wireguard peer tool from `xray-config`.
Both histories are preserved here.

```sh
sudo ./install.sh                                              # user, units, ruleset
export XRAY_CONFDIR=/etc/xray/conf
sudo -E ./sub2xray.py init                                     # once, hand-edit after
sudo -E ./sub2xray.py pool --name main --size 20 sub.txt       # every refresh
sudo systemctl restart xray
```

## The loop, and the two rules that stop it

This is the failure mode that makes a tproxy setup unusable, and it is worth understanding before changing anything.

nftables marks captured packets and sends them to xray.
xray then dials a node, and **that dial is a packet leaving this host too**.
Nothing distinguishes it from traffic you meant to capture, so it is captured, handed back to xray, and dispatched a second time.

For a plain proxy dial that only wastes a round trip.
For DNS it is fatal: the resolver's own upstream query gets fed back to the DNS module, which then answers its own lookups out of its own cache.
The log fills with `cache HIT ... empty response`, every name takes seconds, and no query ever reaches an upstream at all.

Two independent rules prevent it, and both are here on purpose:

| where | rule | covers |
|---|---|---|
| `nftables.conf`, output chain | `meta skuid xray return` | everything xray sends, whatever the protocol does |
| every outbound in the confdir | `streamSettings.sockopt.mark = 2` | matched by `meta mark 2 return` |

The uid rule is the load-bearing one.
The mark only works for protocols whose dialer honours `sockopt`, and it is one forgotten field away from being absent.
That is exactly how this broke: `parse_ss` emitted shadowsocks outbounds with no `streamSettings` at all, on the reasoning that an empty TLS block would make xray negotiate TLS on a raw TCP protocol.
True about TLS, but it took the fwmark with it, and public pools are mostly shadowsocks.
Hysteria had the same hole.
`sub2xray.py selftest` now asserts the mark over every outbound it emits rather than per protocol, because per-protocol is how the second one was missed.

> nftables resolves `meta skuid xray` to a numeric uid at parse time.
> The ruleset will not load if the `xray` user does not exist yet, which is why `install.sh` creates it first.

## What install.sh puts where

| repo file | installed to |
|---|---|
| `nftables.conf` | `/etc/xray/nftables.conf` |
| `systemd/xray.service` | `/usr/lib/systemd/system/xray.service` |
| `systemd/xray-nftables.service` | `/usr/lib/systemd/system/xray-nftables.service` |
| `conf/*.json`, if present | `/etc/xray/conf/` |

Both are namespaced on purpose.
A unit called `nftables.service` overwrites the one the distro's nftables package ships, and `/etc/nftables.conf` is that package's config file.
Installing over both means a package update silently reverts the capture, or the distro's own ruleset flushes this one.

`install.sh` refuses to overwrite a populated `/etc/xray/conf`, because that is where your pools and your hand-edited routing live.
It re-installs the units and the ruleset with `--force-units`.
It validates the config with `xray -test` before enabling anything: starting the capture with a config xray will not load is how a transparent proxy takes the whole host offline, since the ruleset happily tproxies every packet at a port with nothing behind it.

The tools themselves are not installed.
Run `sub2xray.py`, `alive.sh` and `wg-peer.sh` from the clone, with `XRAY_CONFDIR=/etc/xray/conf`.

## Layout

| file | owner | holds |
|---|---|---|
| `00-inbounds.json` | `sub2xray init` | the tproxy door, a plain socks/http port, `log` |
| `05-wireguard.json` | `wg-peer` | the wireguard inbound: server key + peers |
| `10-routing.json` | `sub2xray init` | dns, outbounds, observatory, the `lb` balancer, the rules |
| `50-pool-<name>-NN.json` | `sub2xray pool` | outbounds for one subscription, chunked |

All inside `$XRAY_CONFDIR`, default `conf` in the current directory, `/etc/xray/conf` once installed.
`sub2xray --outdir` and `wg-peer`'s `XRAY_CONF` override individually.

**`XRAY_CONFDIR` is relative, so it follows your shell.**
A systemd unit needs `WorkingDirectory=` or an absolute path.
Started from elsewhere it would quietly create its own empty `conf/`.

**`init` and `pool` are separate commands because they have different lifecycles.**
`init` writes what you then hand-edit and rarely touch, `pool` rewrites node files on every refresh.
`pool` refuses to run if `10-routing.json` is missing rather than scaffolding it, which is the conflation the split exists to prevent.
The two scaffold files are created only if missing; `--force` rewrites them and discards your edits.

**Re-running `pool` removes that pool's old chunk files first.**
Otherwise a subscription that shrank from 200 nodes to 120 would leave chunks 07 to 10 behind, and `-confdir` would merge those dead nodes straight back in without a word.

## Selective or full

`sub2xray init --mode` replaces the two `config*.json.example` files the tproxy repo used to carry.
They only ever differed in the last few routing rules, and keeping two whole configs in step by hand is how one of them rots.

| mode | catch-all | proxied |
|---|---|---|
| `selective` (default) | `direct` | `DOMAIN_LIST` and `geoip:telegram` |
| `full` | the `lb` balancer | everything |

Edit `DOMAIN_LIST` at the top of `sub2xray.py` and re-run `init --force`.
The same list scopes the proxied DNS server, so the two cannot disagree about what is proxied.

In both modes, ads are blackholed, `geoip:private` and bittorrent go direct, and udp/443 is blocked.
Blocking QUIC makes browsers fall back to TCP TLS, which these proxies can actually carry.
It has to sit above the proxy rules: below them the proxied domains are exactly the QUIC-heavy ones, and their udp/443 would be handed to a balancer that cannot carry it.

Torrents going direct is deliberate.
These are free public nodes shared by strangers, a swarm opens hundreds of connections a second, and it would be both useless over them and abusive to them.

## DNS

Split, and the split is the point.

| server | tag | routed | resolves |
|---|---|---|---|
| `https://1.1.1.1/dns-query` | `dns-proxied` | the `lb` balancer | `DOMAIN_LIST` in selective mode, everything in full |
| `https://8.8.8.8/dns-query` | `dns-direct` | `direct` | the rest |

A DNS server's `tag` becomes the **inbound tag** of the queries that server emits.
That is the whole mechanism, and it is what lets a routing rule say where a lookup travels rather than only where it is sent.

> The rules that read those tags need `"type": "field"`.
> Without it the rule is not a field rule and never matches.
> It is a silent no-op: the tag looks wired up and the queries go out the catch-all.

Resolving proxied names at the exit is not only about poisoning.
It is where the answer should come from.
Resolve a CDN name locally and you get the IP that is optimal for here, then reach it down a tunnel that surfaces somewhere else.

**DoH on both, and that is what makes the fallback safe.**
If the proxied lookup cannot complete, which is the window after a restart while the observatory has probed nobody and `fallbackTag` is blackholing, xray falls through to the next server.
Falling through to a plaintext resolver is how a censored name gets a forged answer that is then cached, after which even a working node dials the block address.
Falling through to another DoH server costs a geographically wrong answer and nothing else, so the fallback is left on.
Refusing to resolve at all would deadlock the pool it is waiting for.

**Never `udp://` or `tcp://`.**
On a network that injects DNS answers a plain resolver is not a resolver, and using a public one instead is not the fix.
`8.8.4.4` returns the block address too, because the injection happens in transit rather than at the server.
Over HTTPS a forged answer fails the certificate check.
`tcp://` has a second problem: the stream is framed by a 2-byte length prefix, so anything that answers port 53 with something else corrupts it beyond recovery, and an HTTP reply reads as an 18516-byte message.

`queryStrategy: UseIPv4`, because otherwise every name is asked twice and the empty AAAA half is retried against every server in turn.

**The DNS rules must stay first in the rule list.**
Below the port-53 rule, a resolver's own query matches that rule and is handed back to `dns-out`, which is the loop again by a different route.

## Which subscription entries become outbounds

| scheme | result |
|---|---|
| `vless://` `vmess://` `trojan://` | outbound |
| `ss://` | outbound, SIP002 (base64 or plain userinfo) and the legacy all-in-one-blob form |
| `hysteria2://` `hy2://` | outbound, registered as protocol `hysteria` with `version: 2`; there is **no** `hysteria2` config id |
| `hysteria://` `hy://` | **skipped**, that outbound only speaks version 2 and v1 is dead upstream |
| `ss://` with a legacy cipher or `?plugin=` | **skipped**, xray dropped the stream ciphers and plugins are separate processes it cannot host |

**Every skip is counted and named on stderr**, per scheme, with the node's `host:port` and the reason.

```
skipped 1 hysteria2 node(s):
  h.example:443 - no hysteria2 outbound exists in xray-core
```

This is the point, not decoration.
A subscription that silently halves is indistinguishable from one full of dead nodes, and `alive.sh`'s counts would then be measured against a pool that lost members without saying so.
One malformed entry is skipped the same way and never aborts the batch.

> **A hysteria outbound with no `address` panics xray on load.**
> It does not fail `-test`, it takes the process down.
> Verified on 26.3.27, so the parser validates host and port before emitting one.

Shadowsocks outbounds carry `settings.servers[0]` rather than `vnext[0]`, and `streamSettings` containing **only** `sockopt`.
No `network` and no `security`, so xray keeps its raw TCP defaults.
`alive.sh` reads both shapes.

**`conf/` and `subs/` are gitignored.**
Pool files carry uuids, passwords and reality keys, and a subscription file is the same credentials in URI form, often the account itself.

## Which of my nodes are alive?

```sh
./alive.sh                    # report only
./alive.sh --prune            # delete the dead
ALIVE_SINCE=-6h ./alive.sh --prune
./alive.sh selftest           # hermetic: stub journalctl, throwaway confdir
```

It reads `journalctl --system -u xray.service --since -1h` and nothing else.
The service is already probing every node continuously, so there is no second xray and no duplicate probe traffic, and the window widens with time rather than patience.

> **This works only while xray logs to stdout**, which is what makes journald the log.
> Point `log.access`/`log.error` at files and journalctl goes quiet, so every run reports a pool in which nothing has ever failed.
> That is the one outcome the tool cannot tell apart from a broken grep, so it says so rather than letting it read as good news.

Two lines matter, and they sit at different log levels:

```
[Warning] app/observatory/burst: error ping https://.../generate_204 with prox-main-105: ...
[Debug]   app/observatory/burst: burst: checking prox-main-105
```

So at the default `warning` you get every failure and no proof of life.
The dead list is measured; alive at that level only ever means *not reported failing*, and the summary says exactly that rather than claiming more.
`sub2xray.py init --force --loglevel debug` makes it report who actually answered.

> **Never grep `the outbound X is dead`.**
> That is the plain observatory's message.
> `burstObservatory` never emits it, so grepping for it reports a perfect pool, silently.

`--prune` deletes the dead outbound from its pool file.
Nothing is kept, deliberately: the subscriptions are the source, so regenerating from them is the recovery.
The delete is per-file `mktemp`+`mv`, so a crash cannot leave a half-written pool.
The running service keeps its old config until you restart it.

**`ALIVE_MIN` (default 1) refuses a prune that would leave fewer than N nodes**, and says so on stdout with the exact override to type.
Everything failing at once is nearly always your uplink, DNS or the probe destination, not 300 unrelated servers dying together.
This exists for the scheduled path, which a report-only dry run cannot protect: a cron job passes `--prune` by definition and nobody reads its output.

> With `fallbackTag: block`, an empty pool is a silent total outage rather than a leak.
> Safe, but you are offline and nothing says so loudly.

## wireguard peers

```sh
export WG_ENDPOINT=vpn.example.net:51820   # what the phone dials
./wg-peer.sh add phone        # keypair, next free IP, QR, splice into config
./wg-peer.sh list
./wg-peer.sh regen [name]     # rebuild client .conf files, keys and IPs untouched
./wg-peer.sh remove phone
```

`WG_ENDPOINT` defaults to the placeholder `vpn.example.com:51820`.
Leave it unset and every QR you hand out points at a host that does not exist, with no error.

`wg-peer` owns `05-wireguard.json` because only it can generate the server key.
Xray rejects an empty `secretKey`, so there is no useful stub for Python to write.
That file holds the inbound and nothing else.
An inbound never dials an outbound directly in Xray; traffic crosses the dispatcher and the routing rules, so the wireguard inbound needs no outbound of its own, just the rules in `10-routing.json`.

> In `selective` mode peers get the same selective treatment as everything else, so most of their traffic exits `direct` from this host.
> Use `--mode full` if peers should exit through the pool.

**`regen` is the recovery command, in both directions.**
A peer's address is recorded twice and independently, in `allowedIPs` in the config and `Address` in the client `.conf`, so whichever survives rebuilds the other.

| lost | recovered | from |
|---|---|---|
| `05-wireguard.json` | yes, `wg-peer regen` | each peer's `.conf`, plus `server.key` |
| a client `.conf` | yes, `wg-peer regen [name]` | the config's `allowedIPs` |
| both, `.key` survives | peer renumbered, with a warning | next free address |
| **`$WG_STATE`** | nothing | keys are gone, every peer must be re-added |

**`regen` never generates a key.**
`wg genkey` runs in exactly two places: `add`, for a brand new peer, and the server key when `$WG_STATE/server.key` does not exist.

> The one case that breaks every peer is a missing `$WG_STATE/server.key`.
> The server key is then generated fresh, its public half changes, and no existing client config authenticates any more.

## How the merge works

`-confdir` reads the files in name order and merges them **by tag**.

- Outbounds from different files accumulate. That is what makes pool files additive.
- **A tag in two files is silently overwritten and the earlier node is destroyed.** Not mis-selected: gone from the merged config, with `Configuration OK` and no error. Tags are `prox-<pool>-<n>`, so pools collide only if two pools share a name.
- Everything is selected by the `prox` prefix. Xray selectors are prefix matches and nothing else, so `TAG_PREFIX` here and `subjectSelector` in `10-routing.json` must agree.

Chunk numbers are zero-padded because `-confdir` reads in name order, where `10` sorts before `2`.

**Do not audit the merge by counting log lines.**
Xray's logger is asynchronous and `-test` exits before it drains.
A 200-node run printed 170 `prepend outbound` lines on one run and 173 on the next, while all 200 outbounds were present.
To check what really merged:

```sh
xray convert pb conf/*.json | strings | grep -oE 'prox-[a-z]+-[0-9]+' | sort -u | wc -l
```

## Known limits

- **One observatory, globally.** Observatories cannot be chained or nested, and every balancer shares this one. Probe scope is `subjectSelector` alone, never balancer membership.
- **`burstObservatory`, never the plain `observatory`.** The plain one sleeps `probeInterval` *between each outbound*, so the interval is a per-node delay rather than a round period. Measured at 4 of 50 nodes reached in 40s at a 10s interval, which over 200 nodes at `3m` would be a ten hour round. Declare only one of the two; with both present, `leastLoad` silently degrades.
- **Probe rate is `nodes / interval`.** At `3m`, 200 nodes is about 1.1 probes/sec. `sampling` is a window, not a rate. There is no backoff, so a dead node is re-probed forever, which is why pruning happens here rather than in Xray. **Keep the pool to a few dozen live nodes.** A pool of 2000 spends its whole life probing and the balancer never converges.
- **Startup fires every probe at once**, with no spread.
- **`fallbackTag` is `block`.** When the strategy can pick nobody, chiefly the window after a restart, traffic is blackholed rather than falling through to whichever node happens to be first. It fails fast instead of timing out against one arbitrary node. It is also why `dns-direct` exists.
- **`geosite:`/`geoip:` rules need the `.dat` files.** A missing one is a hard startup failure, not a warning. `xray.service` sets `XRAY_LOCATION_ASSET=/usr/share/xray`, which is right for Arch; Debian and the official install script use `/usr/local/share/xray`.
- **The plain socks/http port is `auth: noauth`.** It defaults to `127.0.0.1`. Point `--proxy-listen` at a docker bridge to serve containers, and firewall it if you widen it further.
- **`--vless-listen` is off by default and generates its own uuid.** A literal uuid in a config template is a credential every clone shares, on an inbound that is reachable from the network by definition.

## Migrating

If you were running the old `config.json` single-node setup, `sub2xray.py pool` accepts a file with one URI in it, and the balancer degenerates to that node.
`update_outbound_from_sub.py` is gone: it picked the single lowest-ping VLESS node from a subscription and rewrote `config.json`, stopping both services for eight seconds to do it.
`burstObservatory` plus the `lb` balancer does the same selection continuously, per connection, with no outage and no dependency on `python-v2ray`.

If you were running the old `conf/` setup, `sub2xray.py init --force` rewrites the two scaffold files.
Your pool files are untouched, but check the diff on `10-routing.json` first: the DNS design changed and the rule order matters.
