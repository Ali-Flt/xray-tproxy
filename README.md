# xray-tproxy

A transparent proxy for a host or a LAN. nftables captures traffic and hands it to one xray, which sends it out through a pool of subscription nodes behind a latency-picked balancer. A timer refreshes that pool, prunes whatever stops answering, and publishes the survivors; a container posts the list to Telegram when it changes.

## Setup

```sh
sudo ./install.sh                              # user, dirs, units, ruleset
export XRAY_CONFDIR=/etc/xray/conf
sudo -E ./sub2xray.py init                     # inbounds + routing, once
sudoedit /etc/xray/conf/domains.txt            # what gets proxied; init --force to apply

sudoedit /etc/xray/subscriptions.txt           # "<pool-name> <url>", one per line
sudo REFRESH_QUIET=60 REFRESH_MAX=300 /usr/local/bin/xray-refresh   # first cycle, shortened

sudo ./install.sh                              # validates the confdir, enables both services
sudo systemctl enable --now xray-refresh.timer # every 30 min from here
```

The second `install.sh` is not a typo: the first had no config to check, the second runs `xray -test` against it and only then starts anything.

Then the Telegram publisher:

```sh
cd telegram
cp config.ini.example config.ini && $EDITOR config.ini   # api_id, api_hash, bot_token, chat_id
docker compose up -d
```

`api_id`/`api_hash` from [my.telegram.org](https://my.telegram.org), token from `@BotFather`. `chat_id` takes a channel, supergroup or group - all `-100…` except basic groups.

**Add the bot before starting it.** For a channel that means *Manage channel -> Administrators -> Add admin*, leaving "Post Messages" on: a channel accepts posts only from admins, so a bot that is merely subscribed cannot publish. A group only needs the bot as a member. The id is resolved once at startup and the container exits with the reason if it cannot be.

To remove it: `sudo ./uninstall.sh` stops the services and unloads the capture, keeping your confdir and the published list. `--purge` deletes those and the `xray` user too. It tears the ruleset and the policy route down **before** deleting the units, and stops with them intact if that did not work - their `ExecStop` is the only other thing that can unload the capture, and a half-removed one leaves the host with no network.

> **The checkout has to stay where it is.** `/usr/local/bin/xray-refresh` is a symlink into it, and `refresh.sh` finds `alive.sh` and `sub2xray.py` beside itself.

## What the timer does

Every 30 minutes, measured from when the last cycle **finished**:

1. fetch each subscription as the `xray` user, so the fetch is not captured and cannot be blackholed by the dead pool it is replacing. A failed fetch is retried through the proxy, then leaves the pool on disk alone
2. `xray -test`, then restart `xray` and `xray-nftables`
3. every 30s, `alive.sh --prune`; if it deleted anything, restart and reset the clock. Settled when nothing has failed for 5 minutes
4. export the survivors to `/var/lib/xray/working.txt`

Nothing is published unless step 3 settles - a list already known to be dead is worse than yesterday's. A cycle that never goes quiet exits non-zero and leaves the file alone.

```sh
journalctl -fu xray-refresh
systemctl list-timers xray-refresh
```

## Day to day

```sh
sudo systemctl restart xray                 # PartOf restarts the ruleset with it
sudo -E ./alive.sh                          # what is failing, report only
sudo -E ./alive.sh --prune                  # ...and delete it
sudo -E ./sub2xray.py export                # the pool, back as URIs, on stdout
sudo -E ./sub2xray.py pool --name x sub.txt # add a pool by hand
WG_ENDPOINT=vpn.example:51820 ./wg-peer.sh add phone   # wireguard peer + QR
```

Every script has `--help` and a hermetic `selftest` that needs no service and no network.

## Files

| path | owner | holds |
|---|---|---|
| `/etc/xray/conf/00-inbounds.json` | `sub2xray init` | tproxy door, socks/http port, `log` |
| `/etc/xray/conf/10-routing.json` | `sub2xray init` | dns, outbounds, observatory, balancer, rules |
| `/etc/xray/conf/05-wireguard.json` | `wg-peer` | wireguard inbound: server key + peers |
| `/etc/xray/conf/50-pool-<name>-NN.json` | `sub2xray pool` | one subscription's outbounds, chunked |
| `/etc/xray/conf/domains.txt` | **you** | what is proxied, one matcher per line |
| `/etc/xray/subscriptions.txt` | **you** | `<pool-name> <url>` per line |
| `/etc/xray/nftables.conf` | `install.sh` | the capture ruleset |
| `/var/lib/xray/working.txt` | `refresh.sh` | the last settled export |

## Configuration

`sub2xray.py init --help` for the rest; these are the ones worth knowing.

| flag | default | |
|---|---|---|
| `--mode` | `selective` | `selective`: only `domains.txt` + `geoip:telegram` exit via the pool. `full`: everything does |
| `--strategy` | `leastPing` | `leastPing` sends everything to the single lowest-latency node; `leastLoad` spreads it over the three steadiest, which suits a pool of free public nodes better |
| `--probe-interval` | `3m` | probe rate is nodes / interval, and the whole pool is dialled at once on restart |
| `--proxy-listen` | `0.0.0.0` | the plain socks/http port. See the warning below |
| `--loglevel` | `warning` | `error` and `none` leave `alive.sh` nothing to read; `debug` adds proof of life |
| `--access-log` | `none` | not affected by `--loglevel`; unset means stdout, which journald keeps |

`refresh.sh --help` lists its environment: `REFRESH_QUIET`, `REFRESH_EVERY`, `REFRESH_MAX`, `REFRESH_LIMIT`, `REFRESH_SIZE`, `REFRESH_FETCH_USER`, `REFRESH_OUT`, `ALIVE_MIN`.

## Gotchas

**Both services, and the second will not follow the first.** `xray-nftables` is `PartOf=xray.service`, which propagates stop and restart but **not start**. Starting xray alone leaves the ruleset unloaded and nothing says so: nothing is captured and everything reaches the internet directly. Use `systemctl enable --now xray xray-nftables`.

```sh
systemctl is-active xray xray-nftables   # both must say active
sudo nft list table ip xray | head       # the ruleset is loaded
ip rule show | grep 'fwmark 0x1'         # the policy route exists
```

**Logging must stay on stdout.** Point `log.access`/`log.error` at files and journald goes quiet, so `alive.sh` reports a pool in which nothing has ever failed - the one outcome it cannot tell apart from a broken grep.

**Ports 22, 2080 and 8585 stay direct, both ways.** `KEEP_DIRECT_PORTS` in `nftables.conf`. Whatever `prerouting` will not tproxy, `output` must not mark, or the packet is routed to `lo`, refused, and silently dropped - `git pull` over ssh timing out after two minutes is what that looks like. To put github ssh through the pool, do it in ssh, not nftables:

```
# ~/.ssh/config
Host github.com
  Hostname ssh.github.com
  Port 443
```

That leaves port 22 alone. In `selective` mode it still goes direct, because ssh-on-443 is not TLS and no `domain:` rule can match it; use the HTTPS remote if you want github on the pool.

**The socks/http port is `auth: noauth` on `0.0.0.0`.** An open proxy to anything that can route here. Firewall it, or narrow it with `--proxy-listen`.

**`geosite:`/`geoip:` rules need the `.dat` files**, and a missing or misspelled one is a hard startup failure. `xray.service` sets `XRAY_LOCATION_ASSET=/usr/share/xray`; Debian and the official installer use `/usr/local/share/xray`.

**An empty pool is a silent total outage.** `fallbackTag` is `block`, so when the balancer can pick nobody, traffic is blackholed rather than leaking. `ALIVE_MIN` (default 1) refuses a prune that would leave fewer than N.

**Probe cost is the whole pool, every interval, concurrently, with no backoff.** Past ~200 outbounds the balancer stops converging and looks like it is full of bad nodes. `sub2xray.py` prints the arithmetic when you cross it; cut it with `REFRESH_LIMIT`, `alive.sh --prune`, or a longer `--probe-interval`.

**`pool` and `export` drop repeated entries**, keyed on the whole outbound bar its tag - so one server offered over two transports stays two entries. Both say how many collapsed, which is why a settled pool of 13 can publish 5.

**The bot posts only what is new**, as text in fenced blocks - copyable, with no file to download. The first run has nothing to compare against and sends the whole list once. Long batches are split across messages at Telegram's 4096-character limit, between URIs and never inside one.

Nodes are compared with their `#tag` stripped, because tags are positional: one node arriving upstream renumbers every node after it, and hashing the file would call all of them new. What it remembers is what is published *now*, not everything ever seen, so a node that drops out and comes back is announced again.

**The bot reaches Telegram through the pool, not around it.** Its container sits on a docker bridge, prerouting captures it like everything else, and `geoip:telegram` routes to the balancer - which is what you want, since Telegram direct is usually the blocked path. But it means the publisher cannot connect while the pool is down, and every refresh cycle restarts xray underneath it. It retries with a backoff rather than exiting; `cannot reach Telegram` in its log points at the pool, not at the bot.

**`/var/lib/xray/working.txt` is a list of credentials.** Written `0600`. Anything you forward it to is publishing them, Telegram included, and nothing can un-send that. `conf/`, `subs/`, `subscriptions.txt`, `working.txt` and `telegram/config.ini` are gitignored.

## Why it is built this way

The reasoning lives next to the code, not here:

| file | explains |
|---|---|
| `nftables.conf` | the capture loop, and the two rules that stop xray capturing itself |
| `sub2xray.py` | which subscription entries become outbounds, split DNS, the observatory |
| `alive.sh` | how deadness is measured, and why a clean bill of health is suspicious |
| `refresh.sh` | why the fetch runs as the `xray` user, and why every prune is followed by a restart |
| `telegram/bot.py` | why it polls rather than watching, why the list is fenced, and why a bot cannot look its own channel up |

Upgrading an existing confdir: `init --force` rewrites the two scaffold files and leaves your pools alone. Check the diff on `10-routing.json` first - rule order is load-bearing there.
