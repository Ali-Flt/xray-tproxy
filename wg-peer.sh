#!/usr/bin/env bash
# wg-peer - one-shot WireGuard peer management for an Xray wireguard inbound.
#
#   wg-peer add <name>      the normal path. Seeds the wireguard inbound into
#                           $XRAY_CONF if absent, with NO exit outbound - the
#                           confdir's balancer is the exit. Existing peers in
#                           $WG_STATE are adopted back in, so a lost config is
#                           recoverable: keys and IPs live in the state dir.
#
#   wg-peer regen [name]    repair: rebuild whichever of the two records is
#                           missing. Restores the config from $WG_STATE and the
#                           client .conf files from the config, in that order.
#                           Also how a changed WG_ENDPOINT/WG_DNS reaches peers
#                           that already exist. Keys and addresses are never
#                           changed, so every peer keeps working.
#   wg-peer remove <name>   drop peer from config + delete its files
#   wg-peer list            show peers (ip + pubkey) from the config
#   wg-peer qr <name>       re-print an existing peer's QR
#   wg-peer selftest        run the add/list/remove/adopt logic against temp files
#
# Config via env (defaults shown):
#   XRAY_CONFDIR=conf                   ./conf, same var+default as sub2xray.py
#   WG_CONF_NAME=05-wireguard.json      this script's file within it
#   XRAY_CONF=$XRAY_CONFDIR/$WG_CONF_NAME   set directly to override both
#   WG_STATE=$HOME/.local/share/wg-peer   keys + generated confs
#   WG_ENDPOINT=vpn.example.com:51820   what the phone dials
#   WG_DNS=1.1.1.1
#   WG_SUBNET=10.100.0                  server is .1, peers .2+
#   WG_PORT=51820                       wireguard listen port (init/seed only)
#   XRAY_UNIT=xray                      systemd unit to restart after a change
#
# One xray: $XRAY_CONF lives INSIDE the sub2xray confdir, so
# `xray run -confdir /etc/xray/conf` serves socks, http and wireguard from one
# process and peer traffic exits through the pool balancer.
#
# This file carries the wireguard inbound and NOTHING else - no outbound, no
# rules. An inbound never dials an outbound directly in Xray; everything crosses
# the dispatcher and the routing rules, so a wireguard inbound needs no outbound
# of its own, only a rule that reaches one. 10-routing.json's catch-all is that
# rule, and sub2xray.py owns it.
#
# Run `sub2xray.py init` first. This script will not create the confdir: it owns
# only the file it holds the key for.
#
# ⚠ In the default `selective` mode peers get the same selective treatment as
# everything else, so most of their traffic exits `direct` from this host rather
# than through the pool. `sub2xray.py init --mode full` is the one that sends
# everything out through the balancer.
#
# The server key is generated on first use and spliced into the config's
# secretKey - UNLESS the config already has a real secretKey, which is then
# adopted so an already-running setup is never clobbered.
#
# Losing $XRAY_CONF is survivable; losing $WG_STATE is not. The state dir holds
# the server key and every peer's key and .conf, and `init`/`add` rebuild the
# config's peer list from it. A peer whose .conf is gone keeps its key but must
# be renumbered - its device then needs the new config, and you are warned.
set -euo pipefail

# One confdir, shared with sub2xray.py via the same env var and the same default.
# Relative to cwd, so a systemd unit needs WorkingDirectory= or an absolute
# XRAY_CONFDIR - a service started elsewhere would otherwise make its own ./conf.
# The name sorts before 10-routing.json, which costs nothing today (this file has
# no rules) and keeps the inbound ahead of the routing it depends on.
XRAY_CONFDIR="${XRAY_CONFDIR:-conf}"
WG_CONF_NAME="${WG_CONF_NAME:-05-wireguard.json}"
XRAY_CONF="${XRAY_CONF:-$XRAY_CONFDIR/$WG_CONF_NAME}"
WG_STATE="${WG_STATE:-$HOME/.local/share/wg-peer}"
WG_ENDPOINT="${WG_ENDPOINT:-vpn.example.com:51820}"
WG_DNS="${WG_DNS:-1.1.1.1}"
WG_SUBNET="${WG_SUBNET:-10.100.0}"
WG_PORT="${WG_PORT:-51820}"
XRAY_UNIT="${XRAY_UNIT:-xray}"

need() { command -v "$1" >/dev/null || { echo "missing tool: $1" >&2; exit 1; }; }
need wg; need jq; need qrencode

mkdir -p "$WG_STATE/peers"

# edit the wireguard inbound in place, atomically (temp file on same fs → rename)
edit_conf() {
  local tmp; tmp=$(mktemp "$(dirname "$XRAY_CONF")/.wg-peer.XXXXXX")
  jq "$@" "$XRAY_CONF" > "$tmp" && mv "$tmp" "$XRAY_CONF"
}

# Just the inbound. dns, blackhole and every routing rule belong to
# 10-routing.json - duplicating them here is how two files start disagreeing.
write_skeleton() {
  mkdir -p "$(dirname "$XRAY_CONF")"
  cat > "$XRAY_CONF" <<JSON
{
  "inbounds": [
    { "tag": "wg-in", "protocol": "wireguard", "listen": "0.0.0.0", "port": ${WG_PORT},
      "settings": { "secretKey": "", "mtu": 1420, "peers": [] } }
  ]
}
JSON
}

ensure_base() {
  [[ -f "$XRAY_CONF" ]] && return
  local dir; dir=$(dirname "$XRAY_CONF")
  # The cross-check that makes a confdir mismatch loud: if this script and
  # sub2xray.py disagree about where the confdir is, we land somewhere with no
  # routing beside us, and a wireguard inbound with no route out routes nothing.
  [[ -f "$dir/10-routing.json" ]] || {
    echo "no 10-routing.json beside $XRAY_CONF" >&2
    echo "  run:  sub2xray.py --outdir $dir init" >&2
    echo "  or point both at one place with XRAY_CONFDIR" >&2
    exit 1; }
  write_skeleton
  echo "seeded wireguard inbound at $XRAY_CONF - exits via the confdir balancer" >&2
}

ensure_server_key() {
  if [[ ! -f "$WG_STATE/server.key" ]]; then
    local existing
    existing=$(jq -r '.inbounds[]|select(.protocol=="wireguard")|.settings.secretKey // ""' "$XRAY_CONF")
    if [[ -n "$existing" && "$existing" != "<"* ]]; then
      printf '%s' "$existing" > "$WG_STATE/server.key"     # adopt a running key
    else
      (umask 077; wg genkey > "$WG_STATE/server.key")
    fi
    wg pubkey < "$WG_STATE/server.key" > "$WG_STATE/server.pub"
  fi
  # splice the key into the config whenever it's missing or still a placeholder
  # (covers fresh config against an existing state key - e.g. re-init)
  local cur
  cur=$(jq -r '.inbounds[]|select(.protocol=="wireguard")|.settings.secretKey // ""' "$XRAY_CONF")
  if [[ -z "$cur" || "$cur" == "<"* ]]; then
    edit_conf --arg sk "$(cat "$WG_STATE/server.key")" \
      '(.inbounds[]|select(.protocol=="wireguard")|.settings.secretKey) = $sk'
  fi
}

# Writes only when the content would actually differ, so "rewrote" in the output
# means something changed. Returns 1 when it left the file alone.
# Mode 600: this file carries the peer's private key, same as the .key beside it.
write_peer_conf() {
  local name="$1" ip="$2" f="$WG_STATE/peers/$name.conf" tmp
  tmp=$(mktemp "$WG_STATE/peers/.$name.XXXXXX")
  chmod 600 "$tmp"
  cat > "$tmp" <<EOF
[Interface]
PrivateKey = $(cat "$WG_STATE/peers/$name.key")
Address = $ip/32
DNS = $WG_DNS

[Peer]
PublicKey = $(cat "$WG_STATE/server.pub")
Endpoint = $WG_ENDPOINT
AllowedIPs = 0.0.0.0/0
EOF
  if [[ -f "$f" ]] && cmp -s "$tmp" "$f"; then rm -f "$tmp"; return 1; fi
  mv "$tmp" "$f"
}

# Re-add peers that exist in state but are missing from the config - the case
# where the config was lost while $WG_STATE survived. Idempotent: a peer already
# in the config is skipped, so this is safe to run on every add.
#
# The IP comes from the peer's own .conf, because that is what its client is
# pinned to. Without one there is nothing to recover and the peer must be
# renumbered, which invalidates the config already on that device.
adopt_peers() {
  local key name pub ip added=0
  shopt -s nullglob
  for key in "$WG_STATE"/peers/*.key; do
    name=$(basename "$key" .key)
    pub=$(wg pubkey < "$key" 2>/dev/null) || { echo "skip $name: unreadable key" >&2; continue; }
    if jq -e --arg pk "$pub" '[.inbounds[]|select(.protocol=="wireguard")
          |.settings.peers[]?|select(.publicKey==$pk)]|length>0' "$XRAY_CONF" >/dev/null; then
      continue
    fi
    # guarded, not `2>/dev/null`: sed exits 2 on a missing file, and under
    # `set -euo pipefail` that aborts the run - in exactly the recovery case
    ip=""
    if [[ -f "$WG_STATE/peers/$name.conf" ]]; then
      ip=$(sed -n 's#^Address *= *\([0-9.]\{1,\}\)/32.*#\1#p' \
           "$WG_STATE/peers/$name.conf" | head -1)
    fi
    if [[ -z "$ip" ]]; then
      ip=$(next_ip)
      echo "warning: $name has no saved .conf - renumbered to $ip; the config on that device is now stale, re-send it (wg-peer qr $name)" >&2
      write_peer_conf "$name" "$ip" || true
    fi
    edit_conf --arg pk "$pub" --arg ip "$ip/32" \
      '(.inbounds[]|select(.protocol=="wireguard")|.settings.peers) += [{"publicKey":$pk,"allowedIPs":[$ip]}]'
    added=$((added + 1))
  done
  shopt -u nullglob
  [[ $added -gt 0 ]] && echo "adopted $added existing peer(s) from $WG_STATE/peers" >&2
  return 0
}

next_ip() {
  local max
  max=$(jq -r '[.inbounds[]|select(.protocol=="wireguard")|.settings.peers[]?|.allowedIPs[]?
                | select(test("/32$")) | split("/")[0] | split(".")[3] | tonumber] | max // 1' \
        "$XRAY_CONF")
  echo "$WG_SUBNET.$((max + 1))"
}

reload() {
  systemctl restart "$XRAY_UNIT" 2>/dev/null && echo "xray restarted" >&2 \
    || echo "restart xray yourself: systemctl restart $XRAY_UNIT" >&2
}

cmd_add() {
  local name="$1" ip pub
  [[ -f "$WG_STATE/peers/$name.key" ]] && { echo "peer already exists: $name" >&2; exit 1; }
  ensure_base
  ensure_server_key
  adopt_peers                      # else a reseeded config silently loses everyone
  ip=$(next_ip)
  (umask 077; wg genkey > "$WG_STATE/peers/$name.key")
  pub=$(wg pubkey < "$WG_STATE/peers/$name.key")
  write_peer_conf "$name" "$ip" || true

  edit_conf --arg pk "$pub" --arg ip "$ip/32" \
    '(.inbounds[]|select(.protocol=="wireguard")|.settings.peers)
       += [{"publicKey":$pk,"allowedIPs":[$ip]}]'

  echo "added $name at $ip" >&2
  [[ -n "${WG_NOQR:-}" ]] || qrencode -t ansiutf8 < "$WG_STATE/peers/$name.conf"
  reload
}

cmd_remove() {
  local name="$1" pub
  [[ -f "$WG_STATE/peers/$name.key" ]] || { echo "no such peer: $name" >&2; exit 1; }
  pub=$(wg pubkey < "$WG_STATE/peers/$name.key")
  edit_conf --arg pk "$pub" \
    '(.inbounds[]|select(.protocol=="wireguard")|.settings.peers)
       |= map(select(.publicKey != $pk))'
  rm -f "$WG_STATE/peers/$name".{key,conf}
  echo "removed $name" >&2
  reload
}

# Put everything back in agreement from whatever survived. The two records hold
# a peer's address independently - the config in allowedIPs, the client .conf in
# Address - so either can rebuild the other:
#
#   config gone, .conf kept  -> reseed, adopt_peers restores it from .conf
#   .conf gone, config kept  -> rewritten below from the config
#   only the .key            -> renumbered, with a warning
#
# Whole-config repair runs even when a single peer is named: adopting only the
# named one would leave a config still missing the others, which is worse than
# the surprise of it fixing them.
cmd_regen() {
  local only="${1:-}" key name pub ip n=0
  ensure_base
  ensure_server_key
  adopt_peers
  shopt -s nullglob
  for key in "$WG_STATE"/peers/*.key; do
    name=$(basename "$key" .key)
    if [[ -n "$only" && "$name" != "$only" ]]; then continue; fi
    pub=$(wg pubkey < "$key")
    ip=$(jq -r --arg pk "$pub" '.inbounds[]|select(.protocol=="wireguard")
          |.settings.peers[]?|select(.publicKey==$pk)|.allowedIPs[0]' "$XRAY_CONF" | head -1)
    if [[ -z "$ip" ]]; then
      echo "skip $name: not in $XRAY_CONF - run: wg-peer add $name" >&2; continue
    fi
    if write_peer_conf "$name" "${ip%/32}"; then
      echo "rewrote  $WG_STATE/peers/$name.conf ($ip)" >&2
    else
      echo "unchanged $name ($ip)" >&2
    fi
    n=$((n + 1))
  done
  shopt -u nullglob
  if [[ -n "$only" && $n -eq 0 ]]; then echo "no such peer: $only" >&2; exit 1; fi
  return 0
}

cmd_list() {
  jq -r '.inbounds[]|select(.protocol=="wireguard")|.settings.peers[]?
          | "\(.allowedIPs[0])\t\(.publicKey)"' "$XRAY_CONF"
}

selftest() {
  local d; d=$(mktemp -d)
  export WG_STATE="$d/state" XRAY_CONF="$d/conf.json" WG_NOQR=1 XRAY_UNIT="__none__"
  mkdir -p "$WG_STATE/peers"
  echo '{"inbounds":[{"protocol":"wireguard","settings":{"secretKey":"<x>","peers":[]}}]}' > "$XRAY_CONF"
  cmd_add alice >/dev/null
  cmd_add bob   >/dev/null
  [[ $(cmd_list | wc -l) -eq 2 ]] || { echo "FAIL: expected 2 peers" >&2; exit 1; }
  cmd_list | grep -q "$WG_SUBNET.2/32" || { echo "FAIL: alice not .2" >&2; exit 1; }
  cmd_list | grep -q "$WG_SUBNET.3/32" || { echo "FAIL: bob not .3" >&2; exit 1; }
  cmd_remove alice >/dev/null
  [[ $(cmd_list | wc -l) -eq 1 ]] || { echo "FAIL: expected 1 peer after remove" >&2; exit 1; }
  # next add reuses the freed slot? no - monotonic, should be .4
  cmd_add carol >/dev/null
  cmd_list | grep -q "$WG_SUBNET.4/32" || { echo "FAIL: carol not .4" >&2; exit 1; }

  # --- refuses to seed without a confdir it can route through ---
  local d2; d2="$d/bare"; mkdir -p "$d2"
  if ( XRAY_CONF="$d2/05-wireguard.json" ensure_base ) 2>/dev/null; then
    echo "FAIL: seeded without 10-routing.json" >&2; exit 1
  fi

  # --- the lost-config case: $WG_STATE survives, XRAY_CONF does not ---
  local pub_bob pub_carol
  pub_bob=$(wg pubkey < "$WG_STATE/peers/bob.key")
  pub_carol=$(wg pubkey < "$WG_STATE/peers/carol.key")
  echo '{}' > "$d/10-routing.json"          # stands in for the sub2xray confdir
  rm -f "$XRAY_CONF"
  cmd_add dave >/dev/null 2>&1              # reseeds, adopts, then adds
  [[ $(cmd_list | wc -l) -eq 3 ]] || { echo "FAIL: add did not adopt bob+carol" >&2; exit 1; }
  # each keeps the IP its client is pinned to, and dave continues past them
  cmd_list | grep -q "$WG_SUBNET.3/32	$pub_bob"   || { echo "FAIL: bob lost his IP" >&2; exit 1; }
  cmd_list | grep -q "$WG_SUBNET.4/32	$pub_carol" || { echo "FAIL: carol lost her IP" >&2; exit 1; }
  cmd_list | grep -q "$WG_SUBNET.5/32" || { echo "FAIL: dave not .5 after adopt" >&2; exit 1; }
  # the seeded file carries the inbound only - no outbounds, no rules to disagree with
  jq -e 'has("outbounds")|not' "$XRAY_CONF" >/dev/null || { echo "FAIL: skeleton has outbounds" >&2; exit 1; }
  jq -e 'has("routing")|not'   "$XRAY_CONF" >/dev/null || { echo "FAIL: skeleton has routing" >&2; exit 1; }
  # the server key is reused, so configs already on devices still authenticate
  jq -e --arg sk "$(cat "$WG_STATE/server.key")" \
     '(.inbounds[]|select(.protocol=="wireguard")|.settings.secretKey)==$sk' "$XRAY_CONF" >/dev/null \
    || { echo "FAIL: server key not reused" >&2; exit 1; }
  # adopting twice must not duplicate
  adopt_peers >/dev/null 2>&1
  [[ $(cmd_list | wc -l) -eq 3 ]] || { echo "FAIL: adopt_peers not idempotent" >&2; exit 1; }

  # --- key without a .conf: nothing to recover, so it must renumber and say so ---
  rm -f "$WG_STATE/peers/bob.conf" "$XRAY_CONF"
  ( ensure_base && ensure_server_key && adopt_peers ) > "$d/adopt.log" 2>&1
  grep -q "renumbered" "$d/adopt.log" || { echo "FAIL: silent renumber" >&2; exit 1; }
  [[ -f "$WG_STATE/peers/bob.conf" ]] || { echo "FAIL: no replacement conf written" >&2; exit 1; }
  [[ $(cmd_list | wc -l) -eq 3 ]] || { echo "FAIL: expected 3 peers (bob carol dave)" >&2; exit 1; }
  # the ones that kept their .conf must be untouched by the renumber
  cmd_list | grep -q "$WG_SUBNET.4/32	$pub_carol" || { echo "FAIL: carol disturbed" >&2; exit 1; }

  # --- regen with the config gone entirely: rebuilt from the .conf files ---
  local sk_before; sk_before=$(cat "$WG_STATE/server.key")
  rm -f "$XRAY_CONF"
  cmd_regen >/dev/null 2>&1
  [[ -f "$XRAY_CONF" ]] || { echo "FAIL: regen did not recreate the config" >&2; exit 1; }
  [[ $(cmd_list | wc -l) -eq 3 ]] || { echo "FAIL: regen lost peers" >&2; exit 1; }
  cmd_list | grep -q "$WG_SUBNET.4/32"$'\t'"$pub_carol" \
    || { echo "FAIL: regen changed carol's IP rebuilding the config" >&2; exit 1; }
  [[ "$(cat "$WG_STATE/server.key")" == "$sk_before" ]] \
    || { echo "FAIL: regen rolled the server key" >&2; exit 1; }

  # --- regen: rebuild a .conf that is gone while the peer is still configured ---
  local ip_carol; ip_carol=$(cmd_list | grep "$pub_carol" | cut -f1)
  rm -f "$WG_STATE/peers/carol.conf"
  cmd_regen carol >/dev/null 2>&1
  [[ -f "$WG_STATE/peers/carol.conf" ]] || { echo "FAIL: regen wrote nothing" >&2; exit 1; }
  grep -q "Address = $ip_carol" "$WG_STATE/peers/carol.conf" \
    || { echo "FAIL: regen changed carol's address" >&2; exit 1; }
  # the config is untouched - regen rebuilds files, it does not re-key
  cmd_list | grep -q "$ip_carol	$pub_carol" || { echo "FAIL: regen disturbed config" >&2; exit 1; }
  # a second identical regen must report unchanged and not touch the file
  cmd_regen carol > "$d/r2.log" 2>&1
  grep -q "unchanged carol" "$d/r2.log" || { echo "FAIL: regen rewrote an identical file" >&2; exit 1; }
  # the private key file holds a secret; so does the .conf beside it
  [[ "$(stat -c %a "$WG_STATE/peers/carol.conf")" == "600" ]] \
    || { echo "FAIL: peer .conf is not 600" >&2; exit 1; }
  # a changed endpoint reaches existing peers
  WG_ENDPOINT="new.example:51820" cmd_regen carol >/dev/null 2>&1
  grep -q "Endpoint = new.example:51820" "$WG_STATE/peers/carol.conf" \
    || { echo "FAIL: regen did not pick up WG_ENDPOINT" >&2; exit 1; }
  # subshell: cmd_regen exits rather than returns, which would end the selftest
  if ( cmd_regen nosuch ) >/dev/null 2>&1; then
    echo "FAIL: regen accepted unknown peer" >&2; exit 1
  fi

  rm -rf "$d"
  echo "selftest ok"
}

case "${1:-}" in
  add)      shift; cmd_add    "${1:?usage: wg-peer add <name>}";;
  regen)    shift; cmd_regen  "${1:-}";;
  remove)   shift; cmd_remove "${1:?usage: wg-peer remove <name>}";;
  list)     cmd_list;;
  qr)       shift; qrencode -t ansiutf8 < "$WG_STATE/peers/${1:?usage: wg-peer qr <name>}.conf";;
  selftest) selftest;;
  *) echo "usage: wg-peer {add <name>|regen [name]|remove <name>|list|qr <name>|selftest}" >&2; exit 1;;
esac
