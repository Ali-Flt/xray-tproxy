#!/usr/bin/env bash
# install — put the system pieces in place. Run once, as root.
#
#   ./install.sh                 install units + ruleset, seed /etc/xray/conf
#   ./install.sh --force-units   overwrite units and nftables.conf, keep conf/
#
# What it does NOT do is manage your nodes. The confdir is generated:
#
#   XRAY_CONFDIR=/etc/xray/conf ./sub2xray.py init
#   XRAY_CONFDIR=/etc/xray/conf ./sub2xray.py pool --name main --size 20 sub.txt
#   systemctl restart xray
#
# and it deliberately refuses to overwrite an existing confdir, because that is
# where your pools and your hand-edited routing live.
set -euo pipefail

FORCE_UNITS=0
for a in "${@:-}"; do case "$a" in
  "") ;;
  --force-units) FORCE_UNITS=1 ;;
  *) echo "usage: $0 [--force-units]" >&2; exit 1 ;;
esac; done

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
cd "$(dirname "$(readlink -f "$0")")"

for t in xray nft ip; do
  command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }
done

# ⚠ Before the ruleset. nftables resolves `meta skuid xray` to a numeric uid at
# PARSE time, so a ruleset referencing a user that does not exist yet fails to
# load with "User does not exist" — and that rule is the one that stops xray
# capturing its own traffic.
if ! id -u xray >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin xray
  echo "created system user: xray"
fi

install -d -m 0755 /etc/xray
if [[ -d /etc/xray/conf && -n "$(ls -A /etc/xray/conf 2>/dev/null)" ]]; then
  echo "kept   /etc/xray/conf (already populated)"
else
  install -d -o xray -g xray -m 0750 /etc/xray/conf
  if [[ -d conf && -n "$(ls -A conf 2>/dev/null)" ]]; then
    cp conf/*.json /etc/xray/conf/
    chown -R xray:xray /etc/xray/conf
    echo "seeded /etc/xray/conf from ./conf"
  else
    echo "empty  /etc/xray/conf — generate it:"
    echo "         XRAY_CONFDIR=/etc/xray/conf $PWD/sub2xray.py init"
    echo "         XRAY_CONFDIR=/etc/xray/conf $PWD/sub2xray.py pool --name main <sub>"
  fi
fi

put() {   # put <src> <dst> — never clobber without --force-units
  if [[ -e "$2" && $FORCE_UNITS -eq 0 ]] && ! cmp -s "$1" "$2"; then
    echo "kept   $2 (differs; --force-units to overwrite)"
  else
    install -m 0644 "$1" "$2"; echo "wrote  $2"
  fi
}
put nftables.conf            /etc/nftables.conf
put systemd/xray.service     /usr/lib/systemd/system/xray.service
put systemd/nftables.service /usr/lib/systemd/system/nftables.service

systemctl daemon-reload

# Validate before enabling anything. Starting the capture with a config xray
# will not load is how a transparent proxy takes the whole host offline: the
# ruleset happily tproxies every packet at a port with nothing behind it.
if compgen -G "/etc/xray/conf/*.json" >/dev/null; then
  if xray -test -confdir /etc/xray/conf; then
    systemctl enable --now xray.service
    systemctl enable --now nftables.service   # PartOf=xray, so it follows it
    echo
    echo "up. check:  systemctl status xray nftables"
    echo "            journalctl -u xray -f"
  else
    echo
    echo "config did not pass -test; nothing was started." >&2
    echo "Fix /etc/xray/conf, then: systemctl enable --now xray nftables" >&2
    exit 1
  fi
else
  echo
  echo "no config yet, so nothing was started. Generate the confdir above, then:"
  echo "  systemctl enable --now xray nftables"
fi
