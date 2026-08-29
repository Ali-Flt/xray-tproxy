#!/usr/bin/env bash
# install - put the system pieces in place. Run once, as root.
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
# load with "User does not exist" - and that rule is the one that stops xray
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
    # domains.txt is config too, and -confdir ignores it for not being .json
    [[ -f conf/domains.txt ]] && cp conf/domains.txt /etc/xray/conf/
    chown -R xray:xray /etc/xray/conf
    echo "seeded /etc/xray/conf from ./conf"
  else
    echo "empty  /etc/xray/conf - generate it:"
    echo "         XRAY_CONFDIR=/etc/xray/conf $PWD/sub2xray.py init"
    echo "         XRAY_CONFDIR=/etc/xray/conf $PWD/sub2xray.py pool --name main <sub>"
  fi
fi

put() {   # put <src> <dst> - never clobber without --force-units
  if [[ -e "$2" && $FORCE_UNITS -eq 0 ]] && ! cmp -s "$1" "$2"; then
    echo "kept   $2 (differs; --force-units to overwrite)"
  else
    install -m 0644 "$1" "$2"; echo "wrote  $2"
  fi
}
# ⚠ Namespaced on purpose. A unit called nftables.service overwrites the one
# the distro's nftables package ships, and /etc/nftables.conf is that
# package's config file - installing over both means a package update
# silently reverts the capture, or its ruleset flushes ours.
put nftables.conf                 /etc/xray/nftables.conf
put systemd/xray.service          /usr/lib/systemd/system/xray.service
put systemd/xray-nftables.service /usr/lib/systemd/system/xray-nftables.service
put systemd/xray-refresh.service  /usr/lib/systemd/system/xray-refresh.service
put systemd/xray-refresh.timer    /usr/lib/systemd/system/xray-refresh.timer

# A symlink rather than a copy: refresh.sh calls alive.sh and sub2xray.py from
# its own directory, which `readlink -f` resolves back to this checkout even
# when it is started through the link. So the unit gets a fixed ExecStart and
# the repo stays the one place the scripts live - but it also has to stay where
# it is, or the link dangles.
ln -sfn "$PWD/refresh.sh" /usr/local/bin/xray-refresh
# Verified, not assumed: a dangling link fails at the next timer firing with an
# ENOENT naming a path that is plainly there, which is a poor way to find out.
if [[ -x /usr/local/bin/xray-refresh ]]; then
  echo "linked /usr/local/bin/xray-refresh -> $PWD/refresh.sh"
else
  echo "WARNING: /usr/local/bin/xray-refresh does not resolve to an executable" >&2
fi
install -d -m 0755 /var/lib/xray
if [[ ! -e /etc/xray/subscriptions.txt ]]; then
  install -m 0644 subscriptions.txt.example /etc/xray/subscriptions.txt
  echo "wrote  /etc/xray/subscriptions.txt (edit it, then: systemctl enable --now xray-refresh.timer)"
else
  echo "kept   /etc/xray/subscriptions.txt"
fi

systemctl daemon-reload

# Validate before enabling anything. Starting the capture with a config xray
# will not load is how a transparent proxy takes the whole host offline: the
# ruleset happily tproxies every packet at a port with nothing behind it.
if compgen -G "/etc/xray/conf/*.json" >/dev/null; then
  if xray -test -confdir /etc/xray/conf; then
    systemctl enable --now xray.service
    # Explicitly, and NOT because PartOf carries it: PartOf propagates stop and
    # restart, never start. Bringing up xray alone leaves the ruleset unloaded,
    # which fails silently - nothing is captured, everything goes out direct,
    # and no log says the proxy is not in the path.
    systemctl enable --now xray-nftables.service
    echo
    echo "up. check:  systemctl status xray xray-nftables"
    echo "            journalctl -u xray -f"
  else
    echo
    echo "config did not pass -test; nothing was started." >&2
    echo "Fix /etc/xray/conf, then: systemctl enable --now xray xray-nftables" >&2
    exit 1
  fi
else
  echo
  echo "no config yet, so nothing was started. Generate the confdir above, then:"
  echo "  systemctl enable --now xray xray-nftables"
fi
