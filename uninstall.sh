#!/usr/bin/env bash
# uninstall - undo install.sh, and leave the network working.
#
#   sudo ./uninstall.sh           units, ruleset and routing. Keeps your config
#   sudo ./uninstall.sh --purge   ...and deletes the confdir, the published
#                                 list and the xray user
#   ./uninstall.sh --help
#   ./uninstall.sh selftest       stubs systemctl/nft/ip against a temp root
#
# ⚠ THE ORDER IS THE WHOLE POINT. The capture is two halves: an nftables table,
#   and a policy route that sends anything marked 1 to a table whose local
#   default route turns it back into prerouting. Delete the units while those
#   are still loaded and every marked packet is routed to lo with nothing
#   listening for it - the host loses its network, nothing logs a reason, and
#   the ExecStop that would have cleaned up has just been removed along with
#   its unit. So the teardown runs FIRST, does not rely on ExecStop having
#   worked, and is verified before a single file is deleted. If anything is
#   still loaded afterwards this stops with the units intact, because at that
#   point they are the only remaining way to clean up.
#
# ⚠ --purge deletes credentials, with no backup and no undo: pool files carry
#   uuids, passwords and reality keys, 05-wireguard.json carries the wireguard
#   SERVER key, and working.txt is the published node list. Without it, all of
#   that is left exactly where it is and only the system pieces are removed.
#
# The telegram container is not installed by install.sh and is not touched:
#   cd telegram && docker compose down -v
set -euo pipefail

# --help prints the header block above rather than a second copy of it, so the
# two cannot drift. Everything from line 2 down to `set -` is the help text.
case "${1:-}" in -h|--help)
  sed -n '2,/^set -/{/^set -/q; s/^#\( \|$\)//p}' "$0"; exit 0;;
esac

# Everything is addressed through this so the selftest can point the whole
# script at a temp directory. Empty in real use, which is the identity.
ROOT="${UNINSTALL_ROOT:-}"
UNITS="$ROOT/usr/lib/systemd/system"
CONF="$ROOT/etc/xray"
STATE="$ROOT/var/lib/xray"
LINK="$ROOT/usr/local/bin/xray-refresh"

PURGE=0; RUNTEST=0
for a in "$@"; do case "$a" in
  --purge)  PURGE=1 ;;
  selftest) RUNTEST=1 ;;
  *) echo "usage: $0 [--purge|selftest]   (--help for the rest)" >&2; exit 1 ;;
esac; done

say() { printf '%s\n' "$*"; }

teardown() {
  # disable --now covers both halves of "stop it and stop it coming back".
  # Failures are ignored throughout: a unit that was never installed, never
  # started or already failed is not a problem here, it is the goal.
  say "stopping services"
  systemctl disable --now xray-refresh.timer xray-refresh.service \
                          xray-nftables.service xray.service >/dev/null 2>&1 || true

  # ⚠ Not left to xray-nftables' ExecStop. That does not run if the unit was
  # already inactive, already failed, or was stopped by hand earlier - all of
  # which leave the table and the ip rule loaded with nothing to remove them.
  say "removing the capture"
  nft delete table ip xray 2>/dev/null || true
  # A loop, not one call: `ip rule del` removes ONE match, and a unit that was
  # restarted without its ExecStartPre firing can leave duplicates behind.
  while ip rule del fwmark 1 table 100 2>/dev/null; do :; done
  ip route del local default dev lo table 100 2>/dev/null || true
}

still_loaded() {
  local bad=0
  if nft list table ip xray >/dev/null 2>&1; then
    say "  STILL LOADED: nftables table ip xray"; bad=1
  fi
  if ip rule show 2>/dev/null | grep -q 'fwmark 0x1 '; then
    say "  STILL LOADED: ip rule fwmark 1"; bad=1
  fi
  if [[ -n "$(ip route show table 100 2>/dev/null)" ]]; then
    say "  STILL LOADED: route table 100"; bad=1
  fi
  return $bad
}

remove_files() {
  say "removing units and the launcher"
  rm -f "$UNITS/xray.service" "$UNITS/xray-nftables.service" \
        "$UNITS/xray-refresh.service" "$UNITS/xray-refresh.timer" "$LINK"
  rm -f "$ROOT/run/xray-refresh.lock"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed xray.service xray-nftables.service \
                         xray-refresh.service >/dev/null 2>&1 || true
}

purge() {
  say "deleting $CONF and $STATE"
  rm -rf "$CONF" "$STATE"
  # After the services are down, so nothing is running as it.
  userdel xray >/dev/null 2>&1 || true
  say "deleted the xray user"
}

# The selftest lives here rather than beside the script, like alive.sh's and
# sub2xray's. Body is unindented on purpose: it contains heredocs.
selftest() {
local SELF work; SELF=$(readlink -f "$0"); work=$(mktemp -d)
trap 'rm -rf "$work"' RETURN
mkdir -p "$work/bin"
export PATH="$work/bin:$PATH"
export CALLS="$work/calls"
ok() { echo "  ok - $1"; }
die() { echo "FAIL - $1" >&2; exit 1; }
at() { grep -n "$1" "$CALLS" | head -1 | cut -d: -f1; }

stub() { { echo '#!/usr/bin/env bash'; cat; } > "$work/bin/$1"; chmod +x "$work/bin/$1"; }
stub systemctl <<'EOF'
echo "systemctl $*" >> "$CALLS"
EOF
stub nft <<'EOF'
echo "nft $*" >> "$CALLS"
# STILL_LOADED makes `list` succeed, standing in for a teardown that did not
# take: the script must then refuse to remove the units.
[[ "${1:-}" == "list" && -z "${STILL_LOADED:-}" ]] && exit 1
exit 0
EOF
stub ip <<'EOF'
echo "ip $*" >> "$CALLS"
[[ "${1:-}" == "rule" && "${2:-}" == "del" ]] && exit 1   # nothing left to delete
[[ "${1:-}" == "route" && "${2:-}" == "show" ]] && exit 0 # prints nothing
[[ "${1:-}" == "rule" && "${2:-}" == "show" ]] && exit 0
exit 0
EOF
stub userdel <<'EOF'
echo "userdel $*" >> "$CALLS"
EOF

seed() {
  rm -rf "$work/root"; : > "$CALLS"
  mkdir -p "$work/root/usr/lib/systemd/system" "$work/root/usr/local/bin" \
           "$work/root/etc/xray/conf" "$work/root/var/lib/xray"
  touch "$work/root/usr/lib/systemd/system/xray.service" \
        "$work/root/usr/lib/systemd/system/xray-nftables.service" \
        "$work/root/usr/lib/systemd/system/xray-refresh.service" \
        "$work/root/usr/lib/systemd/system/xray-refresh.timer" \
        "$work/root/usr/local/bin/xray-refresh" \
        "$work/root/etc/xray/conf/50-pool-x-01.json" \
        "$work/root/var/lib/xray/working.txt"
}
run() { env UNINSTALL_ROOT="$work/root" "$SELF" "$@"; }

seed
out=$(run) || die "a plain uninstall exited non-zero: $out"
[[ ! -e "$work/root/usr/lib/systemd/system/xray.service" ]] || die "xray.service survived"
[[ ! -e "$work/root/usr/lib/systemd/system/xray-refresh.timer" ]] || die "the timer survived"
[[ ! -e "$work/root/usr/local/bin/xray-refresh" ]] || die "the launcher survived"
ok "units and the launcher are removed"

# ⚠ THE ORDER. Removing the units first would strip the ExecStop that is the
# only other thing able to unload the ruleset, leaving marked packets routed
# to lo with nothing listening and no way left to undo it.
(( $(at 'nft delete table') < $(at 'systemctl daemon-reload') )) \
  || die "the ruleset was removed after the units, not before: $(cat "$CALLS")"
grep -q 'ip rule del fwmark 1 table 100' "$CALLS" || die "the ip rule was never deleted"
grep -q 'ip route del local default dev lo table 100' "$CALLS" || die "table 100 was never deleted"
ok "the capture is torn down before anything is deleted"

[[ -f "$work/root/etc/xray/conf/50-pool-x-01.json" ]] || die "the confdir was deleted without --purge"
[[ -f "$work/root/var/lib/xray/working.txt" ]] || die "the published list was deleted without --purge"
grep -q userdel "$CALLS" && die "the user was removed without --purge"
grep -q 'kept ' <<<"$out" || die "it did not say what it kept: $out"
ok "credentials and config are kept unless --purge says otherwise"

seed
out=$(run --purge) || die "--purge exited non-zero: $out"
[[ ! -e "$work/root/etc/xray" ]] || die "--purge left the confdir"
[[ ! -e "$work/root/var/lib/xray" ]] || die "--purge left the published list"
grep -q 'userdel xray' "$CALLS" || die "--purge left the user"
ok "--purge deletes the confdir, the published list and the user"

# A teardown that did not take must stop the run WITH THE UNITS INTACT: their
# ExecStop is then the only remaining way to unload the ruleset.
seed
out=$(STILL_LOADED=1 run) && die "a failed teardown should exit non-zero"
grep -q 'STILL LOADED' <<<"$out" || die "it did not report what is still loaded: $out"
[[ -e "$work/root/usr/lib/systemd/system/xray-nftables.service" ]] \
  || die "it removed the unit whose ExecStop is the last way to clean up"
[[ -e "$work/root/usr/local/bin/xray-refresh" ]] || die "it removed the launcher anyway"
ok "a teardown that did not take stops with the units left in place"

# Unknown arguments must error, never be accepted and ignored.
seed
run --purgee >/dev/null 2>&1 && die "a mistyped flag was accepted"
[[ -e "$work/root/etc/xray/conf/50-pool-x-01.json" ]] || die "a rejected run still deleted"
ok "a mistyped flag errors instead of being silently dropped"

out=$("$SELF" --help)
grep -q -- '--purge ' <<<"$out" || die "--help did not print the usage block"
grep -q 'THE ORDER IS THE WHOLE POINT' <<<"$out" || die "--help stopped early"
grep -q 'set -euo' <<<"$out" && die "--help leaked past the header into the script"
ok "--help prints the header block, and only that"

echo "selftest ok"
}

(( ! RUNTEST )) || { selftest; exit 0; }

# Skipped when UNINSTALL_ROOT is set, which is the selftest: it addresses a
# temp directory and needs no privileges to do it.
[[ $EUID -eq 0 || -n "$ROOT" ]] || { echo "run as root: sudo $0" >&2; exit 1; }

teardown
if ! still_loaded; then
  say ""
  say "The capture is still loaded, so nothing was deleted - the units are the"
  say "only thing left that can unload it. Clear it by hand, then re-run:"
  say "    nft delete table ip xray"
  say "    ip rule del fwmark 1 table 100"
  say "    ip route del local default dev lo table 100"
  exit 1
fi
say "capture removed: no ip xray table, no fwmark rule, no table 100"

remove_files
(( ! PURGE )) || purge

say ""
if (( PURGE )); then
  say "done. Nothing of it is left."
else
  say "done. kept $CONF and $STATE - pool credentials, the wireguard server key"
  say "and the published node list. --purge deletes them."
fi
say "the telegram container is separate:  cd telegram && docker compose down -v"
