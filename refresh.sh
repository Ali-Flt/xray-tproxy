#!/usr/bin/env bash
# refresh - rebuild the pool from subscriptions, keep what answers, publish it.
#
#   ./refresh.sh                  one cycle, then exit
#   ./refresh.sh --help
#   ./refresh.sh selftest         stubs systemctl/curl/journalctl/xray; no service, no network
#
# Run it from cron as root, or - better on a box that already runs xray under
# systemd - from the timer, which logs to the journal and cannot overlap itself:
#
#   systemctl enable --now xray-refresh.timer
#   */30 * * * * /opt/xray-tproxy/refresh.sh >> /var/log/xray-refresh.log 2>&1
#
# The cycle:
#
#   1. fetch every subscription in $REFRESH_SUBS, one pool per line
#   2. xray -test, then restart xray and xray-nftables
#   3. prune whatever the observatory reports failing, restart, and repeat
#      until nothing has failed for $REFRESH_QUIET
#   4. export the survivors to $REFRESH_OUT, atomically
#
# Nothing is published unless step 3 settles. A list we already know is full of
# dead nodes is worse than yesterday's list, so a cycle that never goes quiet
# leaves $REFRESH_OUT alone and exits non-zero, where the timer or cron will
# show it as a failure instead of it passing silently.
#
#   REFRESH_SUBS=/etc/xray/subscriptions.txt   name and url per line
#   REFRESH_OUT=/var/lib/xray/working.txt      the published list
#   REFRESH_QUIET=300     seconds of no failures before the pool counts as settled
#   REFRESH_EVERY=30      seconds between checks
#   REFRESH_MAX=1800      give up after this long and publish nothing
#   REFRESH_LIMIT=150     nodes kept per subscription
#   REFRESH_SIZE=50       nodes per pool file
#   XRAY_CONFDIR=/etc/xray/conf
#   ALIVE_MIN=1           passed through to alive.sh; it refuses to leave fewer
#
# ⚠ $REFRESH_OUT is every surviving node's uuid or password in plain text, so it
#   is written 0600. Anything you forward it to is publishing those credentials.
#
# ⚠ The services are NOT stopped for the refresh. `pool` only writes files and
#   xray does not watch the confdir, so the host keeps its proxy until the
#   restart in step 2 - and pruning before a refresh would be dead work anyway,
#   because `pool` rewrites that pool's files wholesale a second later.
set -euo pipefail

# --help prints the header block above rather than a second copy of it, so the
# two cannot drift. Everything from line 2 down to `set -` is the help text.
case "${1:-}" in -h|--help)
  sed -n '2,/^set -/{/^set -/q; s/^#\( \|$\)//p}' "$0"; exit 0;;
esac

DIR="$(dirname "$(readlink -f "$0")")"
# cron hands over a PATH of /usr/bin:/bin, which has no nft and no systemctl.
# Appended rather than prepended, so a selftest's stub directory still wins.
export PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

CONFDIR="${XRAY_CONFDIR:-/etc/xray/conf}"
SUBS="${REFRESH_SUBS:-/etc/xray/subscriptions.txt}"
OUT="${REFRESH_OUT:-/var/lib/xray/working.txt}"
QUIET="${REFRESH_QUIET:-300}"
EVERY="${REFRESH_EVERY:-30}"
MAX="${REFRESH_MAX:-1800}"
LIMIT="${REFRESH_LIMIT:-150}"
SIZE="${REFRESH_SIZE:-50}"
CURL_TIMEOUT="${REFRESH_CURL_TIMEOUT:-60}"
LOCK="${REFRESH_LOCK:-/run/xray-refresh.lock}"
RUNTEST=0
for a in "$@"; do case "$a" in
  selftest) RUNTEST=1 ;;
  *) echo "usage: $0 [selftest]   (--help for the rest)" >&2; exit 1 ;;
esac; done

say() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }

pool_size() {
  jq -r '.outbounds[]?.tag' "$CONFDIR"/50-pool-*.json 2>/dev/null | grep -c . || true
}

restart_stack() {
  # ⚠ Validate BEFORE restarting. The ruleset happily tproxies every packet at
  # a port with nothing behind it, so bringing the capture up against a config
  # xray will not load takes the whole host off the network. install.sh guards
  # the first start the same way; this is the same gate on every later one.
  if ! xray -test -confdir "$CONFDIR" >/dev/null 2>&1; then
    say "xray -test FAILED against $CONFDIR - not restarting, nothing published"
    xray -test -confdir "$CONFDIR" >&2 || true
    return 1
  fi
  systemctl restart xray.service xray-nftables.service
  RESTARTED_AT=$(date +%s)
}

fetch_pools() {
  [[ -r "$SUBS" ]] || { say "no subscription list at $SUBS"; return 1; }
  local name url tmp n=0 ok=0
  while read -r name url _; do
    [[ -n "${name:-}" && "${name:0:1}" != "#" ]] || continue
    if [[ -z "${url:-}" ]]; then
      say "  $SUBS: '$name' has no url - skipped"; continue
    fi
    n=$((n + 1))
    tmp="$WORK/sub-$name"
    # -f so an HTTP error is a failure rather than an error page piped into the
    # parser, and </dev/null so curl cannot eat the loop's input.
    if ! curl -fsS --max-time "$CURL_TIMEOUT" "$url" -o "$tmp" </dev/null; then
      say "  $name: fetch failed - keeping the pool already on disk"; continue
    fi
    [[ -s "$tmp" ]] || { say "  $name: empty response - keeping the pool already on disk"; continue; }
    # A subscription that parses to nothing exits non-zero BEFORE write_pool,
    # so the pool on disk survives a bad fetch rather than being emptied by it.
    if "$DIR/sub2xray.py" --outdir "$CONFDIR" pool \
         --name "$name" --limit "$LIMIT" --size "$SIZE" "$tmp"; then
      ok=$((ok + 1))
    else
      say "  $name: no usable nodes - keeping the pool already on disk"
    fi
  done < "$SUBS"
  say "refreshed $ok of $n subscription(s), pool is now $(pool_size) node(s)"
  (( n > 0 )) || { say "$SUBS lists no subscriptions"; return 1; }
  # Not fatal: the pools already on disk are still worth pruning and publishing,
  # and nodes die between runs whether or not the subscription answered.
  (( ok > 0 )) || say "WARNING: every subscription failed - pruning what is already there"
}

settle() {
  # Prune, restart, repeat until the pool has been quiet for QUIET seconds.
  #
  # The window is "since the last restart", never a fixed -5m. A restart bursts
  # every probe at once, so the failures that matter arrive immediately after
  # it - while a fixed window would keep re-reading the failures of nodes that
  # were pruned two restarts ago and never go quiet.
  #
  # And a prune is always followed by a restart: the running service keeps its
  # old config, so without one it goes on dialling the nodes just deleted and
  # goes on logging them as failures, which reads as a pool that never settles.
  local deadline quiet_since now since before after rc out
  restart_stack || return 1
  quiet_since=$RESTARTED_AT
  deadline=$(( $(date +%s) + MAX ))
  while :; do
    sleep "$EVERY"
    now=$(date +%s)
    if (( now >= deadline )); then
      say "gave up after ${MAX}s with the pool still failing - nothing published"
      return 1
    fi
    since=$(( now - RESTARTED_AT ))
    before=$(pool_size)
    rc=0
    out=$(XRAY_CONFDIR="$CONFDIR" ALIVE_SINCE="-${since}s" "$DIR/alive.sh" --prune 2>&1) || rc=$?
    after=$(pool_size)
    if (( rc == 2 )); then
      # ALIVE_MIN fired: everything failed at once, which is nearly always the
      # uplink rather than every node dying together. Publishing the pool now
      # would publish a list we have just been told is entirely dead.
      say "alive.sh refused to prune (ALIVE_MIN); nothing published"
      printf '%s\n' "$out" | sed 's/^/    /'
      return 1
    fi
    if (( rc != 0 )); then
      say "alive.sh exited $rc"
      printf '%s\n' "$out" | sed 's/^/    /'
      return 1
    fi
    if (( after < before )); then
      say "  pruned $(( before - after )), $after left - restarting"
      restart_stack || return 1
      quiet_since=$RESTARTED_AT
    elif (( now - quiet_since >= QUIET )); then
      say "settled: $after node(s), nothing failing for ${QUIET}s"
      return 0
    fi
  done
}

publish() {
  local tmp
  install -d -m 0755 "$(dirname "$OUT")"
  # Same directory as the destination, so the rename is atomic on one
  # filesystem: whatever is watching $OUT never reads a half-written list.
  tmp=$(mktemp "$OUT.XXXXXX")
  if ! "$DIR/sub2xray.py" --outdir "$CONFDIR" export > "$tmp"; then
    rm -f "$tmp"; say "export produced nothing - $OUT left as it was"; return 1
  fi
  # ⚠ Every line is a credential.
  chmod 0600 "$tmp"
  mv "$tmp" "$OUT"
  say "published $(grep -c . "$OUT") node(s) to $OUT"
}

# The selftest lives here rather than beside the script, like alive.sh's and
# sub2xray's. Body is unindented on purpose: it contains heredocs.
selftest() {
local SELF=$DIR/refresh.sh work; work=$(mktemp -d); trap 'rm -rf "$work"' RETURN
mkdir -p "$work/bin" "$work/conf" "$work/out"
export PATH="$work/bin:$PATH"
ok() { echo "  ok - $1"; }
die() { echo "FAIL - $1" >&2; exit 1; }

stub() { { echo '#!/usr/bin/env bash'; cat; } > "$work/bin/$1"; chmod +x "$work/bin/$1"; }
stub systemctl <<EOF
echo "\$@" >> "$work/systemctl.calls"
EOF
stub xray <<'EOF'
[[ "${1:-}" == "-test" ]] && exit 0
exit 1
EOF
# Three nodes in, and the journal reports the second one failing. Once it has
# been pruned the tag is no longer in the pool, so alive.sh drops it as stale
# and every later check is quiet - which is what lets the loop settle.
stub curl <<'EOF'
out=""; while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && { out=$2; shift; }; shift; done
cat > "$out" <<'URIS'
vless://u1@a.example:443?security=tls&sni=a.example#one
vless://u2@b.example:443?security=tls&sni=b.example#two
vless://u3@c.example:443?security=tls&sni=c.example#three
URIS
EOF
stub journalctl <<'EOF'
echo 'vpn xray[1]: 2026/08/29 00:22:37.047795 [Warning] app/observatory/burst: error ping https://www.gstatic.com/generate_204 with prox-test-2: Head "https://www.gstatic.com/generate_204": context deadline exceeded'
EOF

printf 'test\thttps://example.invalid/sub.txt\n# a comment\n' > "$work/subs.txt"
"$DIR/sub2xray.py" --outdir "$work/conf" init >/dev/null 2>&1

run() { env REFRESH_NO_ROOT_CHECK=1 XRAY_CONFDIR="$work/conf" REFRESH_SUBS="$work/subs.txt" \
   REFRESH_OUT="$work/out/working.txt" REFRESH_QUIET=2 REFRESH_EVERY=1 \
   REFRESH_MAX=60 REFRESH_LOCK="$work/lock" "$SELF" "$@"; }

out=$(run) || die "a clean cycle exited non-zero: $out"
grep -q 'refreshed 1 of 1' <<<"$out" || die "the subscription was not pooled: $out"
grep -q 'pruned 1, 2 left' <<<"$out" || die "the failing node was not pruned: $out"
grep -q 'settled: 2' <<<"$out" || die "the loop never settled: $out"
ok "one cycle pools, prunes what the journal reported, and settles"

[[ $(grep -c . "$work/out/working.txt") == 2 ]] || die "published the wrong count"
grep -q 'a.example' "$work/out/working.txt" || die "the survivors were not published"
grep -q 'b.example' "$work/out/working.txt" && die "a pruned node was published"
[[ "$(stat -c %a "$work/out/working.txt")" == "600" ]] \
  || die "the published list is not 0600: $(stat -c %a "$work/out/working.txt")"
ok "the survivors are published 0600, and the pruned node is not among them"

# ⚠ A prune that is not followed by a restart leaves the service dialling the
# nodes it just deleted, so it goes on logging them and the pool never settles.
grep -c 'restart xray.service' "$work/systemctl.calls" | grep -qv '^0$' \
  || die "no restart was issued"
[[ $(grep -c 'restart xray.service' "$work/systemctl.calls") -ge 2 ]] \
  || die "the prune was not followed by its own restart: $(cat "$work/systemctl.calls")"
ok "every prune is followed by a restart, or the journal keeps reporting it"

# Two cycles must not run at once: they stop and start the same services and
# rewrite the same pool files.
# Held by a subshell rather than `flock <file> sleep`, whose child inherits the
# descriptor and goes on holding the lock after the flock process is killed.
( flock 9; sleep 3 ) 9>"$work/lock" &
sleep 0.3
before=$(wc -l < "$work/systemctl.calls")
out=$(run) || die "an overlapping run must exit 0, not fail"
grep -q 'already running' <<<"$out" || die "the lock did not hold: $out"
[[ $(wc -l < "$work/systemctl.calls") == "$before" ]] || die "it restarted anyway"
wait
ok "an overlapping run exits without touching the services"

# A config xray will not load must never reach a restart: the ruleset would
# tproxy every packet at a port with nothing behind it.
stub xray <<'EOF'
echo "config error" >&2; exit 1
EOF
before=$(wc -l < "$work/systemctl.calls")
out=$(run) && die "a failing xray -test should have failed the cycle"
grep -q 'xray -test FAILED' <<<"$out" || die "the -test failure was not reported: $out"
[[ $(wc -l < "$work/systemctl.calls") == "$before" ]] || die "it restarted anyway"
ok "a config that fails xray -test stops the cycle before any restart"

# ...and a cycle that does not settle must leave the previous list alone.
cp "$work/out/working.txt" "$work/out/expected"
stub xray <<'EOF'
[[ "${1:-}" == "-test" ]] && exit 0
exit 1
EOF
stub journalctl <<'EOF'
echo 'vpn xray[1]: [Warning] app/observatory/burst: error ping https://x with prox-test-1: boom'
echo 'vpn xray[1]: [Warning] app/observatory/burst: error ping https://x with prox-test-3: boom'
EOF
out=$(env REFRESH_NO_ROOT_CHECK=1 ALIVE_MIN=5 XRAY_CONFDIR="$work/conf" REFRESH_SUBS="$work/subs.txt" \
  REFRESH_OUT="$work/out/working.txt" REFRESH_QUIET=2 REFRESH_EVERY=1 \
  REFRESH_MAX=20 REFRESH_LOCK="$work/lock" "$SELF") && die "a refused prune should fail the cycle"
grep -q 'nothing published' <<<"$out" || die "it did not say the publish was skipped: $out"
cmp -s "$work/out/working.txt" "$work/out/expected" \
  || die "a cycle that did not settle overwrote the published list"
ok "a cycle that cannot settle leaves the last good list in place"

echo "selftest ok"
}

(( ! RUNTEST )) || { selftest; exit 0; }

# Skipped only by the selftest, which stubs every command that would need it.
# It bypasses a friendly message, not a permission: without real root the
# systemctl calls below fail on their own.
[[ $EUID -eq 0 || -n "${REFRESH_NO_ROOT_CHECK:-}" ]] || {
  echo "run as root: sudo $0" >&2; exit 1; }
for t in jq curl systemctl xray; do
  command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }
done

# One cycle at a time. A cycle can outlast its own interval - it waits for the
# pool to go quiet - and two of them would stop and start the same services and
# rewrite the same pool files underneath each other. Exit 0, not an error: the
# previous run is doing the work.
exec 9>"$LOCK"
flock -n 9 || { say "another refresh is already running - exiting"; exit 0; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
RESTARTED_AT=0

say "refresh starting, confdir $CONFDIR"
fetch_pools
settle
publish
