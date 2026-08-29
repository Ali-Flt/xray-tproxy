#!/usr/bin/env bash
# alive - which nodes the running service says are dead, and delete them.
#
#   ./alive.sh                    report only
#   ./alive.sh --prune            delete the dead
#   ./alive.sh --prune && sub2xray.py export > working.txt   # the survivors
#   ./alive.sh --help
#   ./alive.sh selftest           stub journalctl; no service, no network
#   XRAY_CONFDIR=conf ./alive.sh
#   ALIVE_SINCE=-6h ./alive.sh    how far back to read; default -1h
#   ALIVE_UNIT=… ./alive.sh       default xray.service
#   ALIVE_SCOPE=--user ./alive.sh    default --system, matching the installed unit
#   ALIVE_MIN=5 ./alive.sh --prune   keep at least 5 alive, or refuse
#   ALIVE_KEEP_LOG=1 ./alive.sh      keep the log slice for diagnosis
#
# Reads `journalctl $ALIVE_SCOPE -u $ALIVE_UNIT --since $ALIVE_SINCE` and nothing
# else. The service already probes every node continuously, so no second xray is
# needed and the window widens with time rather than patience.
#
# ⚠ This works only while xray logs to STDOUT, which is what makes journald the
#   log. Setting log.access/log.error to file paths in 00-inbounds.json sends
#   the observatory's verdicts there instead, journalctl goes quiet, and every
#   run here reports a pool in which nothing has ever failed. That is the one
#   outcome this tool cannot tell apart from a broken grep, so it is called out
#   rather than left to read as good news.
#
# It greps two lines, which sit at different log levels:
#   [Warning] app/observatory/burst: error ping <dest> with <tag>: <err>   dead
#   [Debug]   app/observatory/burst: burst: checking <tag>                 probed
# At the default `warning` you get every death and no proof of life - enough to
# prune, not enough to claim a node answered. The summary says which it had.
# Raise it with: sub2xray.py init --force --loglevel debug
#
# ⚠ --prune DELETES. No revive, no archive: the subscriptions are the backup.
# ⚠ ALIVE_MIN (default 1) refuses a prune that would leave fewer than N. Set 0
#   to override. Everything failing at once is usually your uplink, not 300
#   unrelated servers.
# ⚠ The RUNNING service keeps its old config until restarted, so after a prune
#   the journal describes a pool that no longer matches the files on disk.
# ⚠ Never grep "the outbound X is dead" - that is the PLAIN observatory's
#   message; burstObservatory never emits it, so it reports a perfect pool.
set -euo pipefail

# --help prints the header block above rather than a second copy of it, so the
# two cannot drift. Everything from line 2 down to `set -` is the help text.
case "${1:-}" in -h|--help)
  sed -n '2,/^set -/{/^set -/q; s/^#\( \|$\)//p}' "$0"; exit 0;;
esac

CONFDIR="${XRAY_CONFDIR:-conf}"
MIN="${ALIVE_MIN:-1}"   # ponytail: 0 disables the guard; a bad run can then empty the pool
UNIT="${ALIVE_UNIT:-xray.service}"
# The installed unit is a system unit; --user is kept for a per-user setup.
SCOPE="${ALIVE_SCOPE:---system}"
SINCE="${ALIVE_SINCE:--1h}"
PRUNE=0; RUNTEST=0
# Rejected, not ignored: a dropped flag is silent, and that is the bug that made
# this tool look like it could not write.
for a in "$@"; do case "$a" in
  --prune)  PRUNE=1 ;;
  selftest) RUNTEST=1 ;;
  *) echo "usage: $0 [--prune|selftest]   (--help for the rest)" >&2; exit 1 ;;
esac; done
# The selftest lives here rather than beside the script, like wg-peer's and
# sub2xray's. Body is unindented on purpose: it contains heredocs.
selftest() {
local ALIVE=$0 work; work=$(mktemp -d); trap 'rm -rf "$work"' RETURN
mkdir -p "$work/bin" "$work/conf"
export PATH="$work/bin:$PATH" XRAY_CONFDIR="$work/conf"

# Real wording, from the dev's own service:
#   [Warning] app/observatory/burst: error ping https://… with prox-x: Head "…": context deadline exceeded
#   [Debug]   app/observatory/burst: burst: checking prox-x
W='vpn xray[1]: 2026/08/09 00:22:37.047795 [Warning] app/observatory/burst: error ping https://www.gstatic.com/generate_204 with prox-de-2: Head "https://www.gstatic.com/generate_204": context deadline exceeded (Client.Timeout exceeded while awaiting headers)'
D1='vpn xray[1]: 2026/08/09 00:22:31.000000 [Debug] app/observatory/burst: burst: checking prox-de-1'
D2='vpn xray[1]: 2026/08/09 00:22:32.000000 [Debug] app/observatory/burst: burst: checking prox-de-2'
D3='vpn xray[1]: 2026/08/09 00:22:33.000000 [Debug] app/observatory/burst: burst: checking prox-de-3'
journal() { { echo '#!/usr/bin/env bash'; printf 'echo %q\n' "$@"; } > "$work/bin/journalctl"
            chmod +x "$work/bin/journalctl"; }

reset_pool() {
  cat > "$work/conf/50-pool-de-1.json" <<'EOF'
{"outbounds":[
 {"tag":"prox-de-1","protocol":"vless","settings":{"vnext":[{"address":"1.1.1.1","port":443,"users":[{"id":"aaa"}]}]}},
 {"tag":"prox-de-2","protocol":"vless","settings":{"vnext":[{"address":"2.2.2.2","port":443,"users":[{"id":"bbb"}]}]}},
 {"tag":"prox-de-3","protocol":"vless","settings":{"vnext":[{"address":"3.3.3.3","port":443,"users":[{"id":"ccc"}]}]}}
]}
EOF
}
tags() { jq -cr '[.outbounds[].tag]' "$work/conf/50-pool-de-1.json"; }
ok() { echo "  ok - $1"; }
die() { echo "FAIL - $1" >&2; exit 1; }

# The default case: a service at warning logs failures and no coverage.
reset_pool; journal "$W"
out=$("$ALIVE" --prune)
[[ $(tags) == '["prox-de-1","prox-de-3"]' ]] || die "--prune did not delete the failing node: $(tags)"
ok "--prune deletes what the journal reported as failing"

grep -q '1 of 3 outbounds failed' <<<"$out" || die "dead count not reported: $out"
grep -q 'the other 2 were not reported failing' <<<"$out" \
  || die "a warning-level run claimed nodes answered: $out"
ok "a warning-level run reports deaths as measured and the rest as unconfirmed"

# With debug on, coverage is real and says so.
reset_pool; journal "$D1" "$D2" "$D3" "$W"
out=$("$ALIVE")
grep -q '2 answered' <<<"$out" || die "debug-level run did not confirm answers: $out"
[[ $(tags) == '["prox-de-1","prox-de-2","prox-de-3"]' ]] || die "report-only wrote to the pool"
ok "with debug lines present it confirms who answered - and no flag means no writes"

# A window that only reached part of the pool must not read as a verdict.
reset_pool; journal "$D1" "$D2" "$W"
out=$("$ALIVE")
grep -q 'only 2 of 3 were probed' <<<"$out" \
  || die "partial coverage was not reported as partial: $out"
ok "a partial window says so instead of reading as a verdict"

# The healthy case used to be the broken one: grep matched nothing, and set -e
# killed the script mid-assignment - no summary, no prune, exit 1.
reset_pool; journal "$D1" "$D2" "$D3"
out=$("$ALIVE" --prune)
grep -q 'nothing to prune' <<<"$out" || die "all-alive run never reached the prune block: $out"
grep -q '0 of 3 outbounds failed' <<<"$out" || die "all-alive run printed no summary: $out"
[[ $(tags) == '["prox-de-1","prox-de-2","prox-de-3"]' ]] || die "all-alive run changed the pool"
ok "a pool where nothing failed still reports, and prunes nothing"

# ALIVE_MIN guards the scheduled path, which a report-only dry run cannot.
reset_pool
journal "$W" "${W//prox-de-2/prox-de-1}" "${W//prox-de-2/prox-de-3}"
out=$("$ALIVE" --prune 2>/dev/null) && die "guard did not fire with no survivors"
grep -q 'REFUSED to prune' <<<"$out" || die "the refusal was not on stdout: $out"
[[ $(tags) == '["prox-de-1","prox-de-2","prox-de-3"]' ]] || die "guard fired but the pool was written"
ok "ALIVE_MIN refuses a prune that would leave nothing, and writes nothing"
ALIVE_MIN=0 "$ALIVE" --prune >/dev/null
[[ ! -f "$work/conf/50-pool-de-1.json" ]] || die "ALIVE_MIN=0 should have deleted the pool file"
ok "ALIVE_MIN=0 overrides it and deletes the empty pool file"

# Unknown arguments must error, never be accepted and ignored.
reset_pool; journal "$W"
"$ALIVE" --prunee >/dev/null 2>&1 && die "a mistyped flag was accepted"
[[ $(tags) == '["prox-de-1","prox-de-2","prox-de-3"]' ]] || die "a rejected run still wrote"
ok "a mistyped flag errors instead of being silently dropped"

# A window with no failures at all must say so - it is indistinguishable from a
# broken failure-grep, and that is exactly the state this tool sat in for a day.
reset_pool; journal 'vpn xray[1]: nothing useful here'
out=$("$ALIVE" 2>&1)
grep -q 'NOT ONE failure line matched' <<<"$out" || die "an empty window said nothing: $out"
ok "a window with no failures at all says so"

# REGRESSION: tags whose numbers prefix one another (prox-x-4 / -40 / -6) are
# sorted differently by `sort` (whole line) and `join` (field 1). join printed a
# partial list and exited 1, and pipefail killed the run before DEAD, before the
# prune and before the summary. This is the exact data shape that did it.
cat > "$work/conf/50-pool-de-1.json" <<'EOF'
{"outbounds":[
 {"tag":"prox-de-4","settings":{"vnext":[{"address":"1.1.1.1","port":443,"users":[{"id":"a"}]}]}},
 {"tag":"prox-de-40","settings":{"vnext":[{"address":"2.2.2.2","port":443,"users":[{"id":"b"}]}]}},
 {"tag":"prox-de-6","settings":{"vnext":[{"address":"3.3.3.3","port":443,"users":[{"id":"c"}]}]}},
 {"tag":"prox-de-7","settings":{"vnext":[{"address":"4.4.4.4","port":443,"users":[{"id":"d"}]}]}}
]}
EOF
journal "${W//prox-de-2/prox-de-40}" "${W//prox-de-2/prox-de-6}"
out=$("$ALIVE" --prune)
[[ $(tags) == '["prox-de-4","prox-de-7"]' ]] \
  || die "prefix-numbered tags broke the prune: $(tags)"
grep -q '2 of 4 outbounds failed' <<<"$out" || die "prefix-numbered tags broke the summary: $out"
grep -q 'prox-de-40' <<<"$out" || die "the DEAD list was truncated: $out"
ok "tags whose numbers prefix one another do not truncate the report or the prune"

# The journal names nodes that are no longer in the pool - pruned earlier, or
# hand-added in 60-manual.json. They used to print as "?" and take the counts
# negative: "19 of 2 outbounds failed ... the other -17".
reset_pool
journal "${W//prox-de-2/prox-gone-1}" "${W//prox-de-2/prox-manual-1}" "$W"
out=$("$ALIVE")
grep -q '?' <<<"$out" && die "a tag with no address still printed: $out"
grep -q 'note: 2 failing tag(s) not in' <<<"$out" || die "dropped tags were not reported: $out"
grep -q '1 of 3 outbounds failed' <<<"$out" || die "counts did not survive the filter: $out"
ok "tags no longer in the pool are dropped and counted, not printed as '?'"

# shadowsocks outbounds carry settings.servers[0], not vnext[0]. addr() reads
# both, but T6 asked for this confirmed rather than assumed.
cat > "$work/conf/50-pool-de-1.json" <<'EOF'
{"outbounds":[
 {"tag":"prox-de-1","protocol":"shadowsocks","settings":{"servers":[{"address":"ss.example","port":8388,"method":"aes-256-gcm","password":"p"}]}},
 {"tag":"prox-de-2","protocol":"vless","settings":{"vnext":[{"address":"2.2.2.2","port":443,"users":[{"id":"b"}]}]}}
]}
EOF
journal "${W//prox-de-2/prox-de-1}"
out=$("$ALIVE" --prune)
grep -q 'prox-de-1	ss.example' <<<"$out" || die "an ss node showed no address: $out"
[[ $(tags) == '["prox-de-2"]' ]] || die "an ss node could not be pruned: $(tags)"
ok "a shadowsocks outbound is reported with its address and can be pruned"

# REGRESSION: mktemp creates 0600 and mv puts the SOURCE's mode and owner on
# the destination, so a prune rewrote the pool file rw------- and xray, running
# as its own user, could not read its own config afterwards. Under sudo it
# changed the owner to root too. Nothing said so: the prune reported success
# and the service failed to load at the next restart.
reset_pool; chmod 644 "$work/conf/50-pool-de-1.json"; journal "$W"
"$ALIVE" --prune >/dev/null
[[ $(tags) == '["prox-de-1","prox-de-3"]' ]] || die "the mode test did not prune"
[[ "$(stat -c %a "$work/conf/50-pool-de-1.json")" == "644" ]] \
  || die "prune changed the pool file mode to $(stat -c %a "$work/conf/50-pool-de-1.json")"
reset_pool; chmod 640 "$work/conf/50-pool-de-1.json"; journal "$W"
"$ALIVE" --prune >/dev/null
[[ "$(stat -c %a "$work/conf/50-pool-de-1.json")" == "640" ]] \
  || die "prune did not preserve 640, got $(stat -c %a "$work/conf/50-pool-de-1.json")"
ok "a prune leaves the pool file's permissions exactly as it found them"

# --help is generated from the header comment, so it breaks silently if the
# sed range stops matching. Pin both ends of that range.
out=$("$ALIVE" --help)
grep -q -- '--prune ' <<<"$out" || die "--help did not print the usage block"
grep -q 'burstObservatory never emits it' <<<"$out" || die "--help stopped early"
if grep -q 'set -euo' <<<"$out"; then die "--help leaked past the header into the script"; fi
ok "--help prints the header block, and only that"

echo "selftest ok"
}

(( ! RUNTEST )) || { selftest; exit 0; }
command -v jq >/dev/null || { echo "jq not on PATH" >&2; exit 1; }
compgen -G "$CONFDIR/50-pool-*.json" >/dev/null || {
  echo "no pool files in $CONFDIR - run: sub2xray.py pool --name <name> <sub>" >&2; exit 1; }

# Counted before anything is deleted, or the denominator would describe the pool
# we just shrank rather than the one we read about.
total=$(jq -r '.outbounds[]?.tag' "$CONFDIR"/50-pool-*.json 2>/dev/null | sort -u | grep -c . || true)

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
journalctl "$SCOPE" -u "$UNIT" --since "$SINCE" --no-pager > "$work/probe.log" 2>&1 || true
[[ -z "${ALIVE_KEEP_LOG:-}" ]] || { cp "$work/probe.log" ./alive-probe.log
  echo "log slice kept at ./alive-probe.log" >&2; }

# || true on both: grep exits 1 when it matches nothing, and with `set -e` that
# killed the script mid-assignment. A pool where NOTHING failed is the healthy
# case and it died silently - no DEAD section, no summary, no prune, exit 1.
failed=$(grep -oE 'error ping .* with prox-[a-zA-Z0-9_-]+:' "$work/probe.log" \
         | grep -oE 'prox-[a-zA-Z0-9_-]+' | sort -u || true)
checked=$(grep -oE 'burst: checking prox-[a-zA-Z0-9_-]+' "$work/probe.log" \
          | awk '{print $3}' | sort -u || true)

pool_tags() { jq -r '.outbounds[]?.tag' "$CONFDIR"/50-pool-*.json 2>/dev/null \
              | grep '^prox-' | sort -u; }

# The journal outlives the config: nodes pruned an hour ago still appear in it,
# and hand-added outbounds (60-manual.json) were never in the pool glob at all.
# Both used to print with "?" for an address and drag the counts below zero -
# "19 of 2 outbounds failed ... the other -17". Only tags that are in the pool
# files can be reported against or pruned, so drop the rest and say how many.
in_pool=$(pool_tags)
stale=$(awk 'NR==FNR{p[$0];next} NF && !($0 in p)' <(echo "$in_pool") <(echo "$failed"))
failed=$(awk 'NR==FNR{p[$0];next} NF &&  ($0 in p)' <(echo "$in_pool") <(echo "$failed"))
[[ -z "$stale" ]] || printf 'note: %s failing tag(s) not in %s/50-pool-*.json - already pruned, or hand-added\n' \
  "$(grep -c . <<<"$stale")" "$CONFDIR"
coverage=observed
if [[ -z "$checked" ]]; then          # service is below debug: deaths, no proof of life
  checked=$(pool_tags); coverage=assumed
fi
[[ -n "$checked" ]] || {
  echo "nothing in $SINCE of $UNIT, and no prox-* outbounds to fall back on" >&2
  echo "Widen the window with ALIVE_SINCE=-6h, or check the unit name." >&2
  exit 1; }
# awk again rather than comm, for the same reason: comm also demands sorted
# input, and a set difference does not need one.
alive=$(awk 'NR==FNR{f[$0]; next} NF && !($0 in f)' <(echo "$failed") <(echo "$checked"))
n_checked=$(grep -c . <<<"$checked" || true)
n_failed=$(grep -c . <<<"$failed" || true)

# ⚠ A clean bill of health is also what a broken failure-grep looks like, and
# the two are indistinguishable from outside. Say so rather than let it stand.
(( n_failed > 0 )) || {
  echo "note: NOT ONE failure line matched in $SINCE." >&2
  echo "If you expect dead nodes, either the window is too short or the wording" >&2
  echo "differs - deadness is read from 'error ping ... with <tag>:' alone." >&2
  echo "Capture the evidence: ALIVE_KEEP_LOG=1 $0" >&2; }

# awk, not join. `join` needs both inputs sorted BY THE JOIN FIELD, while sort -u
# orders whole lines - with tags like prox-x-4 / prox-x-40 / prox-x-6 the two
# disagree, and join then prints a PARTIAL list and exits 1. Under pipefail that
# killed the script mid-report: no DEAD section, no prune, no summary, exit 1,
# and the `2>/dev/null` that used to be here hid the reason. awk needs no order.
addr() { jq -r '.outbounds[]? | "\(.tag)\t\(.settings.vnext[0].address // .settings.servers[0].address // "?")"' \
         "$CONFDIR"/50-pool-*.json 2>/dev/null; }
show() { [[ -n "$1" ]] || return 0
  echo "$2"
  awk -F'\t' 'NR==FNR{a[$1]=$2; next} NF{printf "  %s\t%s\n", $1, ($1 in a ? a[$1] : "?")}' \
    <(addr) <(echo "$1"); }

show "$alive"  "ALIVE"
show "$failed" "DEAD"

if [[ $PRUNE -eq 1 ]]; then
  # Refuse to leave fewer than ALIVE_MIN nodes. Everything failing usually means
  # the run was bad - your uplink, DNS, the probe destination - not that every
  # node died at once. Default 1 refuses only when nothing at all survives.
  # This guards the CRON path, which a dry run cannot: a scheduled run passes
  # --prune by definition and nobody reads its output. Raise MIN above 1 once
  # you know your normal survivor count, so a half-broken run is caught too.
  # ⚠ With fallbackTag: block, an empty pool is a silent total outage.
  n_ok=$(grep -c . <<<"${alive:-}" || true)
  if (( MIN > 0 && n_ok < MIN )) && [[ -n "$failed" ]]; then
    # stdout, not stderr: this is the answer to "what did it do", not an error.
    # On stderr it read as the script silently failing to write, twice.
    echo
    echo "  REFUSED to prune: $n_ok would be left, ALIVE_MIN is $MIN. Nothing changed."
    echo "  Everything failing at once is usually your uplink, DNS or the probe"
    echo "  destination - not every node dying together. If you meant it:"
    echo "      ALIVE_MIN=0 $0 --prune"
    exit 2
  fi
  echo
  if [[ -z "$failed" ]]; then
    echo "  nothing to prune"
  else
    # .prune.XXXXXX has no .json suffix, so -confdir never reads it mid-write,
    # and it is inside CONFDIR so the mv is atomic on the same filesystem.
    tags=$(jq -Rn '[inputs | select(length > 0)]' <<<"$failed")
    for f in "$CONFDIR"/50-pool-*.json; do
      tmp=$(mktemp "$CONFDIR/.prune.XXXXXX")
      # mktemp creates the file 0600, and mv carries the SOURCE's mode and
      # owner onto the destination rather than keeping the destination's. So a
      # prune rewrote every pool file it touched to rw------- root:root, and
      # xray - which runs as its own user - could no longer read its own
      # config. Put the original's metadata on the replacement before renaming.
      jq --argjson t "$tags" \
        '.outbounds |= map(select(.tag as $x | $t | index($x) | not))' \
        "$f" > "$tmp" \
        && chmod --reference="$f" "$tmp" \
        && { chown --reference="$f" "$tmp" 2>/dev/null || true; } \
        && mv "$tmp" "$f"
      # If pruning emptied the pool, remove the file entirely rather than
      # leaving a skeleton {"outbounds":[]}.  Keeps the config dir tidy and
      # prevents a silent zero-size outbound list from being loaded by xray.
      if jq -e '.outbounds | length == 0' "$f" >/dev/null 2>&1; then
        rm -f "$f"
      fi
    done
    echo "  deleted $n_failed node(s)"
    echo "  restart to apply: systemctl restart ${SCOPE#--system} $UNIT"
    # What is left in the pool files is the set that survived this prune, and
    # sub2xray owns the JSON-to-URI direction, so the export lives there rather
    # than being rebuilt in jq here.
    echo "  export the survivors:  sub2xray.py export > working.txt"
  fi
fi

echo
# The dead count is measured. The alive count is not, unless the service is at
# debug - at warning it logs failures and nothing else, so "alive" really means
# "never reported failing", and saying otherwise would be a claim we cannot back.
printf '%s of %s outbounds failed in %s\n' "$n_failed" "$total" "$SINCE"
if [[ $coverage == assumed ]]; then
  printf 'the other %s were not reported failing (loglevel debug to confirm they answered)\n' \
    "$(( total - n_failed ))"
else
  printf '%s answered%s\n' "$(grep -c . <<<"${alive:-}" || true)" \
    "$( (( n_checked < total )) && echo ", but only $n_checked of $total were probed - widen ALIVE_SINCE" || true)"
fi
