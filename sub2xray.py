#!/usr/bin/env python3
"""sub2xray: build an Xray confdir from subscriptions.

    python3 sub2xray.py init                          # once: inbounds + routing
    python3 sub2xray.py pool --name de --size 20 sub.txt
    curl -s "$SUBURL" | python3 sub2xray.py pool --name nl --size 20
    xray run -confdir conf
    python3 sub2xray.py export > working.txt   # the pool, back as URIs

Three commands because they have different lifecycles. `init` writes the config
you then hand-edit and rarely touch; `pool` rewrites node files every refresh.
Conflating them is how a subscription refresh silently reverts your routing.
`export` is the way back out, and owns no state of its own: it rebuilds each
URI from the outbound, so after `alive.sh --prune` it prints what survived.

This owns the secret-free half of the confdir. The wireguard inbound
(05-wireguard.json) belongs to wg-peer.sh, because only it can generate the
server key - Xray rejects an empty one, so there is no useful stub to write.

Input may be a base64 subscription blob or a plain list of vless://, vmess://,
trojan://, ss:// or hysteria2:// URIs. Anything else is counted and named on
stderr, never
dropped quietly - a subscription that silently halves is indistinguishable from
one full of dead nodes.
"""
import argparse
import base64
import io
import glob
import json
import os
import re
import sys
import uuid
from urllib.parse import urlparse, parse_qs, unquote, urlencode, quote

# The seed for domains.txt, used only when that file does not exist yet.
# The live list is the FILE, not this: edit $XRAY_CONFDIR/domains.txt and
# re-run `init --force`. Which destinations selective mode proxies, and
# which names resolve at the exit node, both come from it, so the two
# cannot disagree about what is proxied.
DOMAINS_HEADER = """\
# One matcher per line. Blank lines and # comments are ignored.
#
#   domain:example.com    the domain and its subdomains
#   full:example.com      that name exactly
#   geosite:netflix       a named set from the geosite data
#   keyword:exampl        substring match
#   regexp:^ex.*[.]com$   a regular expression
#
# In selective mode these are the destinations that exit through the pool, and
# the names that are resolved at the exit node rather than here. Edit, then
# apply with:  sub2xray.py init --force
#
# The list below is a starting point. Add what you need; a geosite set is
# usually a better answer than a page of hostnames, because it is maintained
# upstream and follows the service when it moves.
#
# WARNING: an unknown geosite: name is a HARD startup failure, not a warning
# like a mistyped prefix is. xray refuses to load the whole config and the
# service will not come up. Check a new one with:
#   xray -test -confdir <confdir>
#
"""

DEFAULT_DOMAINS = [
    # A starting point, not a curated list. Nine geosite sets rather than a
    # hundred hand-listed hostnames: each one is maintained upstream in the
    # geosite data and covers the domains that service actually uses today,
    # including the ones it moves to next month.
    "geosite:google",        # accounts, gstatic, googleapis, ggpht, gemini
    "geosite:youtube",       # and ytimg
    "geosite:telegram",
    "geosite:meta",          # instagram, facebook, whatsapp
    "geosite:openai",
    "geosite:netflix",
    "geosite:spotify",
    "geosite:reddit",
    "geosite:discord",
]

FWMARK = 2
SOCKOPT = {"mark": FWMARK}


TAG_PREFIX = "prox"      # the selector in ROUTING; kept in step below

# One confdir, shared with wg-peer.sh via the same env var and the same default.
# If these two ever disagree you get a config that looks fine and routes nothing,
# so wg-peer refuses to seed unless it finds ROUTING beside it.
CONFDIR = os.environ.get("XRAY_CONFDIR", "conf")   # ./conf, relative to cwd
# Retirement lived here: a .retired deny-list of identities, retagged dead-* so
# subjectSelector stopped matching them. Removed 2026-08-09. It was only needed
# because the live config was generated straight from the subscription with no
# quality gate - absence from a list was how a dead node was kept out. The
# health check is that gate now, so a deny-list has no job beside it. See
# alive.sh, which archives what it deletes.
INBOUNDS = "00-inbounds.json"    # sub2xray init
WIREGUARD = "05-wireguard.json"  # wg-peer - it holds the server key
ROUTING = "10-routing.json"      # sub2xray init
# An INPUT, not a generated file. `--force` regenerates the two above FROM
# this one and never rewrites it - otherwise the edit-then-apply flow would
# reset the very list it is applying. Not .json, because -confdir would then
# try to parse it as config.
DOMAINS = "domains.txt"          # yours to edit; seeded if missing


# What xray reads as a matcher rather than as a literal substring. An unknown
# prefix is NOT an error to xray: "geosit:x" is matched as the plain string
# "geosit:x", which nothing is ever equal to. A typo is therefore a rule that
# silently never fires, which is worth a word on stderr.
DOMAIN_PREFIXES = ("domain:", "geosite:", "full:", "regexp:", "keyword:", "ext:")


def ensure_domains(path):
    """Seed domains.txt if missing, then read it back. Never overwrites."""
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(DOMAINS_HEADER)
            f.write("".join(d + "\n" for d in DEFAULT_DOMAINS))
        print(f"wrote {path} (seeded - edit it, then: init --force)", file=sys.stderr)
    return read_domains(path)


def read_domains(path):
    """One matcher per line, order preserved, comments and duplicates dropped.

    `#` starts a comment only at the start of a line or after whitespace, so a
    regexp: entry that contains one survives.

    Deduping here rather than at the point of definition is what makes pasting
    safe: a list assembled by hand over time repeats itself, and whatever goes
    in, xray is handed each matcher once.
    """
    out, seen = [], set()
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = re.sub(r"(^|\s)#.*", "", line).strip()
            if not line:
                continue
            if ":" in line and not line.startswith(DOMAIN_PREFIXES):
                print(f"{path}:{n}: {line.split(':')[0]!r} is not a matcher xray "
                      f"knows, so this line will match nothing", file=sys.stderr)
            if line not in seen:
                seen.add(line)
                out.append(line)
    return out


def b64d(s):
    """Decode base64, tolerating missing padding and urlsafe alphabet."""
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")


def stream(net, security, sni, host, path, service, fp, pbk, sid):
    """Shared streamSettings - identical between vless and vmess."""
    ss = {"network": net, "security": security, "sockopt": dict(SOCKOPT)}
    if net == "ws":
        ss["wsSettings"] = {"path": path or "/", "headers": {"Host": host or sni}}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": service}
    elif net == "xhttp":
        # XHTTP (formerly HTTP transport): needs a path, defaults to /.
        # host is optional — if absent, serverName is used.
        ss["xhttpSettings"] = {
            "path": path or "/",
            "host": host or sni,
        }
    # tcp needs nothing extra
    if security == "tls":
        ss["tlsSettings"] = {"serverName": sni, "fingerprint": fp or "chrome"}
    elif security == "reality":
        ss["realitySettings"] = {
            "serverName": sni, "fingerprint": fp or "chrome",
            "publicKey": pbk, "shortId": sid,
        }
    return ss


def parse_vless(uri, tag):
    u = urlparse(uri)
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    sni = q.get("sni", u.hostname)
    # HTTP transport was removed and migrated to XHTTP. Convert type=http →
    # type=xhttp so the node survives. XHTTP needs a path (defaults to /).
    net = q.get("type", "tcp")
    if net == "http":
        net = "xhttp"
    if net not in ("tcp", "ws", "grpc", "xhttp", "kcp", "quic", "h2", "raw", "httpupgrade", "splithttp"):
        raise ValueError(f"vless unknown transport: {net!r}")
    # Legacy XTLS removed in Xray 5.x: security=xtls -> security=tls
    security = q.get("security", "none")
    if security == "xtls":
        security = "tls"
    # REALITY requires a public key; without it the node is broken
    if security == "reality" and not q.get("pbk"):
        raise ValueError("reality without public key (pbk)")
    out = {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": u.hostname, "port": u.port or 443,
            "users": [{"id": u.username, "encryption": q.get("encryption", "none"),
                       "flow": q.get("flow", "")}],
        }]},
        "streamSettings": stream(
            net, security, sni,
            q.get("host", ""), unquote(q.get("path", "/")),
            q.get("serviceName", ""), q.get("fp", ""),
            q.get("pbk", ""), q.get("sid", "")),
    }
    return out


def parse_trojan(uri, tag):
    # Manual parse: trojan passwords can contain +, /, @ which confuse
    # urlparse.  Strip scheme, then split fragment -> query -> userinfo@hostport.
    body = uri[9:]  # strip 'trojan://'
    body, _, frag = body.partition("#")
    body, _, query = body.partition("?")
    q = {k: v[0] for k, v in parse_qs(query).items()}
    at_idx = body.rfind("@")
    if at_idx == -1:
        # No password in this URI - xray will refuse it anyway
        raise ValueError("trojan without a password (no @ in URI)")
    password = unquote(body[:at_idx])
    hostport = body[at_idx + 1:].rstrip("/")
    host, _, port = hostport.rpartition(":")
    sni = q.get("sni", host)
    net = q.get("type", "tcp")
    if net == "http":
        net = "xhttp"
    if net not in ("tcp", "ws", "grpc", "xhttp", "kcp", "quic", "h2", "raw", "httpupgrade", "splithttp"):
        raise ValueError(f"trojan unknown transport: {net!r}")
    # Legacy XTLS removed in Xray 5.x: security=xtls -> security=tls
    # (XTLS is now xtls-rprx-vision flow with TLS, not a separate security mode)
    security = q.get("security", "tls")
    if security == "xtls":
        security = "tls"
    # REALITY requires a public key; without it the node is broken
    if security == "reality" and not q.get("pbk"):
        raise ValueError("reality without public key (pbk)")
    out = {
        "tag": tag,
        "protocol": "trojan",
        "settings": {"servers": [{
            "address": host, "port": int(port) if port else 443,
            "password": password,
        }]},
        "streamSettings": stream(
            net, security, sni,
            q.get("host", ""), unquote(q.get("path", "/")),
            q.get("serviceName", ""), q.get("fp", ""),
            q.get("pbk", ""), q.get("sid", "")),
    }
    return out


def parse_vmess(uri, tag):
    # The name lives inside the base64 as "ps", but some subscriptions append a
    # #fragment anyway. It is not part of the payload, and left on it the
    # decode fails with "Incorrect padding" and the node is lost.
    c = json.loads(b64d(uri[len("vmess://"):].split("#", 1)[0]))
    sni = c.get("sni") or c.get("host") or c.get("add")
    net = c.get("net", "tcp")
    if net == "http":
        net = "xhttp"
    if net not in ("tcp", "ws", "grpc", "xhttp", "kcp", "quic", "h2", "http", "splithttp", "raw", "httpupgrade", "mKCP", "reality"):
        raise ValueError(f"vmess unknown transport: {net!r}")
    security = "tls" if str(c.get("tls", "")) in ("tls", "true", "1") else "none"
    out = {
        "tag": tag,
        "protocol": "vmess",
        "settings": {"vnext": [{
            "address": c["add"], "port": int(c["port"]),
            "users": [{"id": c["id"], "alterId": int(c.get("aid", 0)),
                       "security": c.get("scy", "auto")}],
        }]},
        "streamSettings": stream(
            net, security, sni, c.get("host", ""), c.get("path", "/"),
            c.get("path", "") if net == "grpc" else "", c.get("fp", ""), "", ""),
    }
    return out


# What xray-core's shadowsocks outbound will actually accept. The legacy stream
# ciphers (aes-256-cfb, rc4-md5, ...) were removed upstream, so a node using one
# is unusable here however well it parses - refuse it by name rather than let
# xray fail the whole config later with "not a valid cipher".
SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}


def parse_ss(uri, tag):
    """ss:// in both shapes that appear in the wild.

    SIP002  ss://<b64url(method:password)>@host:port?...#name
            ss://method:password@host:port#name        (2022 ciphers, plain)
    legacy  ss://<b64(method:password@host:port)>#name

    The two are told apart by where the '@' is: in SIP002 it is in the URI, in
    the legacy form it is inside the base64. Anything with ?plugin= is refused -
    v2ray-plugin and friends are separate processes that xray cannot host.
    """
    body = uri[len("ss://"):]
    body = body.split("#", 1)[0]
    body, _, query = body.partition("?")
    if "plugin" in parse_qs(query):
        raise ValueError("ss plugin= is not supported by xray-core")
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:              # SIP002 encodes only the userinfo
            userinfo = b64d(userinfo)
    else:                                    # legacy: the whole body is base64
        userinfo, _, hostport = b64d(body).rpartition("@")
    method, _, password = userinfo.partition(":")
    host, _, port = hostport.rpartition(":")
    method = method.strip().lower()
    # Shadowsocks 2022 keys may be URL-encoded (%3A -> :, %2B -> +, etc.).
    # Xray's client splits on ':' to get the per-user keys, so keep colons.
    if method.startswith("2022-"):
        password = unquote(password)
    if method not in SS_METHODS:
        raise ValueError(f"ss method {method!r} is not in xray-core")
    if not host or not port.isdigit():
        raise ValueError(f"ss address {hostport!r} is not host:port")
    return {
        "tag": tag,
        "protocol": "shadowsocks",
        "settings": {"servers": [{
            "address": host.strip("[]"),     # IPv6 arrives bracketed; xray wants it bare
            "port": int(port), "method": method, "password": password,
        }]},
        # sockopt ONLY. Plain shadowsocks is raw TCP: network and security are
        # left unset so xray keeps its defaults (raw/none) - naming a security
        # here would make it negotiate TLS and every ss node would fail. But the
        # block cannot be omitted altogether, which is what it used to be: with
        # no streamSettings there is no fwmark, so every ss dial was caught by
        # the tproxy inbound and dispatched a second time. Most public pools are
        # majority shadowsocks, so that was most of the pool looping.
        "streamSettings": {"sockopt": dict(SOCKOPT)},
    }


def parse_hysteria2(uri, tag):
    """hysteria2://password@host:port?sni=…&insecure=…#name

    Xray 26.3.27 registers this as protocol "hysteria" with version 2 - there
    is no "hysteria2" config id, which is why it read as unsupported until the
    dev's own binary was checked. Settings are flat: address, port, password.

    ⚠ Validate before emitting. A hysteria outbound with a missing address does
    not fail -test, it PANICS xray on load - so one malformed subscription entry
    would take the service down rather than being rejected. Verified against
    26.3.27.
    """
    u = urlparse(uri)
    host, port = u.hostname, u.port or 443
    if not host:
        raise ValueError("hysteria2 without a host would panic xray on load")
    if not 0 < port < 65536:
        raise ValueError(f"hysteria2 port {port} out of range")
    return {
        "tag": tag,
        "protocol": "hysteria",
        "settings": {"version": 2, "address": host, "port": port,
                     "password": unquote(u.username or "")},
        # Same reason as shadowsocks: no streamSettings meant no fwmark.
        # streamSettings is parsed by the generic StreamConfig for every
        # protocol before the transport ever sees it, so naming sockopt here
        # cannot fail to load whatever hysteria does with it afterwards.
        # ⚠ Whether its QUIC dialer HONOURS the mark is not something this repo
        # verifies - it opens its own socket. That is why nftables also skips
        # xray's uid: the mark is the belt, the uid rule is the braces, and for
        # a protocol like this one only the braces are load-bearing.
        "streamSettings": {"sockopt": dict(SOCKOPT)},
    }


def parse(uri, tag):
    if uri.startswith("vless://"):
        return parse_vless(uri, tag)
    if uri.startswith("vmess://"):
        return parse_vmess(uri, tag)
    if uri.startswith("trojan://"):
        return parse_trojan(uri, tag)
    if uri.startswith("ss://"):
        return parse_ss(uri, tag)
    if uri.startswith(("hysteria2://", "hy2://")):
        return parse_hysteria2(uri, tag)
    if uri.startswith(("hysteria://", "hy://")):
        # Not "unsupported": xray HAS a hysteria outbound, it just refuses
        # anything but version 2 - "version != 2". v1 is dead upstream anyway.
        raise ValueError("hysteria v1: xray's hysteria outbound only speaks version 2")
    return None  # anything else: no such outbound in xray-core


def _hostport(address, port):
    """host:port, re-bracketing an IPv6 literal that was stored bare."""
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def _stream_query(ss):
    """streamSettings back into the query parameters parse() reads them from."""
    q = {}
    net = ss.get("network", "tcp")
    if net != "tcp":
        q["type"] = net
    if net == "ws":
        w = ss.get("wsSettings", {})
        q["path"] = w.get("path", "/")
        host = w.get("headers", {}).get("Host", "")
        if host:
            q["host"] = host
    elif net == "grpc":
        q["serviceName"] = ss.get("grpcSettings", {}).get("serviceName", "")
    elif net == "xhttp":
        x = ss.get("xhttpSettings", {})
        q["path"] = x.get("path", "/")
        if x.get("host"):
            q["host"] = x["host"]
    tls = ss.get("tlsSettings") or ss.get("realitySettings") or {}
    for key, field in (("sni", "serverName"), ("fp", "fingerprint"),
                       ("pbk", "publicKey"), ("sid", "shortId")):
        if tls.get(field):
            q[key] = tls[field]
    return q


def to_uri(ob):
    """The inverse of parse(): one outbound back to the URI it came from.

    Nothing keeps the original URI list - a subscription is refetched, not
    stored - so the pool files are the only record of a node, and exporting
    means rebuilding the URI from what xray is actually configured with. That
    is exact for everything that reaches xray, and drops exactly what parse()
    dropped on the way in:

      - the node's display name. The tag stands in for it, which is more
        useful anyway: it names the pool the node came from.
      - hysteria2's sni= and insecure=. parse_hysteria2 does not keep them, so
        they are not in this config either; a URI carrying them would be
        claiming more than xray was told.

    Returns None for an outbound with no URI form (direct, block, dns-out),
    so that a hand-added file in the confdir cannot break an export.
    """
    proto, tag = ob.get("protocol"), ob.get("tag", "")
    st, ss = ob.get("settings", {}), ob.get("streamSettings", {})
    frag = "#" + quote(tag, safe="") if tag else ""
    if proto == "vless":
        v = st["vnext"][0]
        user = v["users"][0]
        q = _stream_query(ss)
        # vless defaults to security=none, so it is omitted when it is that
        if ss.get("security", "none") != "none":
            q["security"] = ss["security"]
        if user.get("encryption", "none") != "none":
            q["encryption"] = user["encryption"]
        if user.get("flow"):
            q["flow"] = user["flow"]
        return (f"vless://{quote(user['id'], safe='')}@"
                f"{_hostport(v['address'], v['port'])}?{urlencode(q)}{frag}")
    if proto == "trojan":
        srv = st["servers"][0]
        q = _stream_query(ss)
        # ...trojan defaults to tls, so security is always explicit here: an
        # omitted one would be read back as tls whatever it actually is.
        q["security"] = ss.get("security", "tls")
        return (f"trojan://{quote(srv['password'], safe='')}@"
                f"{_hostport(srv['address'], srv['port'])}?{urlencode(q)}{frag}")
    if proto == "vmess":
        v = st["vnext"][0]
        user = v["users"][0]
        net = ss.get("network", "tcp")
        q = _stream_query(ss)
        conf = {
            "v": "2", "ps": tag, "add": v["address"], "port": str(v["port"]),
            "id": user["id"], "aid": str(user.get("alterId", 0)),
            "scy": user.get("security", "auto"), "net": net,
            "host": q.get("host", ""),
            # grpc has no path: parse_vmess reads the service name out of it
            "path": (ss.get("grpcSettings", {}).get("serviceName", "")
                     if net == "grpc" else q.get("path", "")),
            "tls": "tls" if ss.get("security") == "tls" else "",
            "sni": q.get("sni", ""), "fp": q.get("fp", ""),
        }
        return "vmess://" + base64.b64encode(
            json.dumps(conf).encode()).decode()
    if proto == "shadowsocks":
        srv = st["servers"][0]
        method, password = srv["method"], srv["password"]
        if method.startswith("2022-"):
            # 2022 keys are base64 already and the spec keeps them in the
            # clear; base64ing the pair again is the shape clients get wrong.
            userinfo = f"{method}:{quote(password, safe='')}"
        else:
            userinfo = base64.urlsafe_b64encode(
                f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{_hostport(srv['address'], srv['port'])}{frag}"
    if proto == "hysteria":
        return (f"hysteria2://{quote(st.get('password', ''), safe='')}@"
                f"{_hostport(st['address'], st['port'])}{frag}")
    return None


def _where(uri):
    """host:port for a skip message, without trusting the URI to be parseable."""
    try:
        u = urlparse(uri)
        if u.hostname:
            return f"{u.hostname}:{u.port or '?'}"
    except ValueError:
        pass
    return uri[:48]


def build(raw, pool):
    """One pool file: outbounds only, all tagged <TAG_PREFIX>-<pool>-<n>.

    The pool name is in every tag because -confdir merges files by tag, and a
    tag appearing in two files is *silently overwritten* - no error, one node
    quietly gone. The namespace is what makes pool files independent.
    """
    # Input is either base64 of the URI list, or the URIs already.
    text = raw if "://" in raw else b64d(raw)
    outbounds, skipped, seen, dupes = [], {}, set(), 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        scheme = line.split("://", 1)[0] if "://" in line else "(not a URI)"
        try:
            ob = parse(line, "")
        except Exception as e:            # one bad node must not kill the batch
            skipped.setdefault(scheme, []).append(f"{_where(line)} - {e}")
            continue
        if ob:
            # Before --limit, which is applied by the caller: a subscription
            # that repeats itself would otherwise spend the budget on clones,
            # and the observatory would probe one server as though it were six.
            ident = config_id(ob)
            if ident in seen:
                dupes += 1
                continue
            seen.add(ident)
            ob["tag"] = f"{TAG_PREFIX}-{pool}-{len(outbounds) + 1}"
            outbounds.append(ob)
        else:
            skipped.setdefault(scheme, []).append(
                f"{_where(line)} - no {scheme} outbound exists in xray-core")
    # Counted AND named. A subscription that quietly halves looks exactly like
    # one full of dead nodes, and the alive-count would then be measured against
    # a pool that lost members without saying so.
    for scheme, why in sorted(skipped.items()):
        print(f"skipped {len(why)} {scheme} node(s):", file=sys.stderr)
        for w in why:
            print(f"  {w}", file=sys.stderr)
    if dupes:
        # Counted, not named, and that is not the inconsistency it looks like:
        # a skip is a node you asked for and cannot have, which is worth a name
        # and a reason. A duplicate is the same node twice - nothing is lost,
        # so the count is the whole of the information.
        print(f"deduped {dupes} repeated node(s); {len(outbounds)} distinct",
              file=sys.stderr)
    if not outbounds:
        sys.exit("no vless/vmess/trojan/ss nodes found in input")
    return {"outbounds": outbounds}


def node_id(ob):
    """Identity that survives a subscription refetch: where it goes, and as whom.

    Tags cannot be used for this - they are positional, so one node appearing or
    disappearing upstream renumbers everything after it.
    """
    st = ob["settings"]
    if "vnext" in st:                     # vless, vmess
        v = st["vnext"][0]
        secret = v["users"][0].get("id", "")
    elif "servers" in st:                 # trojan, shadowsocks
        v = st["servers"][0]
        secret = v.get("password", "")
    else:                                 # hysteria: settings are flat
        v = st
        secret = st.get("password", "")
    return f"{v['address']}:{v['port']}:{secret}"


def config_id(ob):
    """The whole outbound bar its tag: what dedupe keys on.

    NOT node_id, deliberately. Two entries can name the same server and the
    same credential and still be different configurations - one host offered
    over ws and over grpc, or under two SNIs - and only one of the two may
    actually work. Measured against a 1033-entry subscription: 56 entries were
    exact repeats of another, and a further 51 were the same server under a
    different configuration. Keying on node_id would have discarded those 51
    before the observatory ever got to find out which of them answered.
    """
    return json.dumps({k: v for k, v in ob.items() if k != "tag"}, sort_keys=True)


def inbounds_conf(tproxy_port, proxy_listen, proxy_port, vless, vless_id,
                  loglevel, access_log):
    """The tproxy door, plus an ordinary proxy port for things that ask for one.

    `all-in` is the transparent one: nftables tproxies every captured packet at
    it, so it sees the real destination address rather than a CONNECT request.
    `local_proxy` is for callers that cannot be captured - a container on a
    bridge the ruleset does not cover, or an app you would rather point at a
    proxy explicitly.

    ⚠ It listens on 0.0.0.0 by default and is `auth: noauth`, which is an open
    proxy to anything that can route to this host. That is a deliberate choice
    for a LAN gateway and a trust boundary you own: firewall the port, or pass
    --proxy-listen a narrower address. nftables also has to leave that port
    alone, or a connection to it arriving on a public interface is tproxy'd
    into the transparent door instead of reaching it - see KEEP_DIRECT_PORTS.

    Sniffing is on so routing rules can match domains; without it a rule sees
    only the IP, and every domain rule in 10-routing.json is dead weight.

    ⚠ Logging goes to stdout, NOT to /var/log/xray/*.log. Under systemd stdout
    is journald, which is where alive.sh reads the observatory's verdicts from.
    Point `log.access`/`log.error` at files and journalctl goes quiet, so
    alive.sh reports a pool where nothing ever failed - the one state it warns
    about because it is indistinguishable from a broken grep.
    """
    sniff = {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": False}
    inbounds = [
        {
            "tag": "all-in",
            "port": tproxy_port,
            "protocol": "dokodemo-door",
            "settings": {"followRedirect": True, "network": "tcp,udp"},
            "sniffing": sniff,
            "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
        },
        {
            "tag": "local_proxy",
            "listen": proxy_listen,
            "port": proxy_port,
            "protocol": "mixed",          # socks and http on one port
            "settings": {"allowTransparent": False, "auth": "noauth", "udp": True},
            "sniffing": sniff,
        },
    ]
    if vless:
        # Opt-in, and generated rather than shipped: a literal uuid in a config
        # template is a credential everybody who cloned the repo shares, on an
        # inbound reachable from the network by definition. Generated ONCE
        # though, see read_vless_id. Rolling it on every init would leave the
        # inbound up and listening while every client that already holds the old
        # one is quietly refused.
        listen, _, port = vless.rpartition(":")
        inbounds.append({
            "tag": "inbound-external",
            "listen": listen or "0.0.0.0",
            "port": int(port),
            "protocol": "vless",
            "settings": {
                "clients": [{"id": vless_id, "email": "peer", "flow": ""}],
                "decryption": "none",
            },
            "sniffing": sniff,
            "streamSettings": {"network": "tcp", "security": "none"},
        })
    # Two independent logs, and only one of them is what `loglevel` controls.
    #
    #   error   levelled by `loglevel`. Carries the observatory verdicts, which
    #           is the whole of what alive.sh reads.
    #   access  one line per connection, plus one per DNS cache hit. NOT
    #           levelled: `loglevel: error` does not quiet it by a single line.
    #           Unset it defaults to stdout, so under systemd the entire stream
    #           lands in journald. "none" is what turns it off, and off is the
    #           default here because nothing in this repo reads it.
    #
    # dnsLog is left unset, which is off. Turning it on adds a line per lookup
    # per server, and with a serial-query list that is four lines a name.
    return {"log": {"loglevel": loglevel, "access": access_log},
            "inbounds": inbounds}


def dns_conf(mode, domains):
    """Split DNS: the proxied set resolves at the exit node, the rest resolves here.

    A DNS server's `tag` becomes the INBOUND tag of the queries that server
    emits, and that is the whole mechanism - it is how a routing rule gets to
    say where a lookup travels, as opposed to where it is sent:

      dns-proxied  → the balancer.
      dns-direct   → direct.

    In selective mode the proxied server is scoped to the domain list, so one
    list decides what is proxied and where its names are resolved; the two
    cannot drift. In full mode it is unscoped, because everything is proxied.

    ⚠ The rules that read these tags need `"type": "field"`. Without it the rule
    is not a field rule and never matches, which is a silent no-op: the tag
    looks wired up and the queries go out the catch-all.

    Resolving at the exit is not only about poisoning. It is where the answer
    should come from: resolve a CDN name here and you get the IP that is optimal
    for *here*, then reach it down a tunnel that surfaces somewhere else.

    ⚠ DoH on BOTH, and that is what makes the fallback safe rather than a hole.
    If the proxied lookup cannot complete - the window after a restart, before
    the observatory has probed anyone and while fallbackTag is blackholing -
    xray falls through to the next server. Falling through to a plaintext
    resolver is how a censored name gets a forged answer that is then CACHED,
    and afterwards even a working node dials 10.10.34.36. Falling through to
    another DoH server costs a geographically wrong answer and nothing else, so
    the fallback is left ON: refusing to resolve at all would deadlock the pool
    it is waiting for.

    ⚠ Never udp:// or tcp://. On a network that injects answers a plain resolver
    is not a resolver, and "use a public one" is not the fix - 8.8.4.4 returned
    the block address too, because the injection happens in transit rather than
    at the server. Over HTTPS a forged answer fails the certificate check. tcp://
    has a second problem: the stream is framed by a 2-byte length prefix, so
    anything answering port 53 with something else corrupts it beyond recovery -
    an HTTP reply reads as an 18516-byte message ('H','T').

    queryStrategy UseIPv4 because every name was otherwise asked twice and the
    AAAA half came back empty, then got retried against every server in turn.
    """
    proxied = {"address": "https://1.1.1.1/dns-query", "tag": "dns-proxied"}
    if mode == "selective":
        proxied["domains"] = domains
    return {
        "queryStrategy": "UseIPv4",
        "servers": [proxied, {"address": "https://8.8.8.8/dns-query",
                              "tag": "dns-direct"}],
    }


def routing_conf(probe_interval, mode, domains):
    """The one observatory. Xray allows exactly one, and it cannot be nested.

    burstObservatory, not the plain one. The plain observatory sleeps
    probeInterval *between each outbound*, so its interval is a per-node delay
    rather than a round period: measured at 4 of 50 nodes reached in 40s at
    10s, which at 3m over 200 nodes is a ~10 hour round. burst probes
    concurrently, so interval means what it looks like it means.

    Declare only one of the two. Both present and leastLoad silently degrades.

    mode="full"       everything exits through the pool; direct is the exception.
    mode="selective"  the domain list exits through the pool; direct otherwise.

    These were the two config*.json.example files in the tproxy repo. They are
    one flag now, because they only ever differed in the last few rules and
    keeping two whole configs in step by hand is how one of them rots.
    """
    proxy_rules = (
        [{"type": "field", "network": "tcp,udp", "balancerTag": "lb"}]
        if mode == "full" else
        [
            {"type": "field", "ip": ["geoip:telegram"], "balancerTag": "lb"},
            {"type": "field", "domain": domains, "balancerTag": "lb"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ]
    )
    return {
        "dns": dns_conf(mode, domains),
        "outbounds": [
            # Every one of these carries the fwmark. `direct` without it is an
            # instant loop: the packet leaves, the OUTPUT chain marks it 1, and
            # the ip rule sends it back to the tproxy inbound that emitted it.
            {"tag": "direct", "protocol": "freedom",
             "settings": {"domainStrategy": "UseIPv4"},
             "streamSettings": {"sockopt": dict(SOCKOPT)}},
            {"tag": "block", "protocol": "blackhole",
             "settings": {"response": {"type": "http"}}},
            # No `settings.address`: with one, this outbound answers A/AAAA out
            # of the DNS module and forwards the rest to that address. The
            # module's own upstream queries are what we are trying to keep away
            # from here, so it is left to hand every query back to the module
            # and let the dns-proxied/dns-direct rules decide how it travels.
            {"tag": "dns-out", "protocol": "dns",
             "streamSettings": {"sockopt": dict(SOCKOPT)}},
        ],
        "burstObservatory": {
            "subjectSelector": [TAG_PREFIX],
            "pingConfig": {
                "destination": "https://www.gstatic.com/generate_204",
                "interval": probe_interval,
                # window, not rate: probe rate stays nodes/interval either way.
                # 3 samples ride out one unlucky timeout without going dead.
                "sampling": 3,
                "timeout": "5s",
            },
        },
        "routing": {
            # fallbackTag fires when the strategy can pick nobody - notably the
            # window after a restart, before the first probe round lands. Without
            # it, balancerTag rules fall through and every connection piles onto
            # the FIRST outbound, whichever node that happens to be. Blackholing
            # instead fails fast and visibly rather than timing out against one
            # arbitrary node for a minute. It is also why dns-direct exists.
            "balancers": [{"tag": "lb", "selector": [TAG_PREFIX],
                           "fallbackTag": "block",
                           "strategy": {"type": "leastPing"}}],
            # AsIs, not IPIfNonMatch. Under tproxy the destination IP is already
            # on the packet, so ip/geoip rules match without help; IPIfNonMatch
            # only adds a forward lookup per connection whose answer then gets a
            # vote on where the connection goes.
            "domainStrategy": "AsIs",
            # Order matters and is why these live in one file: first match wins.
            "rules": [
                # FIRST, and they must stay first: traffic the DNS module itself
                # emits. Below the port-53 rule a resolver's own query matches
                # that rule and is handed back to dns-out - the module then
                # answers its own upstream lookups out of its own cache, which
                # reads in the log as an endless "cache HIT ... empty response".
                {"type": "field", "inboundTag": ["dns-proxied"], "balancerTag": "lb"},
                {"type": "field", "inboundTag": ["dns-direct"], "outboundTag": "direct"},
                # client DNS, intercepted and re-asked by the module. udp only:
                # matching tcp/53 here would loop for the same reason.
                {"type": "field", "network": "udp", "port": "53",
                 "outboundTag": "dns-out"},
                # The LAN, the host and the docker bridges. nftables returns on
                # these too, but a packet that arrives some other way (the mixed
                # inbound, a container pointed at it explicitly) never touches
                # that ruleset.
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                # Torrents stay off the pool. They are free public nodes shared
                # by strangers; a swarm opens hundreds of connections a second
                # and would be both useless over them and abusive to them.
                # Needs the sniffer, which is why sniffing is on.
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:category-ads-all"],
                 "outboundTag": "block"},
                # QUIC has no way through these proxies; blocking it makes
                # browsers fall back to TCP TLS, which they can carry. It has to
                # sit above the proxy rules - below them, the proxied domains
                # are exactly the QUIC-heavy ones and their udp/443 would be
                # handed to a balancer that cannot carry it.
                {"type": "field", "network": "udp", "port": "443",
                 "outboundTag": "block"},
            ] + proxy_rules,
        },
    }


# Above this many nodes the observatory's load is worth saying out loud. Not a
# limit: a pool grows one subscription at a time and the cost of it is invisible
# until the balancer stops converging, which looks like bad nodes rather than
# too many of them.
PROBE_BUDGET = 200


def interval_seconds(text):
    """'3m' -> 180. Only needed to do arithmetic on what xray was given."""
    try:
        return int(text[:-1]) * {"s": 1, "m": 60, "h": 3600}[text[-1]]
    except (ValueError, KeyError, IndexError):
        return None


def probe_load_note(outdir):
    """Say what the observatory has just been signed up for.

    burstObservatory probes every subject CONCURRENTLY each round and has no
    backoff, so a node that has been dead for a week is still dialled every
    interval. Nothing in xray reports the resulting rate, and the failure mode
    is indirect: probes start timing out under their own weight, leastPing
    never gets a clean round, and the balancer looks like it is full of bad
    nodes rather than too many of them.
    """
    tags = set()
    for f in glob.glob(os.path.join(outdir, "50-pool-*.json")):
        try:
            with open(f) as fh:
                tags.update(o.get("tag", "")
                            for o in json.load(fh).get("outbounds", []))
        except (OSError, ValueError):
            continue          # a half-written pool is not this function's problem
    n = sum(1 for t in tags if t.startswith(TAG_PREFIX))
    if n <= PROBE_BUDGET:
        return
    interval = None
    try:
        with open(os.path.join(outdir, ROUTING)) as fh:
            interval = json.load(fh)["burstObservatory"]["pingConfig"]["interval"]
    except (OSError, ValueError, KeyError):
        pass
    secs = interval_seconds(interval or "")
    say = lambda m: print(m, file=sys.stderr)
    say(f"\nwarning: {n} outbounds now match the observatory selector "
        f"{TAG_PREFIX!r}.")
    if secs:
        say(f"  At interval {interval} that is {n / secs:.1f} probes/sec sustained, "
            f"and {n} concurrent dials every time xray restarts.")
    say("  burst probes every subject at once and never backs off, so a node that "
        "has been\n  dead for a week is dialled again every round. Cut it with any of:")
    say("      ./alive.sh --prune")
    say(f"      sub2xray.py pool --limit {PROBE_BUDGET} ...")
    if secs:
        say(f"      sub2xray.py init --force --probe-interval {max(3, n // 60)}m")


def write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    print(f"wrote {path}", file=sys.stderr)


def write_pool(outdir, pool, outbounds, size):
    """One file per chunk of `size` nodes; 0 means a single file.

    Existing files for this pool are removed first: a subscription that shrank
    would otherwise leave stale chunks behind, and -confdir would merge those
    dead nodes back in with no warning.
    """
    for stale in glob.glob(os.path.join(outdir, f"50-pool-{pool}-*.json")):
        os.remove(stale)
    step = size if size > 0 else len(outbounds)
    chunks = [outbounds[i:i + step] for i in range(0, len(outbounds), step)]
    for n, chunk in enumerate(chunks, 1):
        # zero-padded: -confdir reads in name order, where "10" sorts before "2"
        write_json(os.path.join(outdir, f"50-pool-{pool}-{n:02d}.json"),
                   {"outbounds": chunk})
    return len(chunks)


def export_uris(outdir, name=None):
    """The pool files, back as a URI list. Order follows the tags.

    What is in the pool files is what xray is dialling, so after a prune this
    is the set of nodes that survived it - alive.sh deletes the dead ones from
    exactly these files. No aliveness is judged here; the confdir is.

    Deduped by config_id, which is what `pool` deduped on: the same node
    reached from two subscriptions parses into two tags and two
    different-looking URIs, and whoever imports this list would then probe it
    twice. Keyed on the configuration rather than the server, so one host
    offered over two transports stays two entries - the observatory has just
    confirmed that both of them answer.
    """
    pattern = f"50-pool-{name}-*.json" if name else "50-pool-*.json"
    uris, seen, unconvertible, duplicates = [], {}, [], []
    for path in sorted(glob.glob(os.path.join(outdir, pattern))):
        try:
            with open(path) as f:
                outbounds = json.load(f).get("outbounds", [])
        except (OSError, ValueError) as e:
            print(f"{path}: {e}", file=sys.stderr)
            continue
        for ob in outbounds:
            try:
                uri = to_uri(ob)
            except (KeyError, IndexError, TypeError) as e:
                unconvertible.append(f"{ob.get('tag', '?')} - {e}")
                continue
            if uri is None:
                unconvertible.append(
                    f"{ob.get('tag', '?')} - no URI form for protocol "
                    f"{ob.get('protocol', '?')!r}")
                continue
            ident = config_id(ob)
            if ident in seen:
                duplicates.append(f"{ob.get('tag', '?')} is {seen[ident]}")
                continue
            seen[ident] = ob.get("tag", "?")
            uris.append(uri)
    # Named, like every other skip in this file. A list that quietly comes back
    # short is the failure mode the whole tool is written against - and the
    # dedupe is the one that surprises, because the count can collapse without
    # anything being wrong. Duplicates SHARE FATE through a prune: six tags for
    # one server all answer or all fail together, so the survivors of a prune
    # are far more duplicated than the subscription they came from.
    for why in unconvertible:
        print(f"not exported: {why}", file=sys.stderr)
    if duplicates:
        print(f"deduped {len(duplicates)} node(s) - identical configuration "
              f"to one already exported:", file=sys.stderr)
        for why in duplicates:
            print(f"  {why}", file=sys.stderr)
    return uris


def read_vless_id(path):
    """The uuid already in 00-inbounds.json, so that a rerun does not roll it.

    It is a credential, and changing it does not break the inbound in any
    visible way: the port stays open, the listener stays up, and every device
    holding the old one is simply refused. So it is minted exactly once, on the
    init that first turns the inbound on, and read back by every init after
    that - including `--force`, which regenerates the file around it.

    Returns None when there is nothing to reuse, and the caller mints one.
    """
    try:
        with open(path) as f:
            for i in json.load(f).get("inbounds", []):
                if i.get("tag") == "inbound-external":
                    return i["settings"]["clients"][0]["id"]
    except (OSError, ValueError, KeyError, IndexError):
        pass          # absent, not json, or not that shape: nothing to reuse
    return None


def write_scaffold(outdir, probe_interval, mode, domains, inbound, force):
    """Create the hand-editable files, but never clobber edits by default."""
    inbound = dict(inbound)
    if inbound["vless"] and not inbound.get("vless_id"):
        inbound["vless_id"] = (read_vless_id(os.path.join(outdir, INBOUNDS))
                               or str(uuid.uuid4()))
    inbound.setdefault("vless_id", "")
    for name, conf in ((INBOUNDS, inbounds_conf(**inbound)),
                       (ROUTING, routing_conf(probe_interval, mode, domains))):
        path = os.path.join(outdir, name)
        if os.path.exists(path) and not force:
            print(f"kept   {path} (--force to rewrite)", file=sys.stderr)
        else:
            write_json(path, conf)


def _selftest():
    v = parse("vless://uid@ex.com:443?type=ws&security=tls&sni=h.com&host=h.com&path=%2Fp&fp=chrome#n", "prox-1")
    assert v["settings"]["vnext"][0]["address"] == "ex.com"
    assert v["settings"]["vnext"][0]["users"][0]["id"] == "uid"
    assert v["streamSettings"]["wsSettings"]["path"] == "/p"
    assert v["streamSettings"]["wsSettings"]["headers"]["Host"] == "h.com"
    assert v["streamSettings"]["tlsSettings"]["serverName"] == "h.com"
    raw = "eyJhZGQiOiJleC5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiJ1aWQiLCJhaWQiOiIwIiwibmV0Ijoid3MiLCJob3N0IjoiaC5jb20iLCJwYXRoIjoiLyIsInRscyI6InRscyJ9"
    m = parse("vmess://" + raw, "prox-2")
    assert m["settings"]["vnext"][0]["address"] == "ex.com"
    assert m["streamSettings"]["security"] == "tls"
    # a #fragment is not part of the base64 payload; it used to break the decode
    assert parse("vmess://" + raw + "#Frankfurt", "prox-2") == m
    t = parse("trojan://p%40ss@ex.com:443?type=ws&security=tls&sni=h.com&path=%2Fp#n", "prox-3")
    assert t["protocol"] == "trojan"
    assert t["settings"]["servers"][0]["password"] == "p@ss"
    assert t["settings"]["servers"][0]["address"] == "ex.com"
    assert t["streamSettings"]["wsSettings"]["path"] == "/p"
    # Trojan with + and / in password (confuses urlparse's / handling)
    t2 = parse("trojan://ZcV1AKzS1KPuLXOvW3RXr+HFldso5hZoaMpZ/qbeEW4=@130.185.122.106:2053?security=tls&fp=chrome#DE",
               "prox-t2")
    assert t2["protocol"] == "trojan"
    assert t2["settings"]["servers"][0]["password"] == "ZcV1AKzS1KPuLXOvW3RXr+HFldso5hZoaMpZ/qbeEW4="
    assert t2["settings"]["servers"][0]["address"] == "130.185.122.106"
    assert t2["settings"]["servers"][0]["port"] == 2053
    # @ in password (userinfo before last @)
    t3 = parse("trojan://!str18844@zxcvbn@os-tr-2.cats22.net:443#JP", "prox-t3")
    assert t3["settings"]["servers"][0]["password"] == "!str18844@zxcvbn"
    assert t3["settings"]["servers"][0]["address"] == "os-tr-2.cats22.net"
    # Legacy XTLS removed in Xray 5.x: security=xtls -> security=tls
    t4 = parse("trojan://pw@host.com:443?flow=xtls-rprx-direct&security=xtls#test", "prox-t4")
    assert t4["streamSettings"]["security"] == "tls"
    # vless with legacy XTLS
    v2 = parse("vless://uid@host.com:443?security=xtls#v", "prox-v2")
    assert v2["streamSettings"]["security"] == "tls"
    # reality without pbk is refused (Xray will fail with empty password)
    try:
        parse("trojan://pw@host.com:443?security=reality&sni=s.com#broken", "prox-rb")
        assert False, "should have been refused"
    except ValueError as e:
        assert "reality without public key" in str(e)
    try:
        parse("vless://uid@host.com:443?security=reality&sni=s.com#broken", "prox-vb")
        assert False, "should have been refused"
    except ValueError as e:
        assert "reality without public key" in str(e)
    # reality WITH pbk is fine
    vr = parse("vless://uid@host.com:443?security=reality&pbk=abc123&sni=s.com#ok", "prox-vr")
    assert vr["streamSettings"]["security"] == "reality"
    assert vr["streamSettings"]["realitySettings"]["publicKey"] == "abc123"

    # ss:// in all three shapes. SIP002 base64 userinfo, SIP002 plain (what the
    # 2022 ciphers use), and the legacy all-in-one-blob form.
    sip = "ss://" + base64.b64encode(b"aes-256-gcm:sspw").decode() + "@s.com:8388#n"
    for u in (sip,
              "ss://2022-blake3-aes-256-gcm:sspw@s.com:8388#n",
              "ss://" + base64.b64encode(b"aes-256-gcm:sspw@s.com:8388").decode() + "#n"):
        o = parse(u, "prox-s")
        assert o["protocol"] == "shadowsocks", u
        srv = o["settings"]["servers"][0]
        assert (srv["address"], srv["port"], srv["password"]) == ("s.com", 8388, "sspw"), u
        # sockopt and NOTHING else. Naming a security here would make xray
        # negotiate TLS and every ss node would fail - but omitting the block
        # altogether is what left ss dials unmarked and looping through tproxy.
        assert o["streamSettings"] == {"sockopt": {"mark": FWMARK}}, u
        assert "security" not in o["streamSettings"], u
    assert parse(sip, "t")["settings"]["servers"][0]["method"] == "aes-256-gcm"
    # 2022 ciphers with 4 base64 keys - colons separate the keys in both the
    # URI and the JSON; Xray's client splits on ':' to get the per-user keys.
    k1 = base64.b64encode(b"\x00" * 32).decode()   # 44 chars
    k2 = base64.b64encode(b"\x01" * 32).decode()
    k3 = base64.b64encode(b"\x02" * 32).decode()
    k4 = base64.b64encode(b"\x03" * 32).decode()
    uri_2022 = f"ss://2022-blake3-aes-256-gcm:{k1}:{k2}:{k3}:{k4}@x.com:443#four"
    o2 = parse(uri_2022, "prox-2k")
    assert o2["protocol"] == "shadowsocks"
    assert o2["settings"]["servers"][0]["password"] == f"{k1}:{k2}:{k3}:{k4}"
    # URL-encoded 2022 key: %3D -> =, %2F -> /, %2B -> +
    ek1 = base64.b64encode(b"\x00\xff\x00\xff" * 8).decode()  # contains + and /
    u1 = ek1.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    uri_2022e = f"ss://2022-blake3-chacha20-poly1305:{u1}@x.com:443#enc"
    o3 = parse(uri_2022e, "prox-enc")
    assert o3["protocol"] == "shadowsocks"
    pwd = o3["settings"]["servers"][0]["password"]
    assert pwd == ek1, f"expected {ek1!r}, got {pwd!r}"
    # node_id must key on ss the same way it keys on vless, or nothing downstream
    # can identify one - it reads servers[0] rather than vnext[0]
    assert node_id(parse(sip, "t")) == "s.com:8388:sspw"
    # ...and on hysteria, whose settings are flat rather than a servers[] list
    assert node_id(parse("hysteria2://hpw@h.example:8443", "t")) == "h.example:8443:hpw"

    # refused, loudly, rather than handed to xray to fail on later
    for bad, why in (("ss://" + base64.b64encode(b"aes-256-cfb:p").decode() + "@s.com:8388", "method"),
                     ("ss://" + base64.b64encode(b"aes-256-gcm:p").decode() + "@s.com:8388?plugin=v2ray-plugin", "plugin")):
        try:
            parse(bad, "t"); assert False, f"{why} should have been refused"
        except ValueError:
            pass

    # hysteria2, which xray registers as protocol "hysteria" with version 2 -
    # there is no "hysteria2" config id. Flat settings, confirmed against 26.3.27.
    h = parse("hysteria2://p%40ss@h.example:8443?sni=a.b&insecure=1#Oslo", "prox-h")
    assert h["protocol"] == "hysteria"
    assert h["settings"] == {"version": 2, "address": "h.example", "port": 8443,
                             "password": "p@ss"}
    assert "hy2://" and parse("hy2://pw@h.example:443", "t")["protocol"] == "hysteria"
    # ⚠ A hysteria outbound with no address PANICS xray on load rather than
    # failing -test, so one malformed entry would take the service down. Refuse
    # it here or nothing downstream gets the chance.
    for bad in ("hysteria2://pw@:443", "hysteria://pw@h.example:443"):
        try:
            parse(bad, "t"); assert False, f"{bad} should have been refused"
        except ValueError:
            pass

    # ---- dedupe keys on the CONFIGURATION, not the server ---------------
    # Same host, same credential, different transport. node_id cannot tell
    # these apart and config_id must, because only one of them may work and
    # nothing has probed either of them yet.
    same_server = parse("vless://u@a.com:443?security=tls", "t")
    other_transport = parse("vless://u@a.com:443?type=ws&security=tls", "t")
    assert node_id(same_server) == node_id(other_transport)
    assert config_id(same_server) != config_id(other_transport)
    # the tag is excluded, or nothing would ever dedupe: tags are positional
    a1, a2 = parse("vless://u@a.com:443", "prox-x-1"), parse("vless://u@a.com:443", "prox-x-9")
    assert config_id(a1) == config_id(a2)

    buf, old = io.StringIO(), sys.stderr
    sys.stderr = buf
    try:
        deduped = build("\n".join([
            "vless://u@a.com:443?security=tls#one",
            "vless://u@a.com:443?security=tls#two",          # identical, dropped
            "vless://u@a.com:443?type=ws&security=tls#three",  # NOT a duplicate
        ]), "d")["outbounds"]
    finally:
        sys.stderr = old
    assert [o["tag"] for o in deduped] == ["prox-d-1", "prox-d-2"], deduped
    assert deduped[1]["streamSettings"]["network"] == "ws", "a distinct config was dropped"
    assert "deduped 1 repeated node(s); 2 distinct" in buf.getvalue(), buf.getvalue()
    # tags stay contiguous: a gap would not break xray, but the pool file would
    # stop matching what the count says it holds
    assert [o["tag"] for o in build("vless://u@a.com:443\nvless://u@a.com:443\n"
                                    "vless://u@b.com:443", "d")["outbounds"]] \
        == ["prox-d-1", "prox-d-2"]

    # ---- to_uri is the inverse of parse ---------------------------------
    # The pool files are the only record of a node, so a field lost on the way
    # back out is a node that silently stops working wherever it is imported.
    # Compare the OUTBOUND rather than the string: what matters is that xray,
    # and whatever reads the export, are handed the same node.
    for u in (
        "vless://uid@ex.com:443?type=ws&security=tls&sni=h.com&host=h.com&path=%2Fp&fp=chrome#n",
        "vless://uid@ex.com:443?security=reality&pbk=k&sid=ab&fp=firefox&flow=xtls-rprx-vision#n",
        "vless://uid@ex.com:8443?type=grpc&security=tls&serviceName=svc&sni=h.com#n",
        "vless://uid@ex.com:80#no-tls-at-all",
        "vless://uid@[2001:db8::1]:443?security=tls&sni=h.com#v6",
        "trojan://p%40ss@ex.com:443?type=ws&security=tls&sni=h.com&path=%2Fp#n",
        "trojan://ZcV1AKzS1KPuLXOvW3RXr+HFldso5hZoaMpZ/qbeEW4=@1.2.3.4:2053?security=tls&fp=chrome#DE",
        "vmess://" + raw,
        sip,
        f"ss://2022-blake3-aes-256-gcm:{k1}:{k2}@s.com:8388#keys",
        "hysteria2://p%40ss@h.example:8443#Oslo",
    ):
        ob = parse(u, "prox-rt-1")
        back = to_uri(ob)
        assert parse(back, "prox-rt-1") == ob, f"{u}\n  -> {back}\n  {parse(back, 'prox-rt-1')}\n  {ob}"
    # An outbound with no URI form is named, never dropped in silence
    assert to_uri({"tag": "direct", "protocol": "freedom", "settings": {}}) is None

    uris = "\n".join([
        "vless://u1@a.com:443?security=reality&pbk=k&sid=1#Berlin",
        "vless://u2@b.com:443?security=reality&pbk=k&sid=2#Munich",
        "trojan://p@c.com:443?security=tls#Amsterdam",
        "ss://" + base64.b64encode(b"aes-256-gcm:sspw").decode() + "@d.com:8388#Oslo",
        "hysteria2://hpw@e.com:443#Reykjavik",
        "hysteria://old@f.com:443#v1-unsupported",
    ])
    # curl returns base64, often line-wrapped; the padding math must survive newlines
    blob = base64.b64encode(uris.encode()).decode()
    assert b64d("\n".join(blob[i:i + 70] for i in range(0, len(blob), 70))) == uris
    assert build(blob, "de")["outbounds"] == build(uris, "de")["outbounds"]

    # The skip must be VISIBLE. A subscription that quietly halves is
    # indistinguishable from one full of dead nodes, and the alive-count would
    # then be measured against a pool that lost members without saying so.
    buf, old = io.StringIO(), sys.stderr
    sys.stderr = buf
    try:
        build(uris, "de")
    finally:
        sys.stderr = old
    noise = buf.getvalue()
    assert "skipped 1 hysteria node(s)" in noise, noise
    assert "f.com:443" in noise, noise          # named, not just counted
    assert "only speaks version 2" in noise, noise

    a, b = build(uris, "de"), build(uris, "nl")
    # pool file carries outbounds and nothing else
    assert list(a) == ["outbounds"]
    assert [o["tag"] for o in a["outbounds"]] == ["prox-de-1", "prox-de-2", "prox-de-3",
                                                  "prox-de-4", "prox-de-5"]
    # every tag is reachable by the single selector in 10-routing.json
    assert all(o["tag"].startswith(TAG_PREFIX) for o in a["outbounds"])
    # two pools must never collide: -confdir silently overwrites a duplicate tag
    assert not ({o["tag"] for o in a["outbounds"]} & {o["tag"] for o in b["outbounds"]})

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        nodes = [{"tag": f"prox-x-{i}"} for i in range(1, 8)]
        assert write_pool(d, "x", nodes, 3) == 3          # 7 nodes, size 3 -> 3 files
        names = sorted(os.path.basename(p) for p in glob.glob(f"{d}/50-pool-x-*.json"))
        assert names == ["50-pool-x-01.json", "50-pool-x-02.json", "50-pool-x-03.json"]
        assert len(json.load(open(f"{d}/50-pool-x-03.json"))["outbounds"]) == 1
        assert write_pool(d, "x", nodes, 0) == 1          # 0 means one file
        # the shrink must not leave 02/03 behind for -confdir to merge back in
        assert glob.glob(f"{d}/50-pool-x-*.json") == [f"{d}/50-pool-x-01.json"]

        inb = {"tproxy_port": 12345, "proxy_listen": "127.0.0.1",
               "proxy_port": 2080, "vless": "", "vless_id": "",
               "loglevel": "warning", "access_log": "none"}
        dl = ["domain:a.example", "geosite:netflix"]
        write_scaffold(d, "3m", "selective", dl, inb, False)
        edited = json.load(open(f"{d}/10-routing.json"))
        edited["routing"]["rules"].insert(0, {"type": "field", "domain": ["mine"]})
        write_json(f"{d}/10-routing.json", edited)
        write_scaffold(d, "3m", "selective", dl, inb, False)  # must not clobber
        assert json.load(open(f"{d}/10-routing.json")) == edited
        write_scaffold(d, "3m", "selective", dl, inb, True)   # --force must
        assert json.load(open(f"{d}/10-routing.json")) == routing_conf("3m", "selective", dl)

        # The confdir must carry no identity from whoever generated it. A LAN
        # address and a literal uuid were baked in here once; the uuid is a
        # credential every clone would then share, on an inbound that is
        # reachable from the network by definition.
        inb_json = json.load(open(f"{d}/00-inbounds.json"))
        assert "inbound-external" not in [i["tag"] for i in inb_json["inbounds"]]
        blob = json.dumps(inb_json)
        assert "192.168.1." not in blob and "fb78e7cd" not in blob, blob
        # ...and logging must stay on stdout, or journald has nothing and
        # alive.sh reads an empty window as "nothing ever failed".
        # The error log stays on stdout: journald is what alive.sh reads.
        assert "error" not in inb_json["log"]
        # The access log is off by default. Unset it is not off, it is stdout,
        # and --loglevel cannot quiet it - it is a separate stream.
        assert inb_json["log"]["access"] == "none", inb_json["log"]
        assert "dnsLog" not in inb_json["log"]
        vl = inbounds_conf(12345, "127.0.0.1", 2080, "10.0.0.1:8585", "u-1",
                           "warning", "none")
        ext = [i for i in vl["inbounds"] if i["tag"] == "inbound-external"][0]
        assert ext["listen"] == "10.0.0.1" and ext["port"] == 8585
        assert ext["settings"]["clients"][0]["id"] == "u-1"

        # ---- the vless uuid must not move under a rerun ------------------
        # Rolling it leaves the inbound up and listening while every client
        # that already holds the old one is quietly refused, so this is a
        # silent break rather than a visible one.
        vinb = dict(inb, vless="10.0.0.1:8585")
        write_scaffold(d, "3m", "selective", dl, vinb, True)
        first = read_vless_id(f"{d}/00-inbounds.json")
        assert first, "no uuid was minted"
        write_scaffold(d, "3m", "selective", dl, vinb, True)   # --force, again
        assert read_vless_id(f"{d}/00-inbounds.json") == first, "uuid rolled on rerun"
        # explicit beats reuse
        write_scaffold(d, "3m", "selective", dl, dict(vinb, vless_id="fixed-1"), True)
        assert read_vless_id(f"{d}/00-inbounds.json") == "fixed-1"
        # ...but a confdir with nothing to reuse still mints a RANDOM one; a
        # uuid derived from anything stable would be a guessable credential.
        with tempfile.TemporaryDirectory() as d2:
            write_scaffold(d2, "3m", "selective", dl, vinb, False)
            assert read_vless_id(f"{d2}/00-inbounds.json") not in (None, first)
        assert read_vless_id(f"{d}/nonexistent.json") is None

    # node_id outlives retirement: alive.sh keys its archive on identity, and the
    # promote step must dedup on it - a tag in two files is silently overwritten
    nodes = build(uris, "de")["outbounds"]
    ids = [node_id(o) for o in nodes]
    assert len(set(ids)) == len(ids)
    # identity is stable when the node's position moves
    shifted = build("\n".join(uris.splitlines()[::-1]), "de")["outbounds"]
    assert {node_id(o) for o in shifted} == set(ids)

    r = routing_conf("3m", "selective", DEFAULT_DOMAINS)
    # burst only: the plain observatory's interval is a per-node sleep, and
    # declaring both silently degrades the balancer
    assert "observatory" not in r and "burstObservatory" in r
    assert r["burstObservatory"]["pingConfig"]["interval"] == "3m"
    # the selector must reach the tags build() emits, or nothing is ever probed
    assert r["burstObservatory"]["subjectSelector"] == [TAG_PREFIX]
    assert r["routing"]["balancers"][0]["selector"] == [TAG_PREFIX]
    assert build(uris, "de")["outbounds"][0]["tag"].startswith(TAG_PREFIX)

    # ---- the loop guards -------------------------------------------------
    # EVERY outbound that dials out carries the fwmark. One that does not is
    # caught by the nftables OUTPUT chain, marked 1 and handed back to the
    # tproxy inbound that emitted it. This is the single assertion that would
    # have caught the shadowsocks case, so it is written over the whole pool
    # rather than per protocol.
    for ob in build(uris, "de")["outbounds"]:
        got = ob.get("streamSettings", {}).get("sockopt", {}).get("mark")
        assert got == FWMARK, f"{ob['tag']} ({ob['protocol']}) has no fwmark: {got}"
    for ob in r["outbounds"]:
        if ob["protocol"] == "blackhole":
            continue                      # answers locally, never opens a socket
        got = ob.get("streamSettings", {}).get("sockopt", {}).get("mark")
        assert got == FWMARK, f"{ob['tag']} has no fwmark: {got}"

    rules = r["routing"]["rules"]
    # A rule without type:field silently never matches. That is how the
    # dnsproxy rule read as wired up while the queries went out the catch-all.
    for rule in rules:
        assert rule.get("type") == "field", rule
    # Every tag a rule points at has to exist, in one direction or the other.
    tags = {o["tag"] for o in r["outbounds"]} | {"lb"}
    dns_tags = {srv["tag"] for srv in r["dns"]["servers"]}
    for rule in rules:
        assert rule.get("outboundTag", rule.get("balancerTag")) in tags, rule
        for t in rule.get("inboundTag", []):
            assert t in dns_tags, f"rule points at inbound tag {t!r} that no DNS server emits"
    # The DNS module's own queries must be routed BEFORE the port-53 rule.
    # Below it, a resolver's own lookup matches that rule and is handed back to
    # dns-out, and the module starts answering its own upstream queries out of
    # its own cache - the "cache HIT ... empty response" storm.
    idx = {t: i for i, rule in enumerate(rules) for t in rule.get("inboundTag", [])}
    port53 = next(i for i, rule in enumerate(rules) if rule.get("port") == "53")
    assert idx["dns-proxied"] < port53 and idx["dns-direct"] < port53, rules
    # ...and they must go different ways, or the split is not a split.
    assert rules[idx["dns-proxied"]]["balancerTag"] == "lb"
    assert rules[idx["dns-direct"]]["outboundTag"] == "direct"

    # Split DNS mirrors the routing split: same list, both modes.
    sel = routing_conf("3m", "selective", DEFAULT_DOMAINS)
    full = routing_conf("3m", "full", DEFAULT_DOMAINS)
    assert sel["dns"]["servers"][0]["domains"] == DEFAULT_DOMAINS
    assert "domains" not in full["dns"]["servers"][0]
    assert [rr for rr in sel["routing"]["rules"]
            if rr.get("domain") == DEFAULT_DOMAINS][0]["balancerTag"] == "lb"
    # Plaintext DNS cannot appear at all: an injected answer is believed and
    # then cached, and afterwards even a working node dials the block address.
    for conf in (sel, full):
        for srv in conf["dns"]["servers"]:
            assert srv["address"].startswith("https://"), srv
        assert conf["dns"]["queryStrategy"] == "UseIPv4"
    # The last rule is the catch-all, and it is the one thing the modes differ on.
    assert sel["routing"]["rules"][-1]["outboundTag"] == "direct"
    assert full["routing"]["rules"][-1]["balancerTag"] == "lb"
    assert full["routing"]["rules"][-1]["network"] == "tcp,udp"
    # ---- the observatory's cost is reported, and boundable ---------------
    assert interval_seconds("3m") == 180 and interval_seconds("90s") == 90
    assert interval_seconds("1h") == 3600
    assert interval_seconds("") is None and interval_seconds("3x") is None
    with tempfile.TemporaryDirectory() as d:
        write_json(os.path.join(d, ROUTING), routing_conf("3m", "full", ["x"]))
        big = [{"tag": f"prox-p-{i}"} for i in range(1, PROBE_BUDGET + 51)]
        write_pool(d, "p", big, 0)
        buf, old_err = io.StringIO(), sys.stderr
        sys.stderr = buf
        try:
            probe_load_note(d)
        finally:
            sys.stderr = old_err
        note = buf.getvalue()
        # the count, the rate and the restart burst all have to be in it: the
        # number alone does not tell anyone it is a problem
        assert f"{PROBE_BUDGET + 50} outbounds" in note, note
        assert "probes/sec" in note and "concurrent dials" in note, note
        assert "alive.sh --prune" in note and "--limit" in note, note
        # a pool inside the budget says nothing at all
        write_pool(d, "p", big[:10], 0)
        buf, old_err = io.StringIO(), sys.stderr
        sys.stderr = buf
        try:
            probe_load_note(d)
        finally:
            sys.stderr = old_err
        assert buf.getvalue() == "", buf.getvalue()

    # ---- domains.txt is config, and is never written over ---------------
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "domains.txt")
        assert ensure_domains(f) == DEFAULT_DOMAINS       # seeded from the literal
        assert os.path.exists(f)
        open(f, "w").write(
            "# a comment\n"
            "\n"
            "  domain:a.example   \n"                      # trimmed
            "domain:a.example\n"                          # deduped
            "geosite:netflix  # trailing note\n"           # comment after content
            "regexp:^x#y$\n")                             # '#' inside a matcher survives
        assert ensure_domains(f) == ["domain:a.example", "geosite:netflix",
                                     "regexp:^x#y$"]
        # seeding is once: a second call must not put the defaults back
        assert ensure_domains(f) != DEFAULT_DOMAINS
        # a typo'd matcher is a rule that silently never fires, so it is named
        buf, old = io.StringIO(), sys.stderr
        sys.stderr = buf
        try:
            open(f, "w").write("geosit:netflix\ndomain:ok.example\n")
            got = read_domains(f)
        finally:
            sys.stderr = old
        assert got == ["geosit:netflix", "domain:ok.example"]   # passed through
        assert "'geosit'" in buf.getvalue(), buf.getvalue()     # but called out
        # an empty list is legal to read; main is what refuses it in selective
        open(f, "w").write("# nothing but comments\n")
        assert read_domains(f) == []
        # ⚠ --force regenerates the two json files FROM this one and must never
        # rewrite it, or edit-then-apply would reset the list it is applying.
        open(f, "w").write("domain:kept.example\n")
        inb = {"tproxy_port": 12345, "proxy_listen": "127.0.0.1", "proxy_port": 2080,
               "vless": "", "vless_id": "", "loglevel": "warning",
               "access_log": "none"}
        write_scaffold(d, "3m", "selective", read_domains(f), inb, True)
        assert read_domains(f) == ["domain:kept.example"], "--force rewrote domains.txt"
        assert json.load(open(f"{d}/10-routing.json"))["dns"]["servers"][0]["domains"] \
            == ["domain:kept.example"]

    # ---- export reads the confdir, which is what a prune leaves behind ---
    with tempfile.TemporaryDirectory() as d:
        write_pool(d, "de", [parse("vless://u1@a.com:443?security=tls&sni=a.com", "prox-de-1"),
                             parse("ss://2022-blake3-aes-256-gcm:k@s.com:8388", "prox-de-2"),
                             # the same node as prox-de-1, as a second
                             # subscription would have delivered it
                             parse("vless://u1@a.com:443?security=tls&sni=a.com", "prox-de-3"),
                             {"tag": "prox-de-4", "protocol": "freedom", "settings": {}}], 0)
        write_pool(d, "nl", [parse("trojan://pw@c.com:443", "prox-nl-1")], 0)
        buf, old = io.StringIO(), sys.stderr
        sys.stderr = buf
        try:
            got = export_uris(d)
        finally:
            sys.stderr = old
        # deduped by node_id: the repeat carries a different tag and a
        # different-looking URI, and is the same server either way
        assert len(got) == 3, got
        # ...and said out loud, naming BOTH tags: a count that collapses from
        # 13 to 5 is alarming until you can see it was one server six times.
        assert "deduped 1 node(s)" in buf.getvalue(), buf.getvalue()
        assert "prox-de-3 is prox-de-1" in buf.getvalue(), buf.getvalue()
        assert [u.split("://")[0] for u in got] == ["vless", "ss", "trojan"], got
        assert all("prox-de-3" not in u for u in got), got
        # ...and what could not be exported is named rather than dropped
        assert "prox-de-4" in buf.getvalue(), buf.getvalue()
        # --name is the pool, and the tag carries it into the export
        assert export_uris(d, "nl") == [u for u in got if u.startswith("trojan")]
        assert "prox-nl-1" in export_uris(d, "nl")[0]
        # every exported URI must parse back into the outbound it came from
        for uri in got:
            assert parse(uri, "t") is not None, uri
        assert export_uris(d, "no-such-pool") == []

    print("selftest ok")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--outdir", default=CONFDIR,
                    help=f"confdir to write (default: {CONFDIR}, or $XRAY_CONFDIR)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="write inbounds + routing (once)")
    p_init.add_argument("--mode", choices=("selective", "full"), default="selective",
                        help="selective: only DOMAIN_LIST exits via the pool "
                             "(default). full: everything does.")
    p_init.add_argument("--domains", default=None, metavar="PATH",
                        help=f"matcher list, one per line (default: "
                             f"<confdir>/{DOMAINS}, seeded from the built-in "
                             f"list if absent). Never rewritten, including by "
                             f"--force: it is the input --force reads.")
    p_init.add_argument("--vless-id", default="", metavar="UUID",
                        help="uuid for --vless-listen. Default: reuse the one "
                             "already in %s, or mint one on first use." % INBOUNDS)
    p_init.add_argument("--probe-interval", default="3m",
                        help="observatory interval; probe rate is nodes/interval")
    p_init.add_argument("--tproxy-port", type=int, default=12345,
                        help="dokodemo-door port nftables tproxies at (default: 12345)")
    p_init.add_argument("--proxy-listen", default="0.0.0.0",
                        help="listen address for the plain socks/http port. "
                             "Default 0.0.0.0 serves every interface, including "
                             "any public one. That port is auth:noauth, so it is "
                             "an open proxy to whoever can route to it: firewall "
                             "it, or narrow this to a LAN or docker-bridge "
                             "address (172.17.0.1 for containers).")
    p_init.add_argument("--proxy-port", type=int, default=2080)
    p_init.add_argument("--vless-listen", default="", metavar="ADDR:PORT",
                        help="also serve an inbound vless listener, e.g. "
                             "192.168.1.10:8585. Off by default; the uuid is "
                             "generated and printed, never shipped in the repo.")
    p_init.add_argument("--loglevel", default="warning",
                        choices=("debug", "info", "warning", "error", "none"),
                        help="error log only. warning (default) keeps the "
                             "observatory failures alive.sh prunes on; debug "
                             "adds who answered; error and none leave alive.sh "
                             "with nothing to read.")
    p_init.add_argument("--access-log", default="none", metavar="PATH",
                        help="the per-connection log, which is the bulk of the "
                             "volume and is not affected by --loglevel. 'none' "
                             "(default) turns it off. A path writes it there; "
                             "unset entirely, xray sends it to stdout and "
                             "journald keeps all of it.")
    p_init.add_argument("--force", action="store_true",
                        help="rewrite the files, discarding your edits")

    p_pool = sub.add_parser("pool", help="write node files for one subscription")
    p_pool.add_argument("source", nargs="?", help="subscription file; omit for stdin")
    p_pool.add_argument("--name", default="main", help="pool name, namespaces the tags")
    p_pool.add_argument("--size", type=int, default=0, metavar="N",
                        help="nodes per file; 0 (default) puts them all in one")
    p_pool.add_argument("--limit", type=int, default=0, metavar="N",
                        help="keep at most N nodes from this subscription "
                             "(0 = all). The observatory probes every node it "
                             "is given, concurrently, every interval, so this "
                             "is the lever that bounds that cost at the source.")

    p_exp = sub.add_parser("export",
                           help="print the pool's nodes back as URIs, on stdout")
    p_exp.add_argument("--name", default=None, metavar="POOL",
                       help="only this pool (default: every pool file)")
    p_exp.add_argument("--base64", action="store_true",
                       help="emit one base64 blob instead of a URI per line, "
                            "which is the shape a client's 'add subscription' "
                            "box expects")

    sub.add_parser("selftest", help="run the internal checks")
    args = ap.parse_args()

    if args.cmd == "selftest":
        _selftest()
    elif args.cmd == "export":
        # stdout is the list and stderr is the commentary, so a redirect to a
        # file gets URIs and nothing else.
        uris = export_uris(args.outdir, args.name)
        if not uris:
            sys.exit(f"no nodes to export from {args.outdir}/50-pool-*.json")
        blob = "\n".join(uris)
        print(base64.b64encode(blob.encode()).decode() if args.base64 else blob)
        print(f"exported {len(uris)} node(s) from {args.outdir}", file=sys.stderr)
    elif args.cmd == "init":
        os.makedirs(args.outdir, exist_ok=True)
        domains = ensure_domains(args.domains
                                 or os.path.join(args.outdir, DOMAINS))
        if args.mode == "selective" and not domains:
            sys.exit("the domain list is empty, so selective mode would proxy "
                     "nothing but geoip:telegram. Add entries, or use --mode full.")
        write_scaffold(args.outdir, args.probe_interval, args.mode, domains,
                       {"tproxy_port": args.tproxy_port,
                        "proxy_listen": args.proxy_listen,
                        "proxy_port": args.proxy_port,
                        "vless": args.vless_listen,
                        "vless_id": args.vless_id,
                        "loglevel": args.loglevel,
                        "access_log": args.access_log}, args.force)
        # Said out loud at the moment the config is written, not only in --help.
        # An open relay is found by scanners in days and the first symptom is
        # somebody else's traffic, which is a long way from this file. Narrowing
        # --proxy-listen silences it, so it stays a signal rather than a nag.
        if args.proxy_listen in ("0.0.0.0", "::"):
            print(f"note: socks/http on {args.proxy_listen}:{args.proxy_port} is "
                  f"auth:noauth, so it is an open proxy to anything that can "
                  f"route here.\n      Firewall that port, or narrow it: "
                  f"--proxy-listen <lan-or-bridge-addr>", file=sys.stderr)
        if args.vless_listen:
            print(f"vless inbound uuid: "
                  f"{read_vless_id(os.path.join(args.outdir, INBOUNDS))}",
                  file=sys.stderr)
        print(f"confdir ready at {args.outdir}/ - add nodes with: "
              f"sub2xray.py pool --name <name> <sub>", file=sys.stderr)
        print(f"wireguard peers go in {args.outdir}/{WIREGUARD} via wg-peer.sh",
              file=sys.stderr)
    else:
        # Refuse rather than scaffold: silently creating routing here is exactly
        # the conflation the two commands exist to prevent.
        if not os.path.exists(os.path.join(args.outdir, ROUTING)):
            sys.exit(f"{args.outdir}/{ROUTING} missing - run: sub2xray.py "
                     f"--outdir {args.outdir} init")
        src = open(args.source).read() if args.source else sys.stdin.read()
        outbounds = build(src, args.name)["outbounds"]
        # Named, not silent. Dropping most of a subscription without a word is
        # the same failure as a subscription that silently halves.
        if 0 < args.limit < len(outbounds):
            print(f"--limit: keeping {args.limit} of {len(outbounds)} nodes in "
                  f"pool '{args.name}'; the rest are not written", file=sys.stderr)
            outbounds = outbounds[:args.limit]
        n = write_pool(args.outdir, args.name, outbounds, args.size)
        print(f"{len(outbounds)} nodes in pool '{args.name}' across {n} file(s)",
              file=sys.stderr)
        probe_load_note(args.outdir)

