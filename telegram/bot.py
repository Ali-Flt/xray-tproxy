#!/usr/bin/env python3
"""tgpush: send a file to a Telegram group whenever its contents change.

    python3 bot.py                 run the watcher
    python3 bot.py selftest        change detection only; no config, no network

Written for refresh.sh's published node list, but it knows nothing about that
file's format: it watches a path and posts the lines that were not there last
time, in fenced blocks split to fit Telegram's message limit. Config in $TGPUSH_CONFIG, default /etc/tgpush/config.ini.

A channel and a supergroup are the same thing to MTProto - both are peers of
type channel, both have ids of the form -100<id> - so chat_id takes either.
They differ in one way that matters: anyone may post in a group, while in a
channel only an administrator with "Post Messages" can, which is why a bot is
added to a channel by promoting it rather than by inviting it.

⚠ Whatever it sends is published to everyone in that group, and a node list is
  a list of credentials. Nothing here can un-send it.
"""
import asyncio
import configparser
import hashlib
import logging
import os
import signal
import sys
from datetime import datetime, timezone

CONFIG = os.environ.get("TGPUSH_CONFIG", "/etc/tgpush/config.ini")

log = logging.getLogger("tgpush")


def load_config(path):
    """Read the ini, and fail at startup rather than at the first send."""
    if not os.path.exists(path):
        sys.exit(f"no config at {path} - copy config.ini.example and fill it in")
    cp = configparser.ConfigParser()
    cp.read(path)
    try:
        tg, watch = cp["telegram"], cp["watch"]
        cfg = {
            "api_id": tg.getint("api_id"),
            "api_hash": tg["api_hash"].strip(),
            "bot_token": tg["bot_token"].strip(),
            "chat_id": tg.getint("chat_id"),
            "path": watch.get("path", "/var/lib/xray/working.txt"),
            "interval": watch.getint("interval", 30),
            "state": watch.get("state", "/var/lib/tgpush/state"),
            "session": watch.get("session", "/var/lib/tgpush/tgpush"),
            "caption": watch.get("caption",
                                  "{n} new node(s) - {total} working - {when}"),
        }
    except (KeyError, ValueError) as e:
        sys.exit(f"{path}: {e}")
    for key in ("api_id", "api_hash", "bot_token", "chat_id"):
        if not cfg[key]:
            sys.exit(f"{path}: [telegram] {key} is empty")
    return cfg


def ident(uri):
    """What makes a node the same node: everything but its #tag, hashed.

    The fragment is the outbound's tag, and tags are POSITIONAL -
    prox-<pool>-<n>, n being the node's index in the subscription. One node
    appearing upstream renumbers every node after it. Measured against one
    insertion into a 977-node subscription: all 964 nodes present in both
    exports were renumbered, against 14 genuinely added. Keying on the line
    would call all 964 of them new.

    Hashed rather than kept whole so the state file, which is a list of these,
    is not a second copy of every credential in the pool.
    """
    return hashlib.sha256(uri.split("#", 1)[0].encode()).hexdigest()


def read_nodes(path):
    """{identity: line} for the published list, in file order.

    None when the file is missing or has nothing in it - which is not the same
    as an empty pool, and must never be read as "everything was removed".
    """
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return None
    nodes = {}
    for line in text.splitlines():
        line = line.strip()
        if line:
            nodes.setdefault(ident(line), line)
    return nodes or None


def newcomers(nodes, sent):
    """The lines whose identity has not been sent before, in file order."""
    return [uri for key, uri in nodes.items() if key not in sent]


def read_state(path):
    """The identities already sent. An unreadable state file means none."""
    try:
        with open(path) as f:
            return {line.strip() for line in f if line.strip()}
    except OSError:
        return set()


def write_state(path, keys):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        f.write("".join(k + "\n" for k in sorted(keys)))
    os.replace(tmp, path)


def peer_kind(chat_id):
    """(kind, bare id) for a chat id. The sign and the -100 prefix are the type.

    A supergroup or channel is marked -100<id> - they are one peer type and
    need no distinguishing here - a basic group is a bare negative, and a user
    is positive. Kept separate from to_peer so it can be tested without
    telethon installed.
    """
    if chat_id > 0:
        return "user", chat_id
    text = str(chat_id)
    if text.startswith("-100"):
        return "channel", int(text[4:])
    return "chat", -chat_id


def to_peer(chat_id):
    """A chat id as an input peer, without asking Telegram who that is.

    A bot's session starts empty and bots cannot enumerate their dialogs, so
    get_entity() on a group it has merely been added to raises "Could not find
    the input entity". Constructing the peer from the id sidesteps that lookup.
    """
    from telethon.tl.types import PeerChannel, PeerChat, PeerUser
    kind, ident = peer_kind(chat_id)
    return {"user": PeerUser, "channel": PeerChannel, "chat": PeerChat}[kind](ident)


# Telegram refuses a message over 4096 characters, and a pool of typical vless
# URIs passes that at about seventeen nodes. So the list is split, never
# truncated: a node list missing its tail is worse than a second message,
# because nothing about it looks incomplete.
BODY_BUDGET = 3900      # 4096, less the fence, the header and the counter


def chunk(uris, budget=BODY_BUDGET):
    """Group URIs into message-sized batches, never splitting one across two."""
    out, cur, size = [], [], 0
    for uri in uris:
        if cur and size + len(uri) + 1 > budget:
            out.append(cur)
            cur, size = [], 0
        cur.append(uri)
        size += len(uri) + 1
    if cur:
        out.append(cur)
    return out


async def send(client, peer, cfg, fresh, total):
    now = datetime.now(timezone.utc)
    fields = {"n": len(fresh), "total": total,
              "when": now.strftime("%Y-%m-%d %H:%M UTC"),
              "stamp": now.strftime("%Y%m%dT%H%M%SZ")}
    parts = chunk(fresh)
    for i, part in enumerate(parts, 1):
        head = cfg["caption"].format(**fields)
        if len(parts) > 1:
            head += f"  ({i}/{len(parts)})"
        # A fenced block, not bare lines. A URI is full of _ * [ ] ( ) ~ ` and
        # markdown would eat half of them and mangle the rest; inside a fence
        # nothing is parsed, and Telegram renders it monospace with a copy
        # button, which is the whole point of sending text rather than a file.
        text = "**{}**\n```\n{}\n```".format(head, "\n".join(part))
        # link_preview off, or a message of URLs grows a preview card for
        # whichever one Telegram decides to resolve.
        await client.send_message(peer, text, parse_mode="md", link_preview=False)
        if i < len(parts):
            await asyncio.sleep(1)   # polite, and well inside the flood limits


async def pause(stop, seconds):
    """Sleep, but wake immediately on shutdown."""
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


async def watch(cfg, stop):
    from telethon import TelegramClient
    from telethon.errors import ChatAdminRequiredError, ChatWriteForbiddenError
    client = TelegramClient(cfg["session"], cfg["api_id"], cfg["api_hash"])
    # ⚠ A failed connect is ordinary here, not exceptional. This container runs
    # on the proxy host, its own traffic is captured like everything else, and
    # geoip:telegram routes to the balancer - so it reaches Telegram THROUGH
    # the pool it is publishing. Every refresh cycle restarts xray underneath
    # it, and a pool that has not settled cannot carry the connection at all.
    # Exiting on that hands a full traceback to Docker's restart policy once a
    # minute, for a condition that resolves itself.
    delay = cfg["interval"]
    while not stop.is_set():
        try:
            await client.start(bot_token=cfg["bot_token"])
            break
        except Exception as e:
            log.warning("cannot reach Telegram (%s: %s); retrying in %ss. This "
                        "container's traffic goes out through the xray pool - "
                        "check that it is up.", type(e).__name__, e, delay)
            await pause(stop, delay)
            delay = min(delay * 2, 300)     # backoff, capped at five minutes
    if stop.is_set():
        return
    me = await client.get_me()
    # Resolved once, at startup, rather than on the first change. A wrong id or
    # a bot that was never added to the group is otherwise a watcher that looks
    # healthy for hours and then fails at the only moment it had a job to do.
    try:
        peer = await client.get_input_entity(to_peer(cfg["chat_id"]))
    except (ValueError, TypeError) as e:
        sys.exit(f"cannot resolve chat_id {cfg['chat_id']}: {e}\n"
                 f"Check the id (a channel or supergroup starts -100), and that "
                 f"@{me.username} has been added to it - as an administrator if "
                 f"it is a channel.")
    log.info("connected as @%s, watching %s every %ss",
             me.username, cfg["path"], cfg["interval"])
    sent = read_state(cfg["state"])
    if sent:
        log.info("resuming: %d node(s) already sent, only newcomers go out", len(sent))
    while not stop.is_set():
        try:
            nodes = read_nodes(cfg["path"])
            if nodes:
                fresh = newcomers(nodes, sent)
                if fresh:
                    await send(client, peer, cfg, fresh, len(nodes))
                    log.info("sent %d new node(s) of %d published", len(fresh), len(nodes))
                # Only after the send lands - recording first would turn a
                # failed send into a change that is never retried. Written even
                # when nothing was new, because the state is WHAT IS PUBLISHED
                # NOW, not everything ever seen: a node that drops out has to
                # leave the set, or its return would never be announced.
                if fresh or set(nodes) != sent:
                    write_state(cfg["state"], set(nodes))
                    sent = set(nodes)
        except (ChatWriteForbiddenError, ChatAdminRequiredError):
            # Never resolves on its own, so it gets the fix rather than a
            # stack trace repeated every 30 seconds. Not fatal: promoting the
            # bot takes effect immediately and the next check sends.
            log.error("cannot post to %s. In a CHANNEL the bot must be an "
                      "ADMINISTRATOR with 'Post Messages' - being a member is "
                      "enough for a group but not for a channel. Promote "
                      "@%s and the next check sends.",
                      cfg["chat_id"], me.username)
        except Exception as e:          # one bad tick must not end the watch
            log.warning("tick failed, retrying in %ss: %s", cfg["interval"], e)
        # Polling, not inotify. refresh.sh publishes by renaming a temp file
        # over this path, which replaces the inode - an inotify watch on the
        # path follows the OLD inode and silently never fires again.
        await pause(stop, cfg["interval"])
    await client.disconnect()
    log.info("stopped")


def _selftest():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "working.txt")
        assert read_nodes(p) is None                    # missing
        open(p, "w").write("   \n")
        assert read_nodes(p) is None                    # empty is not "all gone"

        # ⚠ Tags are positional, so one node arriving upstream renumbers every
        # node after it. That renaming is not a new node.
        open(p, "w").write("vless://x@a.com:443#prox-p-7\nvless://y@b.com:443#prox-p-8\n")
        first = read_nodes(p)
        assert len(first) == 2
        open(p, "w").write("vless://y@b.com:443#prox-p-9\nvless://x@a.com:443#prox-p-8\n")
        renumbered = read_nodes(p)
        assert set(renumbered) == set(first), "a renumbered or reordered tag read as new"
        assert newcomers(renumbered, set(first)) == [], "it would have resent both"
        # ...and the line that goes out carries the CURRENT tag, not the old one
        open(p, "w").write("vless://x@a.com:443#prox-p-1\nvless://z@c.com:443#prox-p-2\n")
        nodes = read_nodes(p)
        assert newcomers(nodes, set(first)) == ["vless://z@c.com:443#prox-p-2"]

        # ⚠ The state is what is published NOW, never everything ever seen. A
        # node that drops out has to leave the set, or its return is silent -
        # and nodes drop out of these pools constantly.
        gone = {k: v for k, v in first.items()}
        state = set(gone)
        open(p, "w").write("vless://x@a.com:443#prox-p-1\n")     # y disappears
        shrunk = read_nodes(p)
        assert newcomers(shrunk, state) == [], "a removal is not an announcement"
        state = set(shrunk)                                       # ...but it updates
        open(p, "w").write("vless://x@a.com:443#prox-p-1\nvless://y@b.com:443#prox-p-2\n")
        assert newcomers(read_nodes(p), state) == ["vless://y@b.com:443#prox-p-2"], \
            "a node that came back was never announced"

        # a first run has nothing to compare against, so everything is new
        assert len(newcomers(read_nodes(p), set())) == 2

        st = os.path.join(d, "sub", "state")
        assert read_state(st) == set()
        write_state(st, {"aa", "bb"})
        assert read_state(st) == {"aa", "bb"}
        write_state(st, {"cc"})                        # replaces, never appends
        assert read_state(st) == {"cc"}

    # ⚠ Split, never truncated, and never mid-URI: half a node is a node that
    # looks usable and is not.
    long_uri = "vless://" + "x" * 400
    assert chunk([]) == []
    assert chunk(["a", "b"]) == [["a", "b"]]
    batches = chunk([long_uri] * 30)
    assert sum(len(b) for b in batches) == 30, batches
    assert all(sum(len(u) + 1 for u in b) <= BODY_BUDGET for b in batches), batches
    assert all(u == long_uri for b in batches for u in b), "a URI was cut in half"
    # one URI larger than the budget still goes out whole rather than sliced
    assert chunk(["y" * 5000]) == [["y" * 5000]]

    # The peer is constructed rather than looked up: a bot's session is empty
    # and cannot resolve a group it was merely added to.
    assert peer_kind(-1001234567890) == ("channel", 1234567890)
    assert peer_kind(-987654321) == ("chat", 987654321)
    assert peer_kind(12345) == ("user", 12345)
    print("selftest ok")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if sys.argv[1:] == ["selftest"]:
        _selftest()
        sys.exit(0)
    if sys.argv[1:]:
        sys.exit(f"usage: {sys.argv[0]} [selftest]")
    conf = load_config(CONFIG)

    async def run():
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        # docker stop sends SIGTERM. Without this the container is killed ten
        # seconds later mid-send, and the state file may not match what landed.
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await watch(conf, stop)

    asyncio.run(run())
