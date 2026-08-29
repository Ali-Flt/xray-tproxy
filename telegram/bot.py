#!/usr/bin/env python3
"""tgpush: send a file to a Telegram group whenever its contents change.

    python3 bot.py                 run the watcher
    python3 bot.py selftest        change detection only; no config, no network

Written for refresh.sh's published node list, but it knows nothing about that
file's format: it watches a path, and every time the bytes change it sends the
file to one chat. Config in $TGPUSH_CONFIG, default /etc/tgpush/config.ini.

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
            "caption": watch.get("caption", "{n} working nodes - {when}"),
            "filename": watch.get("filename", "nodes-{stamp}.txt"),
        }
    except (KeyError, ValueError) as e:
        sys.exit(f"{path}: {e}")
    for key in ("api_id", "api_hash", "bot_token", "chat_id"):
        if not cfg[key]:
            sys.exit(f"{path}: [telegram] {key} is empty")
    return cfg


def digest(path):
    """The file's content hash, or None if it is missing or empty.

    Content, not mtime: refresh.sh republishes on every settled cycle whether
    or not the survivors changed, and re-sending an identical list every half
    hour is how a group learns to mute you.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if not data.strip():
        return None
    return hashlib.sha256(data).hexdigest()


def read_state(path):
    try:
        with open(path) as f:
            return f.read().strip() or None
    except OSError:
        return None


def write_state(path, value):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        f.write(value + "\n")
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


async def send(client, peer, cfg, body):
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    fields = {"n": len(body.splitlines()), "when": now.strftime("%Y-%m-%d %H:%M UTC"),
              "stamp": stamp}
    # As a document, always. A pool is well past the 4096-character message
    # limit at 30 nodes, and a file is what the other end imports anyway.
    from telethon.tl.types import DocumentAttributeFilename
    buf = body.encode()
    await client.send_file(
        peer, buf, caption=cfg["caption"].format(**fields),
        force_document=True,
        attributes=[DocumentAttributeFilename(cfg["filename"].format(**fields))])


async def watch(cfg, stop):
    from telethon import TelegramClient
    from telethon.errors import ChatAdminRequiredError, ChatWriteForbiddenError
    client = TelegramClient(cfg["session"], cfg["api_id"], cfg["api_hash"])
    await client.start(bot_token=cfg["bot_token"])
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
    last = read_state(cfg["state"])
    if last:
        log.info("resuming from a previous send; an unchanged file is not resent")
    while not stop.is_set():
        try:
            current = digest(cfg["path"])
            if current and current != last:
                with open(cfg["path"]) as f:
                    body = f.read()
                await send(client, peer, cfg, body)
                # Only after the send lands. Recording it first would turn a
                # failed send into a change that is never retried.
                write_state(cfg["state"], current)
                last = current
                log.info("sent %d node(s)", len(body.splitlines()))
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
        try:
            await asyncio.wait_for(stop.wait(), timeout=cfg["interval"])
        except asyncio.TimeoutError:
            pass
    await client.disconnect()
    log.info("stopped")


def _selftest():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "working.txt")
        assert digest(p) is None                       # missing
        open(p, "w").write("   \n")
        assert digest(p) is None                       # empty is not a change
        open(p, "w").write("vless://a\n")
        first = digest(p)
        assert first and digest(p) == first            # stable
        open(p, "w").write("vless://a\n")              # rewritten, same bytes
        assert digest(p) == first, "an identical republish must not look new"
        open(p, "w").write("vless://b\n")
        assert digest(p) != first

        s = os.path.join(d, "sub", "state")
        assert read_state(s) is None
        write_state(s, first)
        assert read_state(s) == first
        write_state(s, "second")                       # replaces, never appends
        assert read_state(s) == "second"

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
