from __future__ import annotations

import argparse
from contextlib import contextmanager
import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from getpass import getpass
from pathlib import Path
from typing import Any, Iterator

from aiohttp import WSMsgType, web

APP_DIR = Path(__file__).resolve().parent
COOKIE_NAME = "wembux_session"
SESSION_DAYS = 30
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    banned INTEGER NOT NULL DEFAULT 0,
    ban_reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS friend_requests (
    id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE(sender_id, recipient_id)
);
CREATE TABLE IF NOT EXISTS friendships (
    user_a TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_b TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY(user_a, user_b),
    CHECK(user_a < user_b)
);
CREATE TABLE IF NOT EXISTS direct_messages (
    id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS dm_pair_time ON direct_messages(sender_id, recipient_id, created_at);
CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS server_members (
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    joined_at TEXT NOT NULL,
    PRIMARY KEY(server_id, account_id)
);
CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(server_id, name)
);
CREATE TABLE IF NOT EXISTS channel_messages (
    id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    sender_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS channel_message_time ON channel_messages(channel_id, created_at);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def open_db(path: Path, initialize: bool = True) -> Iterator[sqlite3.Connection]:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    if initialize:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(SCHEMA)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = stored.split("$", 2)
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def public_account(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "banned": bool(row["banned"]),
        "reason": row["ban_reason"],
        "createdAt": row["created_at"],
    }


def initialize_owner(db_path: Path, username: str, password: str) -> bool:
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Owner username must use 3-32 letters, numbers, or underscores.")
    if len(password) < 8:
        raise ValueError("Choose a password with at least 8 characters.")
    with open_db(db_path) as db:
        exists = db.execute("SELECT 1 FROM accounts WHERE role = 'owner' LIMIT 1").fetchone()
        if exists:
            return False
        db.execute(
            "INSERT INTO accounts(id, username, email, password_hash, role, created_at) VALUES(?, ?, ?, ?, 'owner', ?)",
            (str(uuid.uuid4()), username, f"{username.lower()}@wembux.local", hash_password(password), now_iso()),
        )
    return True


class WembuxService:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.sockets: dict[str, set[web.WebSocketResponse]] = {}
        with open_db(db_path):
            pass

    def connect_db(self) -> sqlite3.Connection:
        return open_db(self.db_path, initialize=False)

    def account_for_session(self, token: str | None) -> sqlite3.Row | None:
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        with self.connect_db() as db:
            return db.execute(
                "SELECT a.* FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=? AND s.expires_at>? AND a.banned=0",
                (token_hash, now_iso()),
            ).fetchone()

    async def require_user(self, request: web.Request) -> sqlite3.Row:
        row = self.account_for_session(request.cookies.get(COOKIE_NAME))
        if row is None:
            raise web.HTTPUnauthorized(text="Please sign in.")
        return row

    async def require_owner(self, request: web.Request) -> sqlite3.Row:
        row = await self.require_user(request)
        if row["role"] != "owner":
            raise web.HTTPForbidden(text="Owner access required.")
        return row

    async def broadcast(self, account_ids: list[str], event: dict[str, Any]) -> None:
        payload = json.dumps(event, separators=(",", ":"))
        targets = {socket for account_id in account_ids for socket in self.sockets.get(account_id, set())}
        if targets:
            await asyncio.gather(*(socket.send_str(payload) for socket in targets if not socket.closed), return_exceptions=True)

    async def health(self, request: web.Request) -> web.Response:
        try:
            with self.connect_db() as db:
                accounts = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
            online_users = sum(bool(sockets) for sockets in self.sockets.values())
            return web.json_response({"status": "ok", "database": "ok", "accounts": accounts, "onlineUsers": online_users})
        except sqlite3.Error:
            return web.json_response({"status": "error", "database": "error"}, status=503)

    async def me(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        return web.json_response({"user": public_account(account)})

    async def register(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid JSON.")
        username = str(data.get("username", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        if not USERNAME_PATTERN.fullmatch(username):
            raise web.HTTPBadRequest(text="Username must be 3-32 letters, numbers, or underscores.")
        if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise web.HTTPBadRequest(text="Enter a valid email address.")
        if len(password) < 8 or len(password) > 1024:
            raise web.HTTPBadRequest(text="Password must be at least 8 characters.")
        account_id = str(uuid.uuid4())
        try:
            with self.connect_db() as db:
                db.execute(
                    "INSERT INTO accounts(id, username, email, password_hash, created_at) VALUES(?, ?, ?, ?, ?)",
                    (account_id, username, email, hash_password(password), now_iso()),
                )
                account = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        except sqlite3.IntegrityError:
            raise web.HTTPConflict(text="That username or email is already in use.")
        response = self.create_session_response(request, account)
        response.set_status(201)
        return response

    async def login(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid JSON.")
        login_name = str(data.get("login", "")).strip()
        password = str(data.get("password", ""))
        with self.connect_db() as db:
            account = db.execute(
                "SELECT * FROM accounts WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE",
                (login_name, login_name),
            ).fetchone()
        if account is None or not verify_password(password, account["password_hash"]):
            raise web.HTTPUnauthorized(text="Incorrect username/email or password.")
        if account["banned"]:
            raise web.HTTPForbidden(text="This account is banned.")
        return self.create_session_response(request, account)

    def create_session_response(self, request: web.Request, account: sqlite3.Row) -> web.Response:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        expiry = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
        with self.connect_db() as db:
            db.execute("DELETE FROM sessions WHERE account_id=?", (account["id"],))
            db.execute("INSERT INTO sessions(token_hash, account_id, expires_at) VALUES(?, ?, ?)", (token_hash, account["id"], expiry.isoformat(timespec="seconds")))
        response = web.json_response({"user": public_account(account)})
        forwarded_proto = self._request_forwarded_proto(request)
        response.set_cookie(COOKIE_NAME, token, httponly=True, secure=forwarded_proto == "https", samesite="Strict", max_age=SESSION_DAYS * 86400, path="/")
        return response

    async def logout(self, request: web.Request) -> web.Response:
        token = request.cookies.get(COOKIE_NAME)
        if token:
            with self.connect_db() as db:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest(),))
        response = web.json_response({"ok": True})
        response.del_cookie(COOKIE_NAME, path="/")
        return response

    async def list_accounts(self, request: web.Request) -> web.Response:
        await self.require_owner(request)
        with self.connect_db() as db:
            rows = db.execute("SELECT * FROM accounts ORDER BY role='owner' DESC, created_at").fetchall()
        return web.json_response({"accounts": [public_account(row) for row in rows]})

    async def moderate_account(self, request: web.Request) -> web.Response:
        await self.require_owner(request)
        account_id = request.match_info["account_id"]
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid JSON.")
        banned = bool(data.get("banned"))
        reason = str(data.get("reason", ""))[:240]
        with self.connect_db() as db:
            target = db.execute("SELECT role FROM accounts WHERE id=?", (account_id,)).fetchone()
            if target is None:
                raise web.HTTPNotFound(text="Account not found.")
            if target["role"] == "owner" and banned:
                raise web.HTTPForbidden(text="The owner account cannot be banned.")
            db.execute("UPDATE accounts SET banned=?, ban_reason=? WHERE id=?", (int(banned), reason if banned else "", account_id))
            if banned:
                db.execute("DELETE FROM sessions WHERE account_id=?", (account_id,))
            updated = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        return web.json_response({"account": public_account(updated)})

    async def friends(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        with self.connect_db() as db:
            friend_rows = db.execute(
                "SELECT a.* FROM friendships f JOIN accounts a ON a.id=CASE WHEN f.user_a=? THEN f.user_b ELSE f.user_a END WHERE f.user_a=? OR f.user_b=? ORDER BY a.username COLLATE NOCASE",
                (account["id"], account["id"], account["id"]),
            ).fetchall()
            incoming = db.execute("SELECT r.id AS request_id, r.created_at, a.* FROM friend_requests r JOIN accounts a ON a.id=r.sender_id WHERE r.recipient_id=? ORDER BY r.created_at", (account["id"],)).fetchall()
            outgoing = db.execute("SELECT r.id AS request_id, r.created_at, a.* FROM friend_requests r JOIN accounts a ON a.id=r.recipient_id WHERE r.sender_id=? ORDER BY r.created_at", (account["id"],)).fetchall()
        return web.json_response({
            "friends": [public_account(row) for row in friend_rows],
            "incoming": [{"id": row["request_id"], "createdAt": row["created_at"], "user": public_account(row)} for row in incoming],
            "outgoing": [{"id": row["request_id"], "createdAt": row["created_at"], "user": public_account(row)} for row in outgoing],
        })

    async def send_friend_request(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid JSON.")
        username = str(data.get("username", "")).strip().lstrip("@")
        with self.connect_db() as db:
            target = db.execute("SELECT * FROM accounts WHERE username=? COLLATE NOCASE", (username,)).fetchone()
            if target is None:
                raise web.HTTPNotFound(text="No account with that username exists.")
            if target["id"] == account["id"]:
                raise web.HTTPBadRequest(text="You cannot add yourself.")
            if target["banned"]:
                raise web.HTTPNotFound(text="Account unavailable.")
            pair = tuple(sorted((account["id"], target["id"])))
            if db.execute("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?", pair).fetchone():
                raise web.HTTPConflict(text="You are already friends.")
            reverse = db.execute("SELECT id FROM friend_requests WHERE sender_id=? AND recipient_id=?", (target["id"], account["id"])).fetchone()
            if reverse:
                raise web.HTTPConflict(text="They already sent you a request. Accept it from your requests.")
            request_id = str(uuid.uuid4())
            try:
                db.execute("INSERT INTO friend_requests(id, sender_id, recipient_id, created_at) VALUES(?, ?, ?, ?)", (request_id, account["id"], target["id"], now_iso()))
            except sqlite3.IntegrityError:
                raise web.HTTPConflict(text="A request is already pending.")
        await self.broadcast([target["id"]], {"type": "friend_request", "fromId": account["id"]})
        return web.json_response({"ok": True, "requestId": request_id}, status=201)

    async def resolve_friend_request(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        request_id = request.match_info["request_id"]
        accept = request.match_info["decision"] == "accept"
        with self.connect_db() as db:
            pending = db.execute("SELECT * FROM friend_requests WHERE id=? AND recipient_id=?", (request_id, account["id"])).fetchone()
            if pending is None:
                raise web.HTTPNotFound(text="Friend request not found.")
            if accept:
                pair = tuple(sorted((pending["sender_id"], pending["recipient_id"])))
                db.execute("INSERT OR IGNORE INTO friendships(user_a, user_b, created_at) VALUES(?, ?, ?)", (*pair, now_iso()))
            db.execute("DELETE FROM friend_requests WHERE id=?", (request_id,))
        await self.broadcast([pending["sender_id"], account["id"]], {"type": "friend_request_resolved", "accepted": accept})
        return web.json_response({"ok": True, "accepted": accept})

    async def list_dm_messages(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        friend_id = request.match_info["friend_id"]
        pair = tuple(sorted((account["id"], friend_id)))
        with self.connect_db() as db:
            if not db.execute("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?", pair).fetchone():
                raise web.HTTPForbidden(text="Accept the friend request before messaging.")
            rows = db.execute(
                "SELECT m.*, a.username FROM direct_messages m JOIN accounts a ON a.id=m.sender_id WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?) ORDER BY created_at DESC LIMIT 100",
                (account["id"], friend_id, friend_id, account["id"]),
            ).fetchall()
        messages = [{"id": row["id"], "senderId": row["sender_id"], "username": row["username"], "text": row["text"], "createdAt": row["created_at"]} for row in reversed(rows)]
        return web.json_response({"messages": messages})

    async def send_dm(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        friend_id = request.match_info["friend_id"]
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid JSON.")
        text = str(data.get("text", "")).strip()
        if not text or len(text) > 2000:
            raise web.HTTPBadRequest(text="Message must be 1-2000 characters.")
        pair = tuple(sorted((account["id"], friend_id)))
        message_id = str(uuid.uuid4())
        created_at = now_iso()
        with self.connect_db() as db:
            if not db.execute("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?", pair).fetchone():
                raise web.HTTPForbidden(text="Accept the friend request before messaging.")
            recipient = db.execute("SELECT id FROM accounts WHERE id=? AND banned=0", (friend_id,)).fetchone()
            if recipient is None:
                raise web.HTTPNotFound(text="Friend is unavailable.")
            db.execute("INSERT INTO direct_messages(id, sender_id, recipient_id, text, created_at) VALUES(?, ?, ?, ?, ?)", (message_id, account["id"], friend_id, text, created_at))
        event = {"type": "dm_message", "friendId": account["id"], "message": {"id": message_id, "senderId": account["id"], "username": account["username"], "text": text, "createdAt": created_at}}
        await self.broadcast([friend_id], event)
        return web.json_response({"message": event["message"]}, status=201)

    async def discover_servers(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        with self.connect_db() as db:
            rows = db.execute(
                "SELECT s.*, a.username AS owner_name, (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id=s.id) AS member_count, EXISTS(SELECT 1 FROM server_members sm WHERE sm.server_id=s.id AND sm.account_id=?) AS joined FROM servers s JOIN accounts a ON a.id=s.owner_id ORDER BY s.created_at DESC LIMIT 100",
                (account["id"],),
            ).fetchall()
        return web.json_response({"servers": [self.server_json(row) for row in rows]})

    @staticmethod
    def server_json(row: sqlite3.Row) -> dict[str, Any]:
        return {"id": row["id"], "name": row["name"], "ownerUsername": row["owner_name"], "members": row["member_count"], "joined": bool(row["joined"])}

    async def list_servers(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        with self.connect_db() as db:
            rows = db.execute(
                "SELECT s.*, a.username AS owner_name, (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id=s.id) AS member_count, 1 AS joined FROM servers s JOIN server_members mine ON mine.server_id=s.id JOIN accounts a ON a.id=s.owner_id WHERE mine.account_id=? ORDER BY s.created_at",
                (account["id"],),
            ).fetchall()
        return web.json_response({"servers": [self.server_json(row) for row in rows]})

    async def create_server(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid JSON.")
        name = str(data.get("name", "")).strip()[:48]
        if not name:
            raise web.HTTPBadRequest(text="Enter a server name.")
        server_id = str(uuid.uuid4())
        channel_id = str(uuid.uuid4())
        created_at = now_iso()
        with self.connect_db() as db:
            db.execute("INSERT INTO servers(id, name, owner_id, created_at) VALUES(?, ?, ?, ?)", (server_id, name, account["id"], created_at))
            db.execute("INSERT INTO server_members(server_id, account_id, role, joined_at) VALUES(?, ?, 'owner', ?)", (server_id, account["id"], created_at))
            db.execute("INSERT INTO channels(id, server_id, name, created_at) VALUES(?, ?, 'general', ?)", (channel_id, server_id, created_at))
        return web.json_response({"server": {"id": server_id, "name": name, "ownerUsername": account["username"], "members": 1, "joined": True}, "channels": [{"id": channel_id, "name": "general"}]}, status=201)

    async def join_server(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        server_id = request.match_info["server_id"]
        with self.connect_db() as db:
            server = db.execute("SELECT id FROM servers WHERE id=?", (server_id,)).fetchone()
            if server is None:
                raise web.HTTPNotFound(text="Server not found.")
            db.execute("INSERT OR IGNORE INTO server_members(server_id, account_id, joined_at) VALUES(?, ?, ?)", (server_id, account["id"], now_iso()))
            channels = db.execute("SELECT id, name FROM channels WHERE server_id=? ORDER BY created_at", (server_id,)).fetchall()
        with self.connect_db() as db:
            member_ids = [row["account_id"] for row in db.execute("SELECT account_id FROM server_members WHERE server_id=?", (server_id,)).fetchall()]
        await self.broadcast(member_ids, {"type": "server_members_changed", "serverId": server_id})
        return web.json_response({"channels": [dict(row) for row in channels]})

    async def list_channels(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        server_id = request.match_info["server_id"]
        with self.connect_db() as db:
            if not db.execute("SELECT 1 FROM server_members WHERE server_id=? AND account_id=?", (server_id, account["id"])).fetchone():
                raise web.HTTPForbidden(text="Join the server to view its channels.")
            channels = db.execute("SELECT id, name FROM channels WHERE server_id=? ORDER BY created_at", (server_id,)).fetchall()
        return web.json_response({"channels": [dict(row) for row in channels]})

    async def create_channel(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        server_id = request.match_info["server_id"]
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid JSON.")
        name = re.sub(r"[^a-z0-9-]+", "-", str(data.get("name", "")).strip().lower()).strip("-")[:32]
        if not name:
            raise web.HTTPBadRequest(text="Enter a valid channel name.")
        channel_id = str(uuid.uuid4())
        try:
            with self.connect_db() as db:
                membership = db.execute("SELECT role FROM server_members WHERE server_id=? AND account_id=?", (server_id, account["id"])).fetchone()
                if membership is None or membership["role"] != "owner":
                    raise web.HTTPForbidden(text="Only the server owner can create channels.")
                db.execute("INSERT INTO channels(id, server_id, name, created_at) VALUES(?, ?, ?, ?)", (channel_id, server_id, name, now_iso()))
        except sqlite3.IntegrityError:
            raise web.HTTPConflict(text="That channel already exists.")
        return web.json_response({"channel": {"id": channel_id, "name": name}}, status=201)

    async def channel_messages(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        channel_id = request.match_info["channel_id"]
        with self.connect_db() as db:
            member = db.execute("SELECT 1 FROM channels c JOIN server_members sm ON sm.server_id=c.server_id WHERE c.id=? AND sm.account_id=?", (channel_id, account["id"])).fetchone()
            if member is None:
                raise web.HTTPForbidden(text="Join the server to read this channel.")
            rows = db.execute("SELECT m.id, m.sender_id, a.username, m.text, m.created_at FROM channel_messages m JOIN accounts a ON a.id=m.sender_id WHERE m.channel_id=? ORDER BY m.created_at DESC LIMIT 100", (channel_id,)).fetchall()
        messages = [{"id": row["id"], "senderId": row["sender_id"], "username": row["username"], "text": row["text"], "createdAt": row["created_at"]} for row in reversed(rows)]
        return web.json_response({"messages": messages})

    async def send_channel_message(self, request: web.Request) -> web.Response:
        account = await self.require_user(request)
        channel_id = request.match_info["channel_id"]
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid JSON.")
        text = str(data.get("text", "")).strip()
        if not text or len(text) > 2000:
            raise web.HTTPBadRequest(text="Message must be 1-2000 characters.")
        message_id = str(uuid.uuid4())
        created_at = now_iso()
        with self.connect_db() as db:
            members = db.execute("SELECT sm.account_id FROM channels c JOIN server_members sm ON sm.server_id=c.server_id WHERE c.id=?", (channel_id,)).fetchall()
            if not members or account["id"] not in {row["account_id"] for row in members}:
                raise web.HTTPForbidden(text="Join the server to send messages.")
            db.execute("INSERT INTO channel_messages(id, channel_id, sender_id, text, created_at) VALUES(?, ?, ?, ?, ?)", (message_id, channel_id, account["id"], text, created_at))
        message = {"id": message_id, "senderId": account["id"], "username": account["username"], "text": text, "createdAt": created_at}
        with self.connect_db() as db:
            server_row = db.execute("SELECT server_id FROM channels WHERE id=?", (channel_id,)).fetchone()
        await self.broadcast([row["account_id"] for row in members], {"type": "channel_message", "channelId": channel_id, "serverId": server_row["server_id"], "message": message})
        return web.json_response({"message": message}, status=201)

    async def websocket(self, request: web.Request) -> web.StreamResponse:
        account = await self.require_user(request)
        socket = web.WebSocketResponse(heartbeat=25, max_msg_size=4096)
        await socket.prepare(request)
        self.sockets.setdefault(account["id"], set()).add(socket)
        await socket.send_json({"type": "connected"})
        try:
            async for message in socket:
                if message.type == WSMsgType.ERROR:
                    break
        finally:
            user_sockets = self.sockets.get(account["id"], set())
            user_sockets.discard(socket)
            if not user_sockets:
                self.sockets.pop(account["id"], None)
        return socket

    async def static_file(self, request: web.Request) -> web.StreamResponse:
        requested = request.match_info.get("path", "") or "index.html"
        allowed_files = {
            "index.html", "login.html", "account-admin.html", "wembux-users.js",
            "manifest.webmanifest", "build-info.json", "wembux.ico", "wembux-192.png", "wembux-512.png",
        }
        if requested not in allowed_files:
            raise web.HTTPNotFound()
        path = (APP_DIR / requested).resolve()
        if APP_DIR.resolve() not in path.parents or not path.is_file():
            raise web.HTTPNotFound()
        return web.FileResponse(path, headers={"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "strict-origin-when-cross-origin"})

    @staticmethod
    def _request_forwarded_proto(request: web.Request) -> str:
        return request.headers.get("X-Forwarded-Proto", request.scheme).split(",", 1)[0].strip().lower()

    def create_app(self) -> web.Application:
        app = web.Application(client_max_size=1024 * 1024)
        app.router.add_get("/api/health", self.health)
        app.router.add_get("/api/me", self.me)
        app.router.add_post("/api/register", self.register)
        app.router.add_post("/api/login", self.login)
        app.router.add_post("/api/logout", self.logout)
        app.router.add_get("/api/admin/accounts", self.list_accounts)
        app.router.add_patch("/api/admin/accounts/{account_id}", self.moderate_account)
        app.router.add_get("/api/friends", self.friends)
        app.router.add_post("/api/friends/requests", self.send_friend_request)
        app.router.add_post("/api/friends/requests/{request_id}/{decision:accept|decline}", self.resolve_friend_request)
        app.router.add_get("/api/dms/{friend_id}/messages", self.list_dm_messages)
        app.router.add_post("/api/dms/{friend_id}/messages", self.send_dm)
        app.router.add_get("/api/servers", self.list_servers)
        app.router.add_get("/api/servers/discover", self.discover_servers)
        app.router.add_post("/api/servers", self.create_server)
        app.router.add_post("/api/servers/{server_id}/join", self.join_server)
        app.router.add_get("/api/servers/{server_id}/channels", self.list_channels)
        app.router.add_post("/api/servers/{server_id}/channels", self.create_channel)
        app.router.add_get("/api/channels/{channel_id}/messages", self.channel_messages)
        app.router.add_post("/api/channels/{channel_id}/messages", self.send_channel_message)
        app.router.add_get("/api/ws", self.websocket)
        app.router.add_get("/{path:.*}", self.static_file)
        return app


def default_data_dir() -> Path:
    configured = os.environ.get("WEMBUX_DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "Wembux" / "data"
    return APP_DIR / "data"


def read_password_masked(prompt: str) -> str:
    if os.name != "nt":
        return getpass(prompt)

    import msvcrt

    print(prompt, end="", flush=True)
    password: list[str] = []
    while True:
        character = msvcrt.getwch()
        if character in ("\r", "\n"):
            print()
            return "".join(password)
        if character == "\x03":
            raise KeyboardInterrupt
        if character in ("\x00", "\xe0"):
            msvcrt.getwch()
            continue
        if character == "\b":
            if password:
                password.pop()
                print("\b \b", end="", flush=True)
            continue
        if character.isprintable():
            password.append(character)
            print("*", end="", flush=True)


def setup_owner(db_path: Path) -> None:
    with open_db(db_path):
        pass
    with sqlite3.connect(db_path) as db:
        exists = db.execute("SELECT 1 FROM accounts WHERE role='owner' LIMIT 1").fetchone()
    if exists:
        print("Wembux owner is already configured.")
        return
    print("First start: create the Wembux owner account. Password input is masked with asterisks.")
    username = input("Owner username [FRIGSS_FINDER]: ").strip() or "FRIGSS_FINDER"
    while True:
        password = read_password_masked("Owner password (8+ characters): ")
        confirmation = read_password_masked("Confirm owner password: ")
        if password != confirmation:
            print("Passwords did not match. Try again.")
            continue
        try:
            created = initialize_owner(db_path, username, password)
            if created:
                print("Owner account created.")
            break
        except ValueError as error:
            print(error)


def main() -> int:
    parser = argparse.ArgumentParser(description="Wembux online chat server")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--setup-owner", action="store_true", help="Create the initial owner account")
    parser.add_argument("--host", default=os.environ.get("WEMBUX_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("WEMBUX_PORT", "8765")))
    args = parser.parse_args()
    db_path = args.data_dir / "wembux.sqlite3"
    if args.setup_owner:
        setup_owner(db_path)
        return 0
    with open_db(db_path) as db:
        owner_exists = db.execute("SELECT 1 FROM accounts WHERE role='owner' LIMIT 1").fetchone()
    if not owner_exists:
        print("No Wembux owner exists. Run Start-Wembux-Server.bat to complete first-time setup.", file=sys.stderr)
        return 2
    service = WembuxService(db_path)
    print(f"Wembux server listening on http://{args.host}:{args.port}")
    web.run_app(service.create_app(), host=args.host, port=args.port, print=None, access_log=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
