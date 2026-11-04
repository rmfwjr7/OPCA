from __future__ import annotations

import hashlib
import hmac
import base64
import json
import os
import re
import secrets
import sqlite3
import time
import shutil
from contextlib import contextmanager
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("OPCA_DB_PATH", BASE_DIR / "opca.sqlite3"))
HOST = os.environ.get("OPCA_HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
PORT = int(os.environ.get("PORT", os.environ.get("OPCA_PORT", "8000")))
SESSION_SECONDS = 60 * 60 * 24 * 30
PASSWORD_ITERATIONS = 310_000
MAX_BODY_BYTES = 1_000_000
MAX_PHOTO_BYTES = 5 * 1024 * 1024
MAX_PHOTO_REQUEST_BYTES = (MAX_PHOTO_BYTES * 4 // 3) + 200_000
PRIVATE_UPLOAD_DIR = Path(os.environ.get("OPCA_PRIVATE_UPLOAD_DIR", BASE_DIR / "opca-data" / "pending"))
PUBLIC_CARD_DIR = Path(os.environ.get("OPCA_CARD_DIR", BASE_DIR / "cards"))
ADMIN_USERNAME = "찍찍이".casefold()
USERNAME_RE = re.compile(r"^[A-Za-z0-9가-힣_.-]{3,24}$")
CARD_IMAGE_PATH_RE = re.compile(r"^/cards/[a-f0-9]{32}\.(?:jpg|png|webp)$")
NICKNAME_ADJECTIVES = ["데굴데굴", "냠냠쩝쩝", "우당당탕", "세상단단", "말랑폭신", "빙글빙글", "반짝반짝"]
HERO_NAMES = ["준킹볼", "디바", "겐지", "메르시", "루시우", "키리코", "아나", "라인하르트", "트레이서", "솜브라", "위도우"]


class ForbiddenError(PermissionError):
    pass


def connect_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def database():
    connection = connect_db()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    with database() as connection:
        connection.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                nickname TEXT NOT NULL UNIQUE,
                chat_notifications INTEGER NOT NULL DEFAULT 1,
                favorite_notifications INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS listings (
                id TEXT PRIMARY KEY,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK(kind IN ('판매', '구매', '교환')),
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS listings_created_at_idx ON listings(created_at DESC);
            CREATE TABLE IF NOT EXISTS favorites (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                listing_id TEXT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                PRIMARY KEY(user_id, listing_id)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                listing_id TEXT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
                sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS photo_submissions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                metadata TEXT NOT NULL,
                private_path TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
                reviewer_note TEXT NOT NULL DEFAULT '',
                submitted_at TEXT NOT NULL,
                reviewed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS photo_submissions_status_idx ON photo_submissions(status, submitted_at);
            CREATE TABLE IF NOT EXISTS card_images (
                card_key TEXT PRIMARY KEY,
                metadata TEXT NOT NULL,
                public_path TEXT NOT NULL,
                submission_id TEXT NOT NULL REFERENCES photo_submissions(id),
                published_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS messages_thread_idx ON messages(listing_id, id);
            """
        )
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_password_hash(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    actual_salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), actual_salt, PASSWORD_ITERATIONS)
    return actual_salt, derived


def nickname_candidate(number: int) -> str:
    if number == 105:
        return "데굴데굴 준킹볼 105"
    adjective = secrets.choice(NICKNAME_ADJECTIVES)
    hero = secrets.choice(HERO_NAMES)
    return f"{adjective} {hero} {number}"


def get_card_metadata(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("포카 정보가 올바르지 않습니다.")
    metadata = {
        "year": str(value.get("year", "")),
        "stage": str(value.get("stage", "")),
        "team": str(value.get("team", "")).strip(),
        "player": str(value.get("player", "")).strip(),
        "cardType": str(value.get("cardType", "")),
        "title": str(value.get("title", "")).strip(),
    }
    if metadata["year"] not in {"2025", "2026"}:
        raise ValueError("연도는 2025년 또는 2026년을 선택해 주세요.")
    if metadata["stage"] not in {"stage1", "stage2", "stage3"}:
        raise ValueError("스테이지를 다시 선택해 주세요.")
    if not metadata["team"] or len(metadata["team"]) > 80 or not metadata["player"] or len(metadata["player"]) > 60:
        raise ValueError("구단과 선수 정보를 확인해 주세요.")
    if metadata["cardType"] not in {"정규 시즌", "기타"}:
        raise ValueError("카드 종류를 선택해 주세요.")
    if metadata["cardType"] == "기타" and not metadata["title"]:
        raise ValueError("기타 포카 이름을 입력해 주세요.")
    if len(metadata["title"]) > 120:
        raise ValueError("포카 이름은 120자 이하로 입력해 주세요.")
    return metadata


def card_metadata_key(metadata: dict) -> str:
    fields = [metadata["year"], metadata["stage"], metadata["team"], metadata["player"], metadata["cardType"], metadata["title"] if metadata["cardType"] == "기타" else ""]
    return json.dumps(fields, ensure_ascii=False, separators=(",", ":"))


def decode_photo_data(data_url: object) -> tuple[bytes, str, str]:
    if not isinstance(data_url, str) or "," not in data_url:
        raise ValueError("이미지 파일을 선택해 주세요.")
    header, encoded = data_url.split(",", 1)
    allowed = {"data:image/jpeg;base64": ("image/jpeg", "jpg"), "data:image/png;base64": ("image/png", "png"), "data:image/webp;base64": ("image/webp", "webp")}
    image_info = allowed.get(header.lower())
    if image_info is None:
        raise ValueError("JPG, PNG, WEBP 이미지만 등록할 수 있습니다.")
    try:
        image_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("이미지 데이터가 올바르지 않습니다.") from exc
    if not image_bytes or len(image_bytes) > MAX_PHOTO_BYTES:
        raise ValueError("사진은 5MB 이하로 등록해 주세요.")
    mime_type, extension = image_info
    valid_signature = (
        (mime_type == "image/jpeg" and image_bytes.startswith(b"\xff\xd8\xff"))
        or (mime_type == "image/png" and image_bytes.startswith(b"\x89PNG\r\n\x1a\n"))
        or (mime_type == "image/webp" and image_bytes.startswith(b"RIFF") and image_bytes[8:12] == b"WEBP")
    )
    if not valid_signature:
        raise ValueError("파일 내용이 이미지 형식과 일치하지 않습니다.")
    return image_bytes, mime_type, extension


def create_session(connection: sqlite3.Connection, user_id: int) -> str:
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("ascii")).digest()
    connection.execute(
        "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        (token_hash, user_id, int(time.time()) + SESSION_SECONDS),
    )
    return raw_token


class OpcaHandler(SimpleHTTPRequestHandler):
    server_version = "OPCA/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def send_json(self, status: int, data: dict, headers: list[tuple[str, str]] | None = None) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, max_bytes: int = MAX_BODY_BYTES) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("요청 형식이 올바르지 않습니다.") from exc
        if length < 1 or length > max_bytes:
            raise ValueError("요청 크기가 올바르지 않습니다.")
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("JSON 형식이 올바르지 않습니다.") from exc
        if not isinstance(value, dict):
            raise ValueError("요청 형식이 올바르지 않습니다.")
        return value

    def get_user(self, connection: sqlite3.Connection) -> sqlite3.Row | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("opca_session")
        if morsel is None:
            return None
        try:
            token_hash = hashlib.sha256(morsel.value.encode("ascii")).digest()
        except UnicodeEncodeError:
            return None
        row = connection.execute(
            """SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id
               WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
            (token_hash, int(time.time())),
        ).fetchone()
        return row

    def require_user(self, connection: sqlite3.Connection) -> sqlite3.Row:
        user = self.get_user(connection)
        if user is None:
            raise PermissionError("로그인이 필요합니다.")
        return user

    def require_admin(self, connection: sqlite3.Connection) -> sqlite3.Row:
        user = self.require_user(connection)
        if not ADMIN_USERNAME or user["username"].casefold() != ADMIN_USERNAME:
            raise ForbiddenError("관리자만 접근할 수 있습니다.")
        return user

    def send_file_bytes(self, status: int, content: bytes, content_type: str, cache_control: str = "no-store") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", cache_control)
        self.end_headers()
        self.wfile.write(content)

    def check_origin(self) -> None:
        origin = self.headers.get("Origin")
        if not origin:
            return
        parsed = urlparse(origin)
        request_host = self.headers.get("Host", "")
        if parsed.netloc.lower() != request_host.lower():
            raise PermissionError("요청 출처를 확인할 수 없습니다.")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        try:
            with database() as connection:
                if path == "/api/session":
                    user = self.get_user(connection)
                    if user is None:
                        self.send_json(HTTPStatus.OK, {"user": None})
                    else:
                        self.send_json(HTTPStatus.OK, {"user": self.public_user(user)})
                    return
                if path == "/api/listings":
                    rows = connection.execute(
                        "SELECT listings.*, users.nickname FROM listings JOIN users ON users.id = listings.owner_id ORDER BY listings.created_at DESC"
                    ).fetchall()
                    self.send_json(HTTPStatus.OK, {"items": [self.public_listing(row) for row in rows]})
                    return
                if path == "/api/card-images":
                    rows = connection.execute("SELECT metadata, public_path, published_at FROM card_images").fetchall()
                    items = []
                    for row in rows:
                        metadata = json.loads(row["metadata"])
                        metadata.update({"url": row["public_path"], "publishedAt": row["published_at"]})
                        items.append(metadata)
                    self.send_json(HTTPStatus.OK, {"items": items})
                    return
                if path == "/api/photo-submissions":
                    user = self.require_user(connection)
                    rows = connection.execute(
                        "SELECT id, metadata, status, reviewer_note, submitted_at, reviewed_at FROM photo_submissions WHERE user_id = ? ORDER BY submitted_at DESC",
                        (user["id"],),
                    ).fetchall()
                    self.send_json(HTTPStatus.OK, {"items": [self.public_photo_submission(row) for row in rows]})
                    return
                if path == "/api/admin/photo-submissions":
                    self.require_admin(connection)
                    rows = connection.execute(
                        """SELECT photo_submissions.*, users.nickname FROM photo_submissions
                           JOIN users ON users.id = photo_submissions.user_id WHERE status = 'pending'
                           ORDER BY submitted_at ASC"""
                    ).fetchall()
                    items = []
                    for row in rows:
                        item = self.public_photo_submission(row)
                        item["submitter"] = row["nickname"]
                        item["imageUrl"] = f"/api/admin/photo-submissions/{item['id']}/image"
                        items.append(item)
                    self.send_json(HTTPStatus.OK, {"items": items})
                    return
                admin_image_match = re.fullmatch(r"/api/admin/photo-submissions/([a-f0-9]{32})/image", path)
                if admin_image_match:
                    self.require_admin(connection)
                    row = connection.execute("SELECT private_path, mime_type FROM photo_submissions WHERE id = ?", (admin_image_match.group(1),)).fetchone()
                    if row is None:
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "사진 제보를 찾을 수 없습니다."})
                        return
                    image_path = Path(row["private_path"])
                    if not image_path.is_file():
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "사진 파일을 찾을 수 없습니다."})
                        return
                    self.send_file_bytes(HTTPStatus.OK, image_path.read_bytes(), row["mime_type"])
                    return
                if path == "/api/my/listings":
                    user = self.require_user(connection)
                    rows = connection.execute(
                        "SELECT listings.*, users.nickname FROM listings JOIN users ON users.id = listings.owner_id WHERE listings.owner_id = ? ORDER BY listings.created_at DESC",
                        (user["id"],),
                    ).fetchall()
                    self.send_json(HTTPStatus.OK, {"items": [self.public_listing(row) for row in rows]})
                    return
                if path == "/api/favorites":
                    user = self.require_user(connection)
                    rows = connection.execute(
                        """SELECT listings.*, users.nickname FROM favorites
                           JOIN listings ON listings.id = favorites.listing_id
                           JOIN users ON users.id = listings.owner_id
                           WHERE favorites.user_id = ? ORDER BY favorites.created_at DESC""",
                        (user["id"],),
                    ).fetchall()
                    ids = [row["id"] for row in rows]
                    self.send_json(HTTPStatus.OK, {"ids": ids, "items": [self.public_listing(row) for row in rows]})
                    return
                if path == "/api/chats":
                    user = self.require_user(connection)
                    rows = connection.execute(
                        """SELECT m.listing_id, MAX(m.id) AS last_id FROM messages m
                           WHERE m.sender_id = ? OR m.recipient_id = ? GROUP BY m.listing_id
                           ORDER BY last_id DESC""",
                        (user["id"], user["id"]),
                    ).fetchall()
                    chats = []
                    for row in rows:
                        last = connection.execute(
                            """SELECT messages.*, sender.nickname AS sender_nickname, recipient.nickname AS recipient_nickname
                               FROM messages JOIN users sender ON sender.id = messages.sender_id
                               JOIN users recipient ON recipient.id = messages.recipient_id WHERE messages.id = ?""",
                            (row["last_id"],),
                        ).fetchone()
                        listing_row = connection.execute(
                            "SELECT listings.*, users.nickname FROM listings JOIN users ON users.id = listings.owner_id WHERE listings.id = ?",
                            (row["listing_id"],),
                        ).fetchone()
                        if listing_row is None:
                            continue
                        owner_id = listing_row["owner_id"]
                        other_user_id = last["recipient_id"] if last["sender_id"] == user["id"] else last["sender_id"]
                        other_name = last["recipient_nickname"] if last["sender_id"] == user["id"] else last["sender_nickname"]
                        if owner_id != user["id"]:
                            other_name = listing_row["nickname"]
                        chats.append({
                            "listingId": row["listing_id"],
                            "listing": self.public_listing(listing_row),
                            "otherUserId": other_user_id,
                            "otherNickname": other_name,
                            "lastMessage": last["body"],
                            "updatedAt": last["created_at"],
                            "unread": 0,
                        })
                    self.send_json(HTTPStatus.OK, {"items": chats})
                    return
                if path.startswith("/api/chats/") and path.endswith("/messages"):
                    user = self.require_user(connection)
                    listing_id = path.removeprefix("/api/chats/").removesuffix("/messages").strip("/")
                    self.authorize_thread(connection, user["id"], listing_id, allow_start=True)
                    rows = connection.execute(
                        """SELECT messages.*, users.nickname AS sender_nickname FROM messages
                                    JOIN users ON users.id = messages.sender_id
                                    WHERE messages.listing_id = ? AND (messages.sender_id = ? OR messages.recipient_id = ?)
                                    ORDER BY messages.id""",
                                (listing_id, user["id"], user["id"]),
                    ).fetchall()
                    self.send_json(HTTPStatus.OK, {"items": [self.public_message(row) for row in rows]})
                    return
                if path.startswith("/api/settings"):
                    user = self.require_user(connection)
                    self.send_json(HTTPStatus.OK, {"chatNotifications": bool(user["chat_notifications"]), "favoriteNotifications": bool(user["favorite_notifications"])})
                    return
        except ForbiddenError as exc:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
            return
        except PermissionError as exc:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
            return
        except Exception as exc:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "서버에서 요청을 처리하지 못했습니다."})
            print(f"API GET error: {type(exc).__name__}: {exc}")
            return
        if path.startswith("/api/"):
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "요청한 API를 찾을 수 없습니다."})
            return
        if path in {"/", "/index.html"}:
            self.path = "/index.html"
            super().do_GET()
            return
        if path == "/roster-data.js":
            super().do_GET()
            return
        if CARD_IMAGE_PATH_RE.fullmatch(path):
            image_path = PUBLIC_CARD_DIR / Path(path).name
            if image_path.is_file():
                mime_type = {"jpg": "image/jpeg", "png": "image/png", "webp": "image/webp"}[image_path.suffix.lower().lstrip(".")]
                self.send_file_bytes(HTTPStatus.OK, image_path.read_bytes(), mime_type, "public, max-age=86400")
                return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_HEAD(self) -> None:
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            self.path = "/index.html"
            super().do_HEAD()
            return
        if path == "/roster-data.js":
            super().do_HEAD()
            return
        if CARD_IMAGE_PATH_RE.fullmatch(path):
            image_path = PUBLIC_CARD_DIR / Path(path).name
            if image_path.is_file():
                mime_type = {"jpg": "image/jpeg", "png": "image/png", "webp": "image/webp"}[image_path.suffix.lower().lstrip(".")]
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", mime_type)
                self.send_header("Content-Length", str(image_path.stat().st_size))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = unquote(urlparse(self.path).path)
        try:
            self.check_origin()
            body = self.read_json(MAX_PHOTO_REQUEST_BYTES if path == "/api/photo-submissions" else MAX_BODY_BYTES)
            with database() as connection:
                if path == "/api/auth/register":
                    username = str(body.get("username", "")).strip()
                    password = str(body.get("password", ""))
                    if not USERNAME_RE.fullmatch(username):
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "아이디는 한글, 영문, 숫자, 점, 밑줄, 하이픈으로 3~24자 입력해 주세요."})
                        return
                    if len(password) < 8 or len(password) > 256:
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "비밀번호는 8자 이상 256자 이하로 입력해 주세요."})
                        return
                    if connection.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone():
                        self.send_json(HTTPStatus.CONFLICT, {"error": "이미 사용 중인 아이디입니다."})
                        return
                    nickname = None
                    for number in [105, *secrets.SystemRandom().sample(range(10, 100), 90)]:
                        candidate = nickname_candidate(number)
                        if not connection.execute("SELECT 1 FROM users WHERE nickname = ?", (candidate,)).fetchone():
                            nickname = candidate
                            break
                    if nickname is None:
                        self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "익명 닉네임을 생성하지 못했습니다."})
                        return
                    salt, password_hash = make_password_hash(password)
                    cursor = connection.execute(
                        """INSERT INTO users(username, password_salt, password_hash, nickname, created_at)
                           VALUES (?, ?, ?, ?, ?)""",
                        (username, salt, password_hash, nickname, now_iso()),
                    )
                    user = connection.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
                    token = create_session(connection, user["id"])
                    self.send_json(HTTPStatus.CREATED, {"user": self.public_user(user)}, [self.session_cookie(token)])
                    return
                if path == "/api/auth/login":
                    username = str(body.get("username", "")).strip()
                    password = str(body.get("password", ""))
                    if len(password) > 256:
                        self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "아이디 또는 비밀번호를 확인해 주세요."})
                        return
                    user = connection.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
                    if user is None:
                        self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "아이디 또는 비밀번호를 확인해 주세요."})
                        return
                    _, candidate = make_password_hash(password, user["password_salt"])
                    if not hmac.compare_digest(candidate, user["password_hash"]):
                        self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "아이디 또는 비밀번호를 확인해 주세요."})
                        return
                    token = create_session(connection, user["id"])
                    self.send_json(HTTPStatus.OK, {"user": self.public_user(user)}, [self.session_cookie(token)])
                    return
                if path == "/api/auth/logout":
                    cookie = SimpleCookie(self.headers.get("Cookie", ""))
                    morsel = cookie.get("opca_session")
                    if morsel:
                        digest = hashlib.sha256(morsel.value.encode("ascii", errors="ignore")).digest()
                        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
                    self.send_json(HTTPStatus.OK, {"ok": True}, [("Set-Cookie", "opca_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")])
                    return
                if path == "/api/listings":
                    user = self.require_user(connection)
                    kind = body.get("kind")
                    if kind not in {"판매", "구매", "교환"}:
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "매물 종류가 올바르지 않습니다."})
                        return
                    payload = body.get("payload")
                    if not isinstance(payload, dict):
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "매물 내용이 올바르지 않습니다."})
                        return
                    listing_id = secrets.token_urlsafe(12)
                    payload = dict(payload)
                    payload.update({"id": listing_id, "kind": kind, "seller": user["nickname"]})
                    connection.execute(
                        "INSERT INTO listings(id, owner_id, kind, payload, created_at) VALUES (?, ?, ?, ?, ?)",
                        (listing_id, user["id"], kind, json.dumps(payload, ensure_ascii=False), now_iso()),
                    )
                    self.send_json(HTTPStatus.CREATED, {"item": payload})
                    return
                if path == "/api/photo-submissions":
                    user = self.require_user(connection)
                    metadata = get_card_metadata(body.get("metadata"))
                    image_bytes, mime_type, extension = decode_photo_data(body.get("imageData"))
                    submission_id = secrets.token_hex(16)
                    PRIVATE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                    private_path = PRIVATE_UPLOAD_DIR / f"{submission_id}.{extension}"
                    private_path.write_bytes(image_bytes)
                    try:
                        connection.execute(
                            """INSERT INTO photo_submissions(id, user_id, metadata, private_path, mime_type, submitted_at)
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (submission_id, user["id"], json.dumps(metadata, ensure_ascii=False), str(private_path), mime_type, now_iso()),
                        )
                    except Exception:
                        private_path.unlink(missing_ok=True)
                        raise
                    connection.commit()
                    self.send_json(HTTPStatus.CREATED, {"item": {"id": submission_id, "metadata": metadata, "status": "pending", "submittedAt": now_iso()}})
                    return
                review_match = re.fullmatch(r"/api/admin/photo-submissions/([a-f0-9]{32})/review", path)
                if review_match:
                    self.require_admin(connection)
                    submission_id = review_match.group(1)
                    decision = body.get("decision")
                    reviewer_note = str(body.get("note", "")).strip()[:500]
                    if decision not in {"approve", "reject"}:
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "승인 또는 반려를 선택해 주세요."})
                        return
                    submission = connection.execute("SELECT * FROM photo_submissions WHERE id = ?", (submission_id,)).fetchone()
                    if submission is None or submission["status"] != "pending":
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "검토 대기 중인 사진 제보를 찾을 수 없습니다."})
                        return
                    public_url = None
                    if decision == "approve":
                        metadata = json.loads(submission["metadata"])
                        card_key = card_metadata_key(metadata)
                        extension = Path(submission["private_path"]).suffix.lower().lstrip(".")
                        if extension not in {"jpg", "png", "webp"}:
                            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "저장된 이미지 형식이 올바르지 않습니다."})
                            return
                        PUBLIC_CARD_DIR.mkdir(parents=True, exist_ok=True)
                        filename = f"{submission_id}.{extension}"
                        destination = PUBLIC_CARD_DIR / filename
                        shutil.copyfile(submission["private_path"], destination)
                        public_url = f"/cards/{filename}"
                        connection.execute(
                            """INSERT INTO card_images(card_key, metadata, public_path, submission_id, published_at)
                               VALUES (?, ?, ?, ?, ?)
                               ON CONFLICT(card_key) DO UPDATE SET metadata=excluded.metadata,
                                 public_path=excluded.public_path, submission_id=excluded.submission_id,
                                 published_at=excluded.published_at""",
                            (card_key, submission["metadata"], public_url, submission_id, now_iso()),
                        )
                    status = "approved" if decision == "approve" else "rejected"
                    connection.execute(
                        "UPDATE photo_submissions SET status = ?, reviewer_note = ?, reviewed_at = ? WHERE id = ?",
                        (status, reviewer_note, now_iso(), submission_id),
                    )
                    if decision == "reject":
                        Path(submission["private_path"]).unlink(missing_ok=True)
                    connection.commit()
                    self.send_json(HTTPStatus.OK, {"id": submission_id, "status": status, "imageUrl": public_url})
                    return
                if path == "/api/favorites/toggle":
                    user = self.require_user(connection)
                    listing_id = str(body.get("listingId", ""))
                    if not connection.execute("SELECT 1 FROM listings WHERE id = ?", (listing_id,)).fetchone():
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "매물을 찾을 수 없습니다."})
                        return
                    existing = connection.execute("SELECT 1 FROM favorites WHERE user_id = ? AND listing_id = ?", (user["id"], listing_id)).fetchone()
                    if existing:
                        connection.execute("DELETE FROM favorites WHERE user_id = ? AND listing_id = ?", (user["id"], listing_id))
                        saved = False
                    else:
                        connection.execute("INSERT INTO favorites(user_id, listing_id, created_at) VALUES (?, ?, ?)", (user["id"], listing_id, now_iso()))
                        saved = True
                    self.send_json(HTTPStatus.OK, {"saved": saved})
                    return
                if path.startswith("/api/chats/") and path.endswith("/messages"):
                    user = self.require_user(connection)
                    listing_id = path.removeprefix("/api/chats/").removesuffix("/messages").strip("/")
                    listing = self.authorize_thread(connection, user["id"], listing_id, allow_start=True)
                    message = str(body.get("body", "")).strip()
                    if not message or len(message) > 4000:
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "메시지는 1~4000자로 입력해 주세요."})
                        return
                    recipient_id = listing["owner_id"] if listing["owner_id"] != user["id"] else body.get("recipientId")
                    if recipient_id is None or int(recipient_id) == user["id"]:
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "대화 상대를 확인할 수 없습니다."})
                        return
                    if listing["owner_id"] == user["id"]:
                        participant = connection.execute(
                            """SELECT 1 FROM messages WHERE listing_id = ? AND
                               ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)) LIMIT 1""",
                            (listing_id, user["id"], int(recipient_id), int(recipient_id), user["id"]),
                        ).fetchone()
                        if participant is None:
                            self.send_json(HTTPStatus.FORBIDDEN, {"error": "이 대화에 답장할 수 없습니다."})
                            return
                    participants = connection.execute("SELECT id FROM users WHERE id = ?", (int(recipient_id),)).fetchone()
                    if participants is None:
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "대화 상대를 찾을 수 없습니다."})
                        return
                    cursor = connection.execute(
                        "INSERT INTO messages(listing_id, sender_id, recipient_id, body, created_at) VALUES (?, ?, ?, ?, ?)",
                        (listing_id, user["id"], int(recipient_id), message, now_iso()),
                    )
                    row = connection.execute(
                        "SELECT messages.*, users.nickname AS sender_nickname FROM messages JOIN users ON users.id = messages.sender_id WHERE messages.id = ?",
                        (cursor.lastrowid,),
                    ).fetchone()
                    self.send_json(HTTPStatus.CREATED, {"item": self.public_message(row)})
                    return
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except ForbiddenError as exc:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
            return
        except PermissionError as exc:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
            return
        except Exception as exc:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "서버에서 요청을 처리하지 못했습니다."})
            print(f"API POST error: {type(exc).__name__}: {exc}")
            return
        if path.startswith("/api/"):
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "요청한 API를 찾을 수 없습니다."})
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_PATCH(self) -> None:
        path = unquote(urlparse(self.path).path)
        try:
            self.check_origin()
            body = self.read_json()
            if path != "/api/settings":
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "요청한 API를 찾을 수 없습니다."})
                return
            with database() as connection:
                user = self.require_user(connection)
                chat_notifications = int(bool(body.get("chatNotifications", user["chat_notifications"])))
                favorite_notifications = int(bool(body.get("favoriteNotifications", user["favorite_notifications"])))
                connection.execute(
                    "UPDATE users SET chat_notifications = ?, favorite_notifications = ? WHERE id = ?",
                    (chat_notifications, favorite_notifications, user["id"]),
                )
                self.send_json(HTTPStatus.OK, {"chatNotifications": bool(chat_notifications), "favoriteNotifications": bool(favorite_notifications)})
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except PermissionError as exc:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
        except Exception as exc:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "서버에서 설정을 저장하지 못했습니다."})
            print(f"API PATCH error: {type(exc).__name__}: {exc}")

    def session_cookie(self, token: str) -> tuple[str, str]:
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
        return ("Set-Cookie", f"opca_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_SECONDS}{secure}")

    @staticmethod
    def public_user(user: sqlite3.Row) -> dict:
        return {
            "id": user["id"],
            "username": user["username"],
            "nickname": user["nickname"],
            "isAdmin": bool(ADMIN_USERNAME and user["username"].casefold() == ADMIN_USERNAME),
        }

    @staticmethod
    def public_photo_submission(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "metadata": json.loads(row["metadata"]),
            "status": row["status"],
            "reviewerNote": row["reviewer_note"],
            "submittedAt": row["submitted_at"],
            "reviewedAt": row["reviewed_at"],
        }

    @staticmethod
    def public_listing(row: sqlite3.Row) -> dict:
        payload = json.loads(row["payload"])
        payload["seller"] = row["nickname"]
        payload["kind"] = row["kind"]
        payload["id"] = row["id"]
        return payload

    @staticmethod
    def public_message(row: sqlite3.Row) -> dict:
        return {"id": row["id"], "senderId": row["sender_id"], "senderNickname": row["sender_nickname"], "body": row["body"], "createdAt": row["created_at"]}

    @staticmethod
    def authorize_thread(connection: sqlite3.Connection, user_id: int, listing_id: str, allow_start: bool = False) -> sqlite3.Row:
        listing = connection.execute("SELECT * FROM listings WHERE id = ?", (listing_id,)).fetchone()
        if listing is None:
            raise PermissionError("매물을 찾을 수 없습니다.")
        if listing["owner_id"] == user_id:
            participant = connection.execute(
                "SELECT 1 FROM messages WHERE listing_id = ? AND recipient_id = ? AND sender_id != ? LIMIT 1",
                (listing_id, user_id, user_id),
            ).fetchone()
        else:
            participant = connection.execute("SELECT 1 FROM messages WHERE listing_id = ? AND (sender_id = ? OR recipient_id = ?) LIMIT 1", (listing_id, user_id, user_id)).fetchone()
        if participant is None and (not allow_start or listing["owner_id"] == user_id):
            raise PermissionError("이 대화에 접근할 수 없습니다.")
        return listing


def main() -> None:
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), OpcaHandler)
    print(f"OPCA is running at http://{HOST}:{PORT}")
    print(f"SQLite database: {DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping OPCA server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
