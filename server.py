"""Bảng đăng ký nhóm Day 9.

Chạy trong thư mục team-hub:

    py server.py

Mở địa chỉ in ra trên màn hình. Các máy khác trong cùng mạng Wi-Fi mở địa chỉ đó.
"""

from __future__ import annotations

import os
import sys
import hashlib
import hmac
import json
import re
import secrets
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = ROOT / "data"
FILES = DATA / "files"
DB_PATH = DATA / "teams.json"
PORT = 8765
MAX_ZIP = 80 * 1024 * 1024
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def on_vercel() -> bool:
    return os.environ.get("VERCEL") == "1"


def load_db() -> dict:
    if on_vercel():
        return {"teams": list_remote_teams()}
    if not DB_PATH.exists():
        return {"teams": []}
    return json.loads(DB_PATH.read_text(encoding="utf-8"))


def save_db(db: dict) -> None:
    if on_vercel():
        raise RuntimeError("Trên Vercel mỗi nhóm được lưu riêng.")
    DATA.mkdir(parents=True, exist_ok=True)
    tmp = DB_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(DB_PATH)


def persist_team(team: dict) -> None:
    if not on_vercel():
        return
    from vercel.blob import BlobClient

    BlobClient().put(
        f"teams/{team['id']}.json",
        json.dumps(team, ensure_ascii=False).encode("utf-8"),
        access="private",
        overwrite=True,
        content_type="application/json",
    )


def list_remote_teams() -> list[dict]:
    from vercel.blob import BlobClient, list_objects
    from vercel.blob.errors import BlobNotFoundError

    client = BlobClient()
    teams: list[dict] = []
    cursor = None
    while True:
        page = list_objects(prefix="teams/", limit=100, cursor=cursor)
        for item in page.blobs:
            if not str(item.pathname).endswith(".json"):
                continue
            try:
                got = client.get(item.pathname, access="private", use_cache=False)
            except BlobNotFoundError:
                continue
            if got is None or got.status_code != 200 or not got.content:
                continue
            teams.append(json.loads(got.content.decode("utf-8")))
        if not page.has_more:
            break
        cursor = page.cursor
    teams.sort(key=lambda team: team.get("createdAt") or "")
    return teams


def store_zip(team_id: str, blob: bytes) -> str:
    if not on_vercel():
        FILES.mkdir(parents=True, exist_ok=True)
        stored = f"{team_id}.zip"
        tmp = FILES / f"{stored}.tmp"
        tmp.write_bytes(blob)
        tmp.replace(FILES / stored)
        return stored
    from vercel.blob import BlobClient

    uploaded = BlobClient().put(
        f"zips/{team_id}.zip",
        blob,
        access="private",
        overwrite=True,
        content_type="application/zip",
    )
    return uploaded.pathname


def hash_pin(pin: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{pin}".encode("utf-8")).hexdigest()


def pin_ok(team: dict, pin: str) -> bool:
    if not isinstance(pin, str) or not pin:
        return False
    digest = hash_pin(pin, team["salt"])
    return hmac.compare_digest(digest, team["pinHash"])


def public_team(team: dict) -> dict:
    return {
        "id": team["id"],
        "name": team["name"],
        "topic": team.get("topic") or "",
        "members": team["members"],
        "hasZip": bool(team.get("zipStored")),
        "zipName": team.get("zipName") or "",
        "updatedAt": team.get("updatedAt") or team.get("createdAt"),
    }


def clean_text(value, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def parse_topic(value) -> str:
    topic = clean_text(value, 160)
    if len(topic) < 4:
        raise ValueError("Đề tài còn thiếu.")
    return topic


def parse_members(raw) -> list[dict]:
    if not isinstance(raw, list):
        raise ValueError("Danh sách thành viên không đúng.")
    if not 3 <= len(raw) <= 5:
        raise ValueError("Mỗi nhóm có từ 3 đến 5 thành viên.")
    members = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("Mỗi thành viên cần họ tên và mã sinh viên.")
        name = clean_text(item.get("name"), 80)
        student_id = clean_text(item.get("studentId"), 20).upper()
        if len(name) < 2:
            raise ValueError("Họ tên thành viên còn thiếu.")
        if not re.fullmatch(r"[A-Z0-9]{4,20}", student_id):
            raise ValueError(f"Mã sinh viên không hợp lệ: {student_id or '(trống)'}.")
        if student_id in seen:
            raise ValueError(f"Mã sinh viên {student_id} bị nhập hai lần.")
        seen.add(student_id)
        members.append({"name": name, "studentId": student_id})
    return members


def assert_unique(db: dict, name: str, members: list[dict], skip_id: str | None) -> None:
    key = name.casefold()
    ids = {m["studentId"] for m in members}
    for team in db["teams"]:
        if team["id"] == skip_id:
            continue
        if team["name"].casefold() == key:
            raise ValueError("Tên nhóm này đã có người đăng ký.")
        overlap = ids & {m["studentId"] for m in team["members"]}
        if overlap:
            joined = ", ".join(sorted(overlap))
            raise ValueError(f"Mã sinh viên đã nằm trong nhóm khác: {joined}.")


def safe_zip_name(name: str) -> str:
    base = Path(name or "nop-bai.zip").name
    base = re.sub(r"[^A-Za-z0-9._ -]", "", base).strip() or "nop-bai.zip"
    if not base.lower().endswith(".zip"):
        base += ".zip"
    return base[:80]


def perform_create(body: dict) -> tuple[int, dict]:
    name = clean_text(body.get("name"), 80)
    topic = parse_topic(body.get("topic"))
    pin = body.get("pin") if isinstance(body.get("pin"), str) else ""
    members = parse_members(body.get("members"))
    if len(name) < 2:
        raise ValueError("Tên nhóm còn thiếu.")
    if not re.fullmatch(r"[A-Za-z0-9 -]+", name):
        raise ValueError("Tên nhóm chỉ dùng chữ không dấu, số, dấu cách.")
    if len(pin) < 4:
        raise ValueError("Mã nhóm trưởng cần ít nhất 4 ký tự.")
    salt = secrets.token_hex(16)
    team = {
        "id": secrets.token_hex(16),
        "name": name,
        "topic": topic,
        "salt": salt,
        "pinHash": hash_pin(pin, salt),
        "members": members,
        "zipStored": "",
        "zipName": "",
        "createdAt": now_iso(),
        "updatedAt": now_iso(),
    }
    with LOCK:
        db = load_db()
        assert_unique(db, name, members, None)
        db["teams"].append(team)
        if on_vercel():
            persist_team(team)
        else:
            save_db(db)
    return 201, {"team": public_team(team)}


def perform_unlock(team_id: str, body: dict) -> tuple[int, dict]:
    pin = body.get("pin") if isinstance(body.get("pin"), str) else ""
    team = next((t for t in load_db()["teams"] if t["id"] == team_id), None)
    if team is None:
        return 404, {"error": "Không tìm thấy nhóm."}
    if not pin_ok(team, pin):
        return 403, {"error": "Sai mã nhóm trưởng."}
    return 200, {"ok": True}


def perform_update(team_id: str, body: dict) -> tuple[int, dict]:
    pin = body.get("pin") if isinstance(body.get("pin"), str) else ""
    members = parse_members(body.get("members"))
    topic = parse_topic(body.get("topic")) if "topic" in body else None
    with LOCK:
        db = load_db()
        team = next((t for t in db["teams"] if t["id"] == team_id), None)
        if team is None:
            return 404, {"error": "Không tìm thấy nhóm."}
        if not pin_ok(team, pin):
            return 403, {"error": "Sai mã nhóm trưởng. Không sửa được thành viên nhóm này."}
        assert_unique(db, team["name"], members, team_id)
        team["members"] = members
        if topic is not None:
            team["topic"] = topic
        team["updatedAt"] = now_iso()
        if on_vercel():
            persist_team(team)
        else:
            save_db(db)
        return 200, {"team": public_team(team)}


def perform_zip(team_id: str, pin: str, filename: str, blob: bytes) -> tuple[int, dict]:
    limit = 4_500_000 if on_vercel() else MAX_ZIP
    if len(blob) <= 0 or len(blob) > limit:
        if on_vercel() and len(blob) > limit:
            return 400, {"error": "File lớn hơn 4,5 MB. Vercel không nhận file lớn hơn mức này."}
        return 400, {"error": "File zip trống hoặc lớn hơn 80 MB."}
    if not blob.startswith(ZIP_MAGIC):
        return 400, {"error": "Chỉ nhận file zip."}
    zip_name = safe_zip_name(filename)
    with LOCK:
        db = load_db()
        team = next((t for t in db["teams"] if t["id"] == team_id), None)
        if team is None:
            return 404, {"error": "Không tìm thấy nhóm."}
        if not pin_ok(team, pin):
            return 403, {"error": "Sai mã nhóm trưởng. Không đổi được file của nhóm này."}
        team["zipStored"] = store_zip(team_id, blob)
        team["zipName"] = zip_name
        team["updatedAt"] = now_iso()
        if on_vercel():
            persist_team(team)
        else:
            save_db(db)
        return 200, {"team": public_team(team)}


class Handler(BaseHTTPRequestHandler):
    server_version = "TeamHub/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/teams":
            with LOCK:
                db = load_db()
            self.send_json(200, {"teams": [public_team(t) for t in db["teams"]]})
            return
        match = re.fullmatch(r"/api/teams/([0-9a-f]{32})/zip", path)
        if match:
            self.send_zip(match.group(1))
            return
        if path in ("/", "/index.html"):
            self.send_file(STATIC / "index.html", "text/html; charset=utf-8")
            return
        self.send_json(404, {"error": "Không tìm thấy trang."})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/teams":
            self.create_team()
            return
        match = re.fullmatch(r"/api/teams/([0-9a-f]{32})/zip", path)
        if match:
            self.replace_zip(match.group(1))
            return
        match = re.fullmatch(r"/api/teams/([0-9a-f]{32})/unlock", path)
        if match:
            self.unlock(match.group(1))
            return
        self.send_json(404, {"error": "Không tìm thấy trang."})

    def unlock(self, team_id: str) -> None:
        try:
            status, payload = perform_unlock(team_id, self.read_json())
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        self.send_json(status, payload)

    def do_PUT(self) -> None:
        match = re.fullmatch(r"/api/teams/([0-9a-f]{32})", urlparse(self.path).path)
        if not match:
            self.send_json(404, {"error": "Không tìm thấy nhóm."})
            return
        self.update_members(match.group(1))

    def create_team(self) -> None:
        try:
            status, payload = perform_create(self.read_json())
        except ValueError as exc:
            status = 409 if "đã" in str(exc) else 400
            self.send_json(status, {"error": str(exc)})
            return
        self.send_json(status, payload)

    def update_members(self, team_id: str) -> None:
        try:
            status, payload = perform_update(team_id, self.read_json())
        except ValueError as exc:
            status = 409 if "đã" in str(exc) else 400
            self.send_json(status, {"error": str(exc)})
            return
        self.send_json(status, payload)

    def replace_zip(self, team_id: str) -> None:
        pin = self.headers.get("X-Team-Pin", "")
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_ZIP:
            self.send_json(400, {"error": "File zip trống hoặc lớn hơn 80 MB."})
            return
        blob = self.rfile.read(length)
        filename = unquote(self.headers.get("X-File-Name", "nop-bai.zip"))
        status, payload = perform_zip(team_id, pin, filename, blob)
        self.send_json(status, payload)

    def send_zip(self, team_id: str) -> None:
        with LOCK:
            db = load_db()
            team = next((t for t in db["teams"] if t["id"] == team_id), None)
            stored = team.get("zipStored") if team else ""
            zip_name = team.get("zipName") if team else ""
            path = FILES / stored if stored and not str(stored).startswith("zips/") else None
        if isinstance(stored, str) and stored.startswith("zips/"):
            from vercel.blob import BlobClient
            from vercel.blob.errors import BlobNotFoundError

            try:
                got = BlobClient().get(stored, access="private", use_cache=False)
            except BlobNotFoundError:
                got = None
            if got is None or got.status_code != 200 or not got.content:
                self.send_json(404, {"error": "Nhóm này chưa gửi file."})
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(got.content)))
            self.send_header("Content-Disposition", f'attachment; filename="{safe_zip_name(zip_name)}"')
            self.end_headers()
            self.wfile.write(got.content)
            return
        if not team or not path or not path.is_file():
            self.send_json(404, {"error": "Nhóm này chưa gửi file."})
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{safe_zip_name(zip_name)}"')
        self.end_headers()
        self.wfile.write(data)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > 100_000:
            raise ValueError("Dữ liệu gửi lên không hợp lệ.")
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Dữ liệu gửi lên không hợp lệ.") from exc
        if not isinstance(body, dict):
            raise ValueError("Dữ liệu gửi lên không hợp lệ.")
        return body

    def send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            self.send_json(404, {"error": "Không tìm thấy trang."})
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def lan_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    DATA.mkdir(parents=True, exist_ok=True)
    FILES.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists():
        save_db({"teams": []})
    class HubServer(ThreadingHTTPServer):
        allow_reuse_address = False

        def server_bind(self) -> None:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

    httpd = HubServer(("0.0.0.0", PORT), Handler)
    ip = lan_ip()
    print("Bảng nhóm đang chạy.", flush=True)
    print(f"  Máy này:  http://127.0.0.1:{PORT}", flush=True)
    print(f"  Máy khác: http://{ip}:{PORT}", flush=True)
    print("Giữ cửa sổ này mở. Bấm Ctrl+C để tắt.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nĐã tắt.")
    finally:
        httpd.server_close()


def _response(status: int, payload: dict):
    from flask import Response

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return Response(body, status=status, mimetype="application/json; charset=utf-8")


def _error_status(exc: ValueError) -> int:
    return 409 if "đã" in str(exc) else 400


def create_app():
    from flask import Flask, request, Response

    flask_app = Flask(__name__)

    @flask_app.get("/")
    def home():
        page = STATIC / "index.html"
        return Response(page.read_bytes(), mimetype="text/html; charset=utf-8")

    @flask_app.get("/api/teams")
    def api_teams():
        return _response(200, {"teams": [public_team(team) for team in load_db()["teams"]]})

    @flask_app.post("/api/teams")
    def api_create():
        try:
            status, payload = perform_create(request.get_json(force=True, silent=True) or {})
        except ValueError as exc:
            return _response(_error_status(exc), {"error": str(exc)})
        return _response(status, payload)

    @flask_app.post("/api/teams/<team_id>/unlock")
    def api_unlock(team_id: str):
        try:
            status, payload = perform_unlock(team_id, request.get_json(force=True) or {})
        except ValueError as exc:
            return _response(400, {"error": str(exc)})
        return _response(status, payload)

    @flask_app.put("/api/teams/<team_id>")
    def api_update(team_id: str):
        try:
            status, payload = perform_update(team_id, request.get_json(force=True) or {})
        except ValueError as exc:
            return _response(_error_status(exc), {"error": str(exc)})
        return _response(status, payload)

    @flask_app.post("/api/teams/<team_id>/zip")
    def api_zip(team_id: str):
        status, payload = perform_zip(
            team_id,
            request.headers.get("X-Team-Pin", ""),
            unquote(request.headers.get("X-File-Name", "nop-bai.zip")),
            request.get_data(),
        )
        return _response(status, payload)

    @flask_app.get("/api/teams/<team_id>/zip")
    def api_download(team_id: str):
        team = next((item for item in load_db()["teams"] if item["id"] == team_id), None)
        stored = team.get("zipStored") if team else ""
        if isinstance(stored, str) and stored.startswith("zips/"):
            from vercel.blob import BlobClient
            from vercel.blob.errors import BlobNotFoundError

            try:
                got = BlobClient().get(stored, access="private", use_cache=False)
            except BlobNotFoundError:
                got = None
            if got is None or got.status_code != 200 or not got.content:
                return _response(404, {"error": "Nhóm này chưa gửi file."})
            return Response(
                got.content,
                mimetype="application/zip",
                headers={"Content-Disposition": f'attachment; filename="{safe_zip_name(team.get("zipName") or "")}"'},
            )
        path = FILES / stored if stored else None
        if not team or not path or not path.is_file():
            return _response(404, {"error": "Nhóm này chưa gửi file."})
        return Response(
            path.read_bytes(),
            mimetype="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{safe_zip_name(team.get("zipName") or "")}"'},
        )

    @flask_app.errorhandler(404)
    def missing(_exc):
        return _response(404, {"error": "Không tìm thấy trang."})

    return flask_app


try:
    import flask  # noqa: F401
except ImportError:
    app = None
else:
    app = create_app()


if __name__ == "__main__":
    main()
