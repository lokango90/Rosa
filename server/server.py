from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import threading
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography.fernet import Fernet, InvalidToken


APP_DIR = Path(__file__).resolve().parent
OUTPUTS_DIR = APP_DIR.parent
PUBLIC_DIR = Path(os.environ.get("MAMAN_ROSA_PUBLIC_DIR", OUTPUTS_DIR)).resolve()
HTML_FILE = PUBLIC_DIR / "espace-maman-rosa.html"
LOGO_FILE = PUBLIC_DIR / "logo.jpeg"
DATA_DIR = Path(os.environ.get("MAMAN_ROSA_DATA_DIR", APP_DIR / "data")).resolve()
BACKUP_DIR = Path(os.environ.get("MAMAN_ROSA_BACKUP_DIR", APP_DIR / "backups")).resolve()
EXTERNAL_BACKUP_DIR = Path(os.environ["MAMAN_ROSA_EXTERNAL_BACKUP_DIR"]).resolve() if os.environ.get("MAMAN_ROSA_EXTERNAL_BACKUP_DIR") else None
DB_FILE = DATA_DIR / "maman_rosa.db"
PBKDF2_ROUNDS = 310_000
SESSION_HOURS = 12
IDLE_MINUTES = 30
LOGIN_WINDOW_MINUTES = 15
LOGIN_MAX_FAILURES = 5
LOCK = threading.RLock()
COOKIE_SECURE = os.environ.get("MAMAN_ROSA_COOKIE_SECURE", "0") == "1"
DATA_SECRET = os.environ.get("MAMAN_ROSA_DATA_KEY", "maman-rosa-local-development-key")
DATA_CIPHER = Fernet(base64.urlsafe_b64encode(hashlib.sha256(DATA_SECRET.encode("utf-8")).digest()))

ROLE_PERMISSIONS = {
    "Administrateur": ["dashboard", "rooms", "pos", "articles", "stock", "cash", "users", "audit", "backup", "approve"],
    "Directeur": ["dashboard", "rooms", "pos", "articles", "stock", "cash", "users", "audit", "backup", "approve"],
    "Réceptionniste": ["dashboard", "rooms", "calendar"],
    "Caissier": ["dashboard", "pos", "cash"],
    "Serveur": ["pos"],
    "Barman": ["pos", "stock"],
    "Cuisinier": ["pos"],
    "Responsable du stock": ["dashboard", "stock", "articles"],
}

ROLE_STATE_KEYS = {
    "Réceptionniste": {"rooms", "selected", "alerted", "history", "exchangeRate", "reservations", "documentCounters"},
    "Caissier": {"cart", "sales", "posSales", "moves", "closures", "openingCash", "expenses", "products", "stockMoves", "lastReceipt", "tables", "history", "exchangeRate", "documentCounters"},
    "Serveur": {"cart", "posSales", "moves", "products", "stockMoves", "lastReceipt", "tables", "rooms", "history"},
    "Barman": {"cart", "posSales", "moves", "products", "stockMoves", "lastReceipt", "tables", "history"},
    "Cuisinier": {"tables", "history"},
    "Responsable du stock": {"products", "stockMoves", "history"},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, rounds, salt, expected = encoded.split("$", 3)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), base64.b64decode(salt), int(rounds)
        )
        return hmac.compare_digest(base64.b64encode(digest).decode(), expected)
    except (ValueError, TypeError):
        return False


def encrypt_value(value: object) -> object:
    if not isinstance(value, str) or not value or value.startswith("enc:v1:"):
        return value
    return "enc:v1:" + DATA_CIPHER.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_value(value: object) -> object:
    if not isinstance(value, str) or not value.startswith("enc:v1:"):
        return value
    try:
        return DATA_CIPHER.decrypt(value[7:].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return "[Donnée chiffrée indisponible]"


def protect_state(state: dict) -> dict:
    protected = deepcopy(state)
    for room in protected.get("rooms", []):
        for key in ("guest", "guestPhone", "guestId", "guestOrigin", "lastGuest"):
            if key in room:
                room[key] = encrypt_value(room[key])
    for reservation in protected.get("reservations", []):
        for key in ("guest", "phone", "identity"):
            if key in reservation:
                reservation[key] = encrypt_value(reservation[key])
    for collection in ("history", "outstandingDebts"):
        for entry in protected.get(collection, []):
            if "guest" in entry:
                entry["guest"] = encrypt_value(entry["guest"])
    return protected


def unprotect_state(state: dict) -> dict:
    visible = deepcopy(state)
    for room in visible.get("rooms", []):
        for key in ("guest", "guestPhone", "guestId", "guestOrigin", "lastGuest"):
            if key in room:
                room[key] = decrypt_value(room[key])
    for reservation in visible.get("reservations", []):
        for key in ("guest", "phone", "identity"):
            if key in reservation:
                reservation[key] = decrypt_value(reservation[key])
    for collection in ("history", "outstandingDebts"):
        for entry in visible.get(collection, []):
            if "guest" in entry:
                entry["guest"] = decrypt_value(entry["guest"])
    return visible


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


def initial_state() -> dict:
    return {
        "rooms": [{"id": i, "status": "free"} for i in range(1, 13)],
        "tables": [False] * 10,
        "sales": 0,
        "moves": [],
        "selected": 1,
        "cart": [],
        "posSales": 0,
        "catalog": [
            {"id": 1, "n": "Poulet grillé", "c": "Restaurant", "p": 18000, "q": 30, "min": 5, "cost": 11000},
            {"id": 2, "n": "Poisson braisé", "c": "Restaurant", "p": 22000, "q": 30, "min": 5, "cost": 13500},
            {"id": 3, "n": "Frites", "c": "Restaurant", "p": 6000, "q": 40, "min": 8, "cost": 2500},
            {"id": 4, "n": "Primus", "c": "Bar", "p": 3500, "q": 48, "min": 12, "cost": 2200},
            {"id": 5, "n": "Skol", "c": "Bar", "p": 3500, "q": 48, "min": 12, "cost": 2200},
            {"id": 6, "n": "Coca-Cola", "c": "Bar", "p": 2500, "q": 36, "min": 8, "cost": 1500},
            {"id": 7, "n": "Eau minérale", "c": "Bar", "p": 1500, "q": 36, "min": 8, "cost": 800},
        ],
        "users": [
            {"id": 1, "name": "Administrateur", "role": "Administrateur"},
            {"id": 2, "name": "Réception", "role": "Réceptionniste"},
            {"id": 3, "name": "Caisse", "role": "Caissier"},
        ],
        "currentUser": 1,
        "expenses": 0,
        "openingCash": 0,
        "closures": [],
        "stockMoves": [],
        "history": [],
        "exchangeRate": 2850,
        "alerted": {},
        "reservations": [],
        "documentCounters": {"invoice": 0, "ticket": 0},
        "outstandingDebts": [],
    }


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_activity_at TEXT
            );
            CREATE TABLE IF NOT EXISTS app_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                state_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                updated_by INTEGER REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_by INTEGER NOT NULL REFERENCES users(id),
                approved_by INTEGER REFERENCES users(id),
                kind TEXT NOT NULL,
                details TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                decided_at TEXT,
                consumed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                succeeded INTEGER NOT NULL DEFAULT 0,
                attempted_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at);
            CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup ON login_attempts(username,ip_address,attempted_at);
            """
        )
        session_columns = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
        if "last_activity_at" not in session_columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN last_activity_at TEXT")
        users = [
            ("Administrateur", "Administrateur", "Administrateur", os.environ.get("MAMAN_ROSA_ADMIN_PASSWORD", "Rosa@2026!")),
            ("Reception", "Réception", "Réceptionniste", os.environ.get("MAMAN_ROSA_RECEPTION_PASSWORD", "Reception@2026!")),
            ("Caisse", "Caisse", "Caissier", os.environ.get("MAMAN_ROSA_CAISSE_PASSWORD", "Caisse@2026!")),
            ("Directeur", "Directeur", "Directeur", os.environ.get("MAMAN_ROSA_DIRECTEUR_PASSWORD", "Direction@2026!")),
        ]
        for username, display, role, password in users:
            conn.execute(
                "INSERT OR IGNORE INTO users(username, display_name, role, password_hash, created_at) VALUES(?,?,?,?,?)",
                (username, display, role, password_hash(password), utc_now()),
            )
        conn.execute(
            "INSERT OR IGNORE INTO app_state(id, state_json, version, updated_at) VALUES(1,?,?,?)",
            (json.dumps(protect_state(initial_state()), ensure_ascii=False), 1, utc_now()),
        )
        conn.execute("PRAGMA optimize")


def backup_database(reason: str = "auto") -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = BACKUP_DIR / f"maman-rosa-{stamp}-{reason}.db"
    with LOCK, db() as source, sqlite3.connect(target) as destination:
        source.backup(destination)
    with sqlite3.connect(target) as verification:
        result = verification.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            target.unlink(missing_ok=True)
            raise RuntimeError("La vérification de la sauvegarde a échoué")
    checksum = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix(target.suffix + ".sha256").write_text(checksum, encoding="ascii")
    if EXTERNAL_BACKUP_DIR:
        EXTERNAL_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, EXTERNAL_BACKUP_DIR / target.name)
        shutil.copy2(target.with_suffix(target.suffix + ".sha256"), EXTERNAL_BACKUP_DIR / (target.name + ".sha256"))
    backups = sorted(BACKUP_DIR.glob("maman-rosa-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[30:]:
        old.unlink(missing_ok=True)
        old.with_suffix(old.suffix + ".sha256").unlink(missing_ok=True)
    return target


def daily_backup_worker() -> None:
    while True:
        try:
            latest = max(BACKUP_DIR.glob("maman-rosa-*.db"), key=lambda p: p.stat().st_mtime, default=None)
            if latest is None or time.time() - latest.stat().st_mtime > 24 * 3600:
                backup_database("daily")
        except Exception as exc:
            print(f"Sauvegarde automatique impossible: {exc}")
        time.sleep(3600)


def expired_passage_worker() -> None:
    """Libère automatiquement les chambres de passage arrivées à expiration."""
    while True:
        try:
            now_ms = int(time.time() * 1000)
            with LOCK, db() as conn:
                row = conn.execute("SELECT state_json,version FROM app_state WHERE id=1").fetchone()
                state = json.loads(row["state_json"])
                released: list[dict] = []
                for index, room in enumerate(state.get("rooms", [])):
                    if room.get("status") != "busy" or room.get("type") != "passage":
                        continue
                    if not room.get("end") or int(room["end"]) > now_ms:
                        continue
                    total = sum(float(line.get("amount", 0) or 0) for line in room.get("folio", []))
                    paid = float(room.get("paid", 0) or 0)
                    balance = max(0, total - paid)
                    archive = {
                        "type": "Fin automatique du passage",
                        "room": room.get("id"),
                        "guest": room.get("guest", "Client"),
                        "start": room.get("start"),
                        "end": room.get("end"),
                        "folio": room.get("folio", []),
                        "payments": room.get("payments", []),
                        "balance": balance,
                        "at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                    }
                    state.setdefault("history", []).append(archive)
                    if balance > 0:
                        state.setdefault("outstandingDebts", []).append(archive)
                    room_id = int(room.get("id", index + 1))
                    state["rooms"][index] = {
                        "id": room_id,
                        "status": "cleaning",
                        "lastGuest": archive["guest"],
                        "cleaningSince": now_ms,
                    }
                    state.setdefault("alerted", {}).pop(str(room_id), None)
                    state.setdefault("alerted", {}).pop(room_id, None)
                    released.append({"room": room_id, "guest": archive["guest"], "balance": balance})
                if released:
                    next_version = int(row["version"]) + 1
                    conn.execute(
                        "UPDATE app_state SET state_json=?,version=?,updated_at=?,updated_by=NULL WHERE id=1",
                        (json.dumps(state, ensure_ascii=False, separators=(",", ":")), next_version, utc_now()),
                    )
                    conn.execute(
                        "INSERT INTO audit_log(user_id,action,details,created_at) VALUES(NULL,?,?,?)",
                        ("automatic_passage_release", json.dumps(released, ensure_ascii=False), utc_now()),
                    )
        except Exception as exc:
            print(f"Libération automatique impossible: {exc}")
        time.sleep(2)


class Handler(BaseHTTPRequestHandler):
    server_version = "MamanRosa/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.client_address[0]} {fmt % args}")

    def json_response(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 5_000_000:
            raise ValueError("Requête trop volumineuse")
        return json.loads(self.rfile.read(length) or b"{}")

    def session(self) -> sqlite3.Row | None:
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(raw)
        morsel = jar.get("maman_rosa_session")
        if not morsel:
            return None
        token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
        with db() as conn:
            row = conn.execute(
                """SELECT s.*, u.username, u.display_name, u.role
                   FROM sessions s JOIN users u ON u.id=s.user_id
                   WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""",
                (token_hash, utc_now()),
            ).fetchone()
            if row:
                last = row["last_activity_at"] or row["created_at"]
                if datetime.fromisoformat(last) < datetime.now(timezone.utc) - timedelta(minutes=IDLE_MINUTES):
                    conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                    return None
                conn.execute("UPDATE sessions SET last_activity_at=? WHERE token_hash=?", (utc_now(), token_hash))
        return row

    def require_session(self, csrf: bool = False) -> sqlite3.Row | None:
        session = self.session()
        if not session:
            self.json_response(401, {"ok": False, "error": "Connexion requise"})
            return None
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf_token"]):
            self.json_response(403, {"ok": False, "error": "Jeton de sécurité invalide"})
            return None
        return session

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/espace-maman-rosa.html"):
            self.serve_app()
        elif path == "/logo.jpeg":
            self.serve_file(LOGO_FILE, "image/jpeg")
        elif path == "/api/state":
            session = self.require_session()
            if session:
                with db() as conn:
                    row = conn.execute("SELECT state_json, version, updated_at FROM app_state WHERE id=1").fetchone()
                self.json_response(200, {"ok": True, "state": unprotect_state(json.loads(row["state_json"])), "version": row["version"], "updated_at": row["updated_at"]})
        elif path == "/api/me":
            session = self.require_session()
            if session:
                self.json_response(200, {"ok": True, "user": {"id": session["user_id"], "name": session["display_name"], "role": session["role"], "permissions": ROLE_PERMISSIONS.get(session["role"], [])}, "csrf": session["csrf_token"], "idle_minutes": IDLE_MINUTES})
        elif path == "/health":
            try:
                with db() as conn:
                    conn.execute("SELECT 1").fetchone()
                self.json_response(200, {"ok": True, "service": "maman-rosa"})
            except sqlite3.Error:
                self.json_response(503, {"ok": False})
        elif path == "/api/audit":
            self.get_audit()
        elif path == "/api/users":
            self.get_users()
        elif path == "/api/backups":
            self.list_backups()
        elif path == "/api/backup/download":
            self.download_backup()
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/login":
                self.login()
            elif path == "/api/logout":
                self.logout()
            elif path == "/api/state":
                self.save_state()
            elif path == "/api/backup":
                self.create_backup()
            elif path == "/api/backup/test":
                self.test_backup()
            elif path == "/api/backup/restore":
                self.restore_backup()
            elif path == "/api/password/change":
                self.change_password()
            elif path == "/api/password/reset":
                self.reset_password()
            elif path == "/api/approval/authorize":
                self.authorize_sensitive_action()
            else:
                self.send_error(404)
        except (json.JSONDecodeError, ValueError) as exc:
            self.json_response(400, {"ok": False, "error": str(exc)})
        except Exception as exc:
            print(f"Erreur: {exc}")
            self.json_response(500, {"ok": False, "error": "Erreur interne"})

    def serve_file(self, path: Path, content_type: str) -> None:
        if not path.exists():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def serve_app(self) -> None:
        session = self.session()
        state = None
        state_version = 0
        if session:
            with db() as conn:
                state_row = conn.execute("SELECT state_json,version FROM app_state WHERE id=1").fetchone()
                state = unprotect_state(json.loads(state_row["state_json"]))
                state_version = state_row["version"]
        html = HTML_FILE.read_text(encoding="utf-8")
        address_html = "Tshingi-Tshingi n°78, Q/Camp Luka, C/Ngaliema<br>Tél. : +243 989 697 763"
        html = html.replace(
            "Hôtel · Bar · Restaurant · RDC</p>",
            "Hôtel · Bar · Restaurant · RDC<br>" + address_html + "</p>",
        )
        html = html.replace(
            "Espace Maman Rosa · RDC",
            "Espace Maman Rosa · RDC<br>Tshingi-Tshingi n°78, Q/Camp Luka, C/Ngaliema<br>Tél. : +243 989 697 763",
            1,
        )
        html = html.replace(
            "<small>HÔTEL · BAR · RESTAURANT</small>",
            "<small style='text-align:center'>HÔTEL · BAR · RESTAURANT</small><small style='padding-top:0;margin-top:9px;line-height:1.45;text-align:center'>Tshingi-Tshingi n°78<br>Q/Camp Luka · C/Ngaliema<br>+243 989 697 763</small>",
            1,
        )
        inject = (
            "<script>window.__SERVER_STATE__=" + json.dumps(state, ensure_ascii=False).replace("</", "<\\/") + ";"
            "window.__SERVER_USER__=" + json.dumps(
                {"id": session["user_id"], "name": session["display_name"], "role": session["role"], "permissions": ROLE_PERMISSIONS.get(session["role"], [])} if session else None,
                ensure_ascii=False,
            ) + ";"
            "window.__CSRF__=" + json.dumps(session["csrf_token"] if session else None) + ";"
            "window.__STATE_VERSION__=" + str(state_version) + ";window.__SAVE_QUEUE__=Promise.resolve();</script>"
        )
        html = html.replace("<head>", "<head>" + inject, 1)
        html = html.replace(
            "const saved=localStorage.getItem('mamanRosaState');",
            "const saved=window.__SERVER_USER__&&window.__SERVER_STATE__?JSON.stringify(window.__SERVER_STATE__):null;",
            1,
        )
        html = html.replace(
            "const activeUser=()=>state.users.find(u=>u.id===Number(state.currentUser))||state.users[0]",
            "const activeUser=()=>window.__SERVER_USER__?{id:window.__SERVER_USER__.id,name:window.__SERVER_USER__.name,role:window.__SERVER_USER__.role}:state.users.find(u=>u.id===Number(state.currentUser))||state.users[0]",
            1,
        )
        html = html.replace(
            "state.rooms[state.selected-1]={id:state.selected,status:'free'};persist();closeModal();render();renderTargetOptions();showToast('Chambre libérée')",
            "state.rooms[state.selected-1]={id:state.selected,status:'cleaning',lastGuest:r.guest||'Client',cleaningSince:Date.now()};persist();closeModal();render();renderTargetOptions();showToast('Chambre libérée — ménage requis')",
        )
        html = html.replace("Connexion Administrateur", "Connexion sécurisée", 1)
        html = html.replace(
            "persist=()=>localStorage.setItem('mamanRosaState',JSON.stringify(state))",
            "persist=()=>{localStorage.setItem('mamanRosaState',JSON.stringify(state));if(window.__CSRF__){const snapshot=JSON.parse(JSON.stringify(state)),approval_id=window.__PENDING_APPROVAL__||null;window.__SAVE_PENDING__=(window.__SAVE_PENDING__||0)+1;window.__SAVE_QUEUE__=window.__SAVE_QUEUE__.then(()=>fetch('/api/state',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF__},body:JSON.stringify({state:snapshot,version:window.__STATE_VERSION__,approval_id})})).then(async r=>{let d=await r.json();if(r.status===409){location.reload();return}if(!r.ok)showToast(d.error||'Modification refusée');else{window.__STATE_VERSION__=d.version;window.__PENDING_APPROVAL__=null}}).catch(()=>showToast('Sauvegarde serveur en attente')).finally(()=>window.__SAVE_PENDING__=Math.max(0,(window.__SAVE_PENDING__||1)-1))}}",
            1,
        )
        thermal_style = """<style id="thermal-print-style">
@media print {
  @page thermal { size: 80mm auto; margin: 3mm; }
  @page a4doc { size: A4 portrait; margin: 14mm; }
  #printArea.print-thermal { page: thermal; width: 74mm !important; padding: 2mm !important; font-size: 11px !important; }
  #printArea.print-a4 { page: a4doc; width: 182mm !important; padding: 8mm !important; font-size: 12px !important; }
  .folio-line { break-inside: avoid; }
  .print-total { font-size: 15px !important; }
}
.calendar-wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:12px;padding:12px}.calendar-grid{border-collapse:collapse;min-width:1000px;width:100%;font-size:11px}.calendar-grid th,.calendar-grid td{border:1px solid var(--line);padding:5px;text-align:center;min-width:27px}.calendar-grid th:first-child,.calendar-grid td:first-child{position:sticky;left:0;background:#fff;min-width:105px;text-align:left;font-weight:bold}.calendar-grid td.booked{background:#e3b84f;color:#3c271f;font-weight:bold}.calendar-grid td.arrived{background:#7aa27e;color:#fff}.preview-overlay{position:fixed;inset:0;background:#0009;z-index:9999;display:none;align-items:center;justify-content:center;padding:20px}.preview-overlay.open{display:flex}.preview-card{background:#eee;border-radius:14px;max-width:900px;width:100%;max-height:95vh;overflow:auto;padding:16px}.preview-paper{background:#fff;color:#111;margin:auto;box-shadow:0 4px 25px #0004;padding:24px}.preview-paper.thermal{width:302px}.preview-paper.a4{width:min(100%,760px);min-height:800px}
</style>"""
        if not session:
            thermal_style += "<style id=locked-profile>.app{display:none!important}#loginScreen{display:grid!important;place-items:center!important}</style>"
        html = html.replace("</head>", thermal_style + "</head>", 1)
        auth_script = """
        <script>
        async function loginAdmin(){
          const username=document.querySelector('#loginName').value.trim();
          const password=document.querySelector('#loginPassword').value;
          const res=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
          const data=await res.json();
          if(data.ok){location.reload();}else{document.querySelector('#loginError').textContent=data.error||'Connexion impossible';}
        }
        async function logoutServer(){
          if(window.__CSRF__)await fetch('/api/logout',{method:'POST',headers:{'X-CSRF-Token':window.__CSRF__}});
          location.reload();
        }
        async function backupNow(){
          const res=await fetch('/api/backup',{method:'POST',headers:{'X-CSRF-Token':window.__CSRF__}});
          const data=await res.json();
          showToast(data.ok?'Sauvegarde créée : '+data.file:(data.error||'Sauvegarde impossible'));
        }
        async function testBackup(name){const res=await fetch('/api/backup/test',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF__},body:JSON.stringify({name})});const data=await res.json();alert(data.ok?'Sauvegarde vérifiée : intégrité OK':(data.error||'Test impossible'))}
        function downloadBackup(name){location.href='/api/backup/download?name='+encodeURIComponent(name)}
        async function restoreBackup(name){if(window.__SERVER_USER__.role!=='Administrateur')return showToast('Restauration réservée à l’administrateur');const confirmation=prompt('Cette opération remplacera les données actuelles. Tapez RESTAURER pour confirmer.');if(confirmation!=='RESTAURER')return;const res=await fetch('/api/backup/restore',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF__},body:JSON.stringify({name,confirmation})});const data=await res.json();if(data.ok){alert(data.message);location.reload()}else showToast(data.error||'Restauration impossible')}
        async function manageBackups(){const popup=window.open('','Sauvegardes','width=820,height=650');if(!popup)return showToast('Autorisez les fenêtres pour gérer les sauvegardes');popup.document.write('<p style="font:16px sans-serif;padding:20px">Chargement…</p>');const data=await (await fetch('/api/backups')).json();if(!data.ok){popup.close();return showToast(data.error)}const rows=(data.backups||[]).map(b=>`<tr><td>${b.name}</td><td>${new Date(b.created_at).toLocaleString('fr-FR')}</td><td>${Math.ceil(b.size/1024)} Ko</td><td><button onclick="opener.downloadBackup('${b.name}')">Télécharger</button> <button onclick="opener.testBackup('${b.name}')">Tester</button> ${window.__SERVER_USER__.role==='Administrateur'?`<button onclick="opener.restoreBackup('${b.name}')">Restaurer</button>`:''}</td></tr>`).join('');popup.document.open();popup.document.write(`<title>Sauvegardes</title><style>body{font:14px sans-serif;padding:22px}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #ddd;text-align:left}button{padding:6px 9px;margin:2px}</style><h1>Sauvegardes vérifiées</h1><p>Les sauvegardes automatiques sont créées chaque jour et contrôlées par SQLite.</p><table><tr><th>Fichier</th><th>Date</th><th>Taille</th><th>Actions</th></tr>${rows}</table>`);popup.document.close()}
        async function resetUserPassword(){
          const username=prompt('Nom d’utilisateur à réinitialiser');if(!username)return;
          const list=await (await fetch('/api/users')).json();const user=(list.users||[]).find(u=>u.username.toLowerCase()===username.toLowerCase());
          if(!user)return showToast('Utilisateur introuvable');
          const res=await fetch('/api/password/reset',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF__},body:JSON.stringify({user_id:user.id})});
          const data=await res.json();if(data.ok)alert('Mot de passe temporaire de '+user.display_name+' : '+data.temporary_password+'\\nÀ communiquer directement à cet utilisateur.');else showToast(data.error);
        }
        async function showAudit(){
          const data=await (await fetch('/api/audit')).json();if(!data.ok)return showToast(data.error);
          const text=(data.entries||[]).slice(0,80).map(e=>`${e.created_at} · ${e.user||'Système'} · ${e.action}\\n${e.details||''}`).join('\\n\\n');
          const w=window.open('','JournalAudit','width=900,height=700');w.document.write('<title>Journal d’audit</title><pre style="white-space:pre-wrap;font:14px sans-serif;padding:20px">'+text.replaceAll('&','&amp;').replaceAll('<','&lt;')+'</pre>');
        }
        async function changeOwnPassword(){
          const current=prompt('Mot de passe actuel'); if(current===null)return;
          const next=prompt('Nouveau mot de passe (12 caractères minimum)'); if(next===null)return;
          const confirmNext=prompt('Confirmez le nouveau mot de passe');
          if(next!==confirmNext)return showToast('Les mots de passe ne correspondent pas');
          const res=await fetch('/api/password/change',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF__},body:JSON.stringify({current_password:current,new_password:next})});
          const data=await res.json();showToast(data.ok?'Mot de passe modifié':data.error);
          if(data.ok)setTimeout(()=>location.reload(),900);
        }
        async function requestDirectorApproval(kind,details){
          if(['Administrateur','Directeur'].includes(window.__SERVER_USER__.role))return true;
          const username=prompt('Validation requise — identifiant du directeur');if(!username)return false;
          const password=prompt('Mot de passe du directeur');if(!password)return false;
          const reason=prompt('Motif obligatoire');if(!reason)return false;
          const res=await fetch('/api/approval/authorize',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF__},body:JSON.stringify({username,password,kind,details,reason})});
          const data=await res.json();if(!data.ok){showToast(data.error);return false}window.__PENDING_APPROVAL__=data.approval_id;showToast('Validation accordée');return true;
        }
        const originalAddFolioLine=window.addFolioLine;
        window.addFolioLine=async function(){if(document.querySelector('#folioCategory').value==='Remise'&&!await requestDirectorApproval('remise','Remise sur folio chambre'))return;return originalAddFolioLine()};
        const originalRemoveFolioLine=window.removeFolioLine;
        window.removeFolioLine=async function(index){if(!await requestDirectorApproval('annulation','Suppression ligne folio'))return;return originalRemoveFolioLine(index)};
        const originalDeleteArticle=window.deleteArticle;
        window.deleteArticle=async function(id){if(!await requestDirectorApproval('suppression','Suppression article '+id))return;return originalDeleteArticle(id)};
        function applyServerRights(){
          const allowed=new Set(window.__SERVER_USER__.permissions||[]);
          const map={'Tableau de bord':'dashboard','Chambres':'rooms','Point de vente':'pos','Articles':'articles','Stock':'stock','Caisse commune':'cash','Utilisateurs':'users'};
          document.querySelectorAll('aside button').forEach(btn=>{for(const [label,perm] of Object.entries(map))if(btn.textContent.includes(label)&&!allowed.has(perm))btn.style.display='none'});
        }
        function startIdleLogout(){
          let timer;const reset=()=>{clearTimeout(timer);timer=setTimeout(()=>{alert('Session fermée après 30 minutes d’inactivité');logoutServer()},30*60000)};
          ['click','keydown','touchstart'].forEach(e=>document.addEventListener(e,reset,{passive:true}));reset();
        }
        function markRoomClean(id){
          const room=state.rooms[id-1];if(!room||room.status!=='cleaning')return;
          state.history=state.history||[];state.history.push({type:'Ménage terminé',room:id,at:new Date().toLocaleString('fr-FR'),user:activeUser().name});
          state.rooms[id-1]={id,status:'free'};persist();closeModal();render();renderTargetOptions();showToast('Chambre '+id+' nettoyée et disponible');
        }
        const originalOpenRoom=window.openRoom;
        window.openRoom=function(id){
          originalOpenRoom(id);const room=state.rooms[id-1],release=document.querySelector('#release');
          if(room&&room.status==='cleaning'){release.style.display='block';release.textContent='✓ Confirmer le nettoyage';release.onclick=()=>markRoomClean(id);document.querySelector('#payBox').style.display='none';document.querySelector('#invoice').style.display='none'}
          else{release.textContent='Check-out / Libérer';release.onclick=window.releaseRoom}
        };
        function reservationNumber(){return 'RES-'+new Date().getFullYear()+'-'+String((state.reservations||[]).length+1).padStart(4,'0')}
        function addReservation(){
          const guest=document.querySelector('#calGuest').value.trim(),phone=document.querySelector('#calPhone').value.trim(),room=Number(document.querySelector('#calRoom').value),arrival=document.querySelector('#calArrival').value,departure=document.querySelector('#calDeparture').value,type=document.querySelector('#calStay').value;
          if(!guest||!arrival||!departure)return showToast('Client, arrivée et départ obligatoires');if(new Date(departure)<=new Date(arrival))return showToast('La date de départ doit suivre l’arrivée');
          const conflict=(state.reservations||[]).some(r=>r.room===room&&r.status!=='cancelled'&&arrival<r.departure&&departure>r.arrival);if(conflict)return showToast('Cette chambre est déjà réservée sur cette période');
          state.reservations=state.reservations||[];state.reservations.push({id:Date.now(),number:reservationNumber(),guest,phone,room,arrival,departure,type,status:'reserved',createdAt:new Date().toISOString(),user:activeUser().name});persist();renderCalendar();showToast('Réservation enregistrée');
        }
        function checkInReservation(id){
          const booking=state.reservations.find(r=>r.id===id),room=booking&&state.rooms[booking.room-1];if(!booking||!room)return;if(room.status!=='free')return showToast('La chambre n’est pas disponible');
          const start=Date.now(),amount=booking.type==='passage'?25000:45000;state.rooms[booking.room-1]={id:booking.room,status:'busy',guest:booking.guest,guestPhone:booking.phone,type:booking.type,start,end:booking.type==='passage'?start+150*60000:new Date(booking.departure).getTime(),folio:[{id:Date.now(),category:'Séjour',label:booking.type==='passage'?'Passage 2 h 30':'Nuitée',amount,at:new Date().toLocaleString('fr-FR')}],paid:0,payments:[],reservationNumber:booking.number};booking.status='arrived';persist();render();renderCalendar();renderTargetOptions();showToast('Arrivée enregistrée — chambre '+booking.room);
        }
        async function cancelReservation(id){
          if(!await requestDirectorApproval('annulation','Annulation réservation '+id))return;const booking=state.reservations.find(r=>r.id===id);if(booking){booking.status='cancelled';booking.cancelledAt=new Date().toISOString();persist();renderCalendar()}
        }
        function renderCalendar(){
          if(!document.querySelector('#calendarGrid'))return;state.reservations=state.reservations||[];const value=document.querySelector('#calMonth').value||new Date().toISOString().slice(0,7),[year,month]=value.split('-').map(Number),days=new Date(year,month,0).getDate();
          let head='<tr><th>Chambre</th>'+Array.from({length:days},(_,i)=>'<th>'+(i+1)+'</th>').join('')+'</tr>',rows=state.rooms.map(room=>'<tr><td>Chambre '+String(room.id).padStart(2,'0')+'</td>'+Array.from({length:days},(_,i)=>{const day=`${value}-${String(i+1).padStart(2,'0')}`,booking=state.reservations.find(r=>r.room===room.id&&r.status!=='cancelled'&&day>=r.arrival.slice(0,10)&&day<r.departure.slice(0,10));return `<td class="${booking?(booking.status==='arrived'?'arrived':'booked'):''}" title="${booking?booking.number+' · '+booking.guest:''}">${booking?'●':''}</td>`}).join('')+'</tr>').join('');document.querySelector('#calendarGrid').innerHTML=head+rows;
          document.querySelector('#reservationList').innerHTML=state.reservations.filter(r=>r.status!=='cancelled').sort((a,b)=>a.arrival.localeCompare(b.arrival)).map(r=>`<div class="folio-line"><span><b>${r.number} · ${r.guest}</b><br><small>Chambre ${r.room} · ${r.arrival.replace('T',' ')} → ${r.departure.replace('T',' ')} · ${r.status==='arrived'?'Arrivé':'Réservée'}</small></span><span>${r.status==='reserved'?`<button class="btn primary" onclick="checkInReservation(${r.id})">Check-in</button> <button class="btn danger" onclick="cancelReservation(${r.id})">Annuler</button>`:''}</span></div>`).join('')||'<p class="muted">Aucune réservation.</p>';
        }
        function createCalendarUI(){
          if(!window.__SERVER_USER__.permissions.includes('calendar'))return;const nav=document.querySelector('.nav'),button=document.createElement('button');button.dataset.v='calendar';button.textContent='▣ Réservations';nav.insertBefore(button,nav.lastElementChild);const section=document.createElement('section');section.id='calendar';section.className='view';section.innerHTML=`<div class="card"><div class="toolbar"><h2>Calendrier des réservations</h2><input id="calMonth" type="month" value="${new Date().toISOString().slice(0,7)}" onchange="renderCalendar()"></div><div class="split"><div class="field"><label>Client</label><input id="calGuest"></div><div class="field"><label>Téléphone</label><input id="calPhone" placeholder="+243..."></div><div class="field"><label>Chambre</label><select id="calRoom">${state.rooms.map(r=>`<option value="${r.id}">Chambre ${r.id}</option>`).join('')}</select></div><div class="field"><label>Type</label><select id="calStay"><option value="night">Nuitée</option><option value="passage">Passage 2 h 30</option></select></div><div class="field"><label>Arrivée prévue</label><input id="calArrival" type="datetime-local"></div><div class="field"><label>Départ prévu</label><input id="calDeparture" type="datetime-local"></div></div><button class="btn primary" onclick="addReservation()">＋ Enregistrer la réservation</button></div><div class="calendar-wrap"><table id="calendarGrid" class="calendar-grid"></table></div><div class="card"><h2>Arrivées et réservations</h2><div id="reservationList"></div></div>`;document.querySelector('main').appendChild(section);button.onclick=()=>{document.querySelectorAll('.nav button,.view').forEach(x=>x.classList.remove('active'));button.classList.add('active');section.classList.add('active');document.querySelector('#title').textContent='Calendrier des réservations';renderCalendar()};renderCalendar();
        }
        function documentNumber(kind){state.documentCounters=state.documentCounters||{invoice:0,ticket:0};state.documentCounters[kind]=(state.documentCounters[kind]||0)+1;return (kind==='invoice'?'FAC':'TKT')+'-'+new Date().getFullYear()+'-'+String(state.documentCounters[kind]).padStart(6,'0')}
        function showPrintPreview(format,title,body,total,totalLabel,number,isCopy=false){
          let overlay=document.querySelector('#professionalPreview');if(!overlay){overlay=document.createElement('div');overlay.id='professionalPreview';overlay.className='preview-overlay';overlay.innerHTML='<div class="preview-card"><div class="toolbar"><b>Aperçu avant impression</b><div><button class="btn ghost" id="previewCopy">Duplicata</button> <button class="btn primary" id="previewPrint">Imprimer</button> <button class="btn ghost" id="previewClose">Fermer</button></div></div><div id="previewPaper" class="preview-paper"></div></div>';document.body.appendChild(overlay)}
          const copy=isCopy?'<div style="text-align:center;border:2px solid #111;padding:4px;font-weight:bold">COPIE</div>':'',html=`${copy}<img src="logo.jpeg" style="display:block;width:110px;margin:0 auto 8px"><div style="text-align:center"><b>ESPACE MAMAN ROSA</b><br>Tshingi-Tshingi n°78, Q/Camp Luka, C/Ngaliema<br>Tél. : +243 989 697 763</div><hr><div><b>${title}</b><br>N° ${number}<br>Date : ${new Date().toLocaleString('fr-FR')}</div><hr>${body}<div class="print-total"><span>${totalLabel}</span><span>${money(total)}</span></div><p style="text-align:center">Merci pour votre visite</p>`;const paper=document.querySelector('#previewPaper');paper.className='preview-paper '+(format==='a4'?'a4':'thermal');paper.innerHTML=html;overlay.classList.add('open');document.querySelector('#previewClose').onclick=()=>overlay.classList.remove('open');document.querySelector('#previewPrint').onclick=()=>{const area=document.querySelector('#printArea');area.className=format==='a4'?'print-a4':'print-thermal';area.innerHTML=html;window.print()};document.querySelector('#previewCopy').onclick=()=>showPrintPreview(format,title,body,total,totalLabel,number,true)
        }
        window.printRoomInvoice=function(){const r=state.rooms[state.selected-1];if(!r||r.status==='free')return showToast('Aucun séjour à facturer');if(!r.invoiceNumber){r.invoiceNumber=documentNumber('invoice');persist()}const body=`Client : <b>${r.guest||'Client'}</b><br>Chambre : ${r.id}<br><br>`+(r.folio||[]).map(l=>`<div class="folio-line"><span>${l.category||''} — ${l.label}</span><b>${money(l.amount)}</b></div>`).join('')+`<div class="folio-line"><span>Total encaissé</span><b>${money(roomPaid(r))}</b></div>`;showPrintPreview('a4','FACTURE HÔTEL',body,Math.max(0,roomTotal(r)-roomPaid(r)),'RESTE À PAYER',r.invoiceNumber)};
        const originalPayCash=window.payCash;window.payCash=function(){originalPayCash();if(state.lastReceipt&&!state.lastReceipt.number){state.lastReceipt.number=documentNumber('ticket');persist()}};
        window.printLastReceipt=function(){const r=state.lastReceipt;if(!r)return showToast('Aucun ticket disponible');if(!r.number){r.number=documentNumber('ticket');persist()}showPrintPreview('thermal','TICKET DE CAISSE',`Caissier : ${r.user}<br>${r.target}<hr>${r.lines}`,r.amount,'TOTAL',r.number)};
        window.printLastClosure=function(){const c=state.closures.at(-1);if(!c)return showToast('Aucune clôture disponible');if(!c.reportNumber){c.reportNumber='RAP-'+new Date().getFullYear()+'-'+String(c.id).slice(-6);persist()}showPrintPreview('a4','RAPPORT DE CLÔTURE',`Caissier : ${c.user}<br>Date : ${c.at}<div class="folio-line"><span>Fonds initial</span><b>${money(c.opening||0)}</b></div><div class="folio-line"><span>Recettes</span><b>${money(c.sales||0)}</b></div><div class="folio-line"><span>Dépenses</span><b>${money(c.expenses||0)}</b></div><div class="folio-line"><span>Montant compté</span><b>${money(c.counted)}</b></div>`,c.diff,'ÉCART',c.reportNumber)};
        async function syncFromServer(){
          if(!window.__SERVER_USER__||(window.__SAVE_PENDING__||0)>0)return;
          try{
            const res=await fetch('/api/state',{cache:'no-store'});if(res.status===401){location.reload();return}if(!res.ok)return;
            const data=await res.json();if(data.version<=window.__STATE_VERSION__)return;
            const fresh=data.state||{};
            if(Array.isArray(fresh.catalog)){catalog.splice(0,catalog.length,...fresh.catalog)}
            Object.keys(state).forEach(key=>{if(key!=='catalog')delete state[key]});
            Object.entries(fresh).forEach(([key,value])=>{if(key!=='catalog')state[key]=value});
            state.catalog=catalog;window.__STATE_VERSION__=data.version;
            render();renderTargetOptions();renderProducts();renderCart();renderStock();renderArticles();renderTables();renderDashboard();renderClosure();renderCalendar();
          }catch(e){}
        }
        function startLiveSync(){setInterval(syncFromServer,4000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)syncFromServer()})}
        if(window.__SERVER_USER__){
          document.querySelector('#loginScreen').style.display='none';
          const selector=document.querySelector('#currentUser');
          if(selector){const badge=document.createElement('div');badge.className='user-select';badge.style.cssText='padding:10px 12px;background:rgba(255,255,255,.12);border-radius:8px;font-weight:bold';badge.textContent=window.__SERVER_USER__.name+' · '+window.__SERVER_USER__.role;selector.replaceWith(badge)}
          window.switchUser=()=>{showToast('Déconnectez-vous puis saisissez le mot de passe du profil souhaité')};
          const aside=document.querySelector('aside');
          const makeAccountAction=(label,handler)=>{const button=document.createElement('button');button.className='btn ghost';button.textContent=label;button.onclick=handler;button.style.cssText='width:100%;margin-top:8px';return button};
          const logout=makeAccountAction('Changer de profil / Déconnexion',logoutServer);
          const password=makeAccountAction('Changer mon mot de passe',changeOwnPassword);
          if(['Administrateur','Directeur'].includes(window.__SERVER_USER__.role)){
            const adminToggle=document.createElement('button');adminToggle.className='btn ghost';adminToggle.textContent='⚙ Paramètres administrateur';adminToggle.setAttribute('aria-expanded','false');adminToggle.style.cssText='width:100%;margin-top:10px;font-weight:700';
            const adminPanel=document.createElement('div');adminPanel.style.cssText='display:none;margin-top:4px;padding:4px 8px 10px;background:rgba(255,255,255,.08);border-radius:10px';
            adminToggle.onclick=()=>{const open=adminPanel.style.display!=='none';adminPanel.style.display=open?'none':'block';adminToggle.setAttribute('aria-expanded',String(!open))};
            adminPanel.appendChild(logout);adminPanel.appendChild(password);
            adminPanel.appendChild(makeAccountAction('Sauvegarder maintenant',backupNow));
            adminPanel.appendChild(makeAccountAction('Gérer les sauvegardes',manageBackups));
            adminPanel.appendChild(makeAccountAction('Récupérer un mot de passe',resetUserPassword));
            adminPanel.appendChild(makeAccountAction('Journal d’audit',showAudit));
            aside.appendChild(adminToggle);aside.appendChild(adminPanel);
          }else{
            logout.style.marginTop='10px';aside.appendChild(logout);aside.appendChild(password);
          }
          applyServerRights();createCalendarUI();startIdleLogout();startLiveSync();
        }
        </script>
        """
        html = html.replace("</body>", auth_script + "</body>")
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def login(self) -> None:
        payload = self.read_json()
        username = str(payload.get("username", ""))[:80]
        password = str(payload.get("password", ""))[:256]
        ip_address = self.client_address[0]
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=LOGIN_WINDOW_MINUTES)).isoformat()
        with db() as conn:
            failures = conn.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE username=? COLLATE NOCASE AND ip_address=? AND succeeded=0 AND attempted_at>=?",
                (username, ip_address, cutoff),
            ).fetchone()[0]
            if failures >= LOGIN_MAX_FAILURES:
                conn.execute("INSERT INTO audit_log(action,details,created_at) VALUES(?,?,?)", ("login_blocked", json.dumps({"username": username, "ip": ip_address}), utc_now()))
                self.json_response(429, {"ok": False, "error": "Trop de tentatives. Réessayez dans 15 minutes."})
                return
            user = conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE AND active=1", (username,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                conn.execute("INSERT INTO login_attempts(username,ip_address,succeeded,attempted_at) VALUES(?,?,0,?)", (username, ip_address, utc_now()))
                conn.execute("INSERT INTO audit_log(user_id,action,details,created_at) VALUES(?,?,?,?)", (user["id"] if user else None, "login_failed", json.dumps({"username": username, "ip": ip_address}), utc_now()))
                time.sleep(0.35)
                self.json_response(401, {"ok": False, "error": "Identifiants incorrects"})
                return
            conn.execute("DELETE FROM login_attempts WHERE (username=? COLLATE NOCASE AND ip_address=?) OR attempted_at<?", (username, ip_address, cutoff))
            conn.execute("INSERT INTO login_attempts(username,ip_address,succeeded,attempted_at) VALUES(?,?,1,?)", (username, ip_address, utc_now()))
            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(24)
            expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat()
            conn.execute("DELETE FROM sessions WHERE expires_at<=?", (utc_now(),))
            conn.execute(
                "INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,created_at,last_activity_at) VALUES(?,?,?,?,?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), user["id"], csrf, expires, utc_now(), utc_now()),
            )
            conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (utc_now(), user["id"]))
            conn.execute("INSERT INTO audit_log(user_id,action,details,created_at) VALUES(?,?,?,?)", (user["id"], "login", json.dumps({"ip": ip_address}), utc_now()))
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        secure = "; Secure" if COOKIE_SECURE else ""
        self.send_header("Set-Cookie", f"maman_rosa_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_HOURS*3600}{secure}")
        body = json.dumps({"ok": True, "csrf": csrf}).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def logout(self) -> None:
        session = self.require_session(csrf=True)
        if not session:
            return
        raw = cookies.SimpleCookie(self.headers.get("Cookie", "")).get("maman_rosa_session")
        if raw:
            with db() as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(raw.value.encode()).hexdigest(),))
        self.send_response(200)
        secure = "; Secure" if COOKIE_SECURE else ""
        self.send_header("Set-Cookie", f"maman_rosa_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}")
        self.send_header("Content-Length", "11")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def save_state(self) -> None:
        session = self.require_session(csrf=True)
        if not session:
            return
        payload = self.read_json()
        state = payload.get("state")
        if not isinstance(state, dict):
            raise ValueError("État invalide")
        encoded = json.dumps(protect_state(state), ensure_ascii=False, separators=(",", ":"))
        with LOCK, db() as conn:
            current_row = conn.execute("SELECT state_json,version FROM app_state WHERE id=1").fetchone()
            current = current_row["version"]
            expected_version = payload.get("version")
            if expected_version is not None and int(expected_version) != current:
                self.json_response(409, {"ok": False, "error": "Données modifiées sur un autre appareil", "version": current})
                return
            old_state = unprotect_state(json.loads(current_row["state_json"]))
            if session["role"] not in ("Administrateur", "Directeur"):
                allowed_keys = ROLE_STATE_KEYS.get(session["role"], set())
                forbidden = [key for key in set(old_state) | set(state) if old_state.get(key) != state.get(key) and key not in allowed_keys]
                if forbidden:
                    conn.execute("INSERT INTO audit_log(user_id,action,details,created_at) VALUES(?,?,?,?)", (session["user_id"], "permission_denied", json.dumps({"keys": forbidden}), utc_now()))
                    self.json_response(403, {"ok": False, "error": "Droits insuffisants pour cette modification"})
                    return
            sensitive = self.sensitive_changes(old_state, state)
            approval_id = payload.get("approval_id")
            if sensitive and session["role"] not in ("Administrateur", "Directeur"):
                approval = conn.execute(
                    "SELECT * FROM approval_requests WHERE id=? AND requested_by=? AND status='approved' AND consumed_at IS NULL",
                    (approval_id, session["user_id"]),
                ).fetchone()
                if not approval:
                    self.json_response(403, {"ok": False, "error": "Validation du directeur obligatoire"})
                    return
                conn.execute("UPDATE approval_requests SET consumed_at=? WHERE id=?", (utc_now(), approval_id))
            conn.execute(
                "UPDATE app_state SET state_json=?,version=?,updated_at=?,updated_by=? WHERE id=1",
                (encoded, current + 1, utc_now(), session["user_id"]),
            )
            conn.execute(
                "INSERT INTO audit_log(user_id,action,details,created_at) VALUES(?,?,?,?)",
                (session["user_id"], "state_saved", json.dumps({"version": current + 1, "sensitive": sensitive}, ensure_ascii=False), utc_now()),
            )
        self.json_response(200, {"ok": True, "version": current + 1})

    @staticmethod
    def sensitive_changes(old: dict, new: dict) -> list[str]:
        changes: list[str] = []
        old_products = {str(p.get("id")) for p in old.get("products", [])}
        new_products = {str(p.get("id")) for p in new.get("products", [])}
        if old_products - new_products:
            changes.append("suppression_article")
        old_lines = {str(line.get("id")): line for room in old.get("rooms", []) for line in room.get("folio", [])}
        new_lines = {str(line.get("id")): line for room in new.get("rooms", []) for line in room.get("folio", [])}
        if old_lines.keys() - new_lines.keys():
            changes.append("annulation_folio")
        if any(float(line.get("amount", 0) or 0) < 0 and key not in old_lines for key, line in new_lines.items()):
            changes.append("remise")
        return changes

    def get_audit(self) -> None:
        session = self.require_session()
        if not session:
            return
        if "audit" not in ROLE_PERMISSIONS.get(session["role"], []):
            self.json_response(403, {"ok": False, "error": "Accès direction requis"})
            return
        with db() as conn:
            rows = conn.execute("""SELECT a.id,a.action,a.details,a.created_at,u.display_name AS user
                                   FROM audit_log a LEFT JOIN users u ON u.id=a.user_id
                                   ORDER BY a.id DESC LIMIT 500""").fetchall()
        self.json_response(200, {"ok": True, "entries": [dict(row) for row in rows]})

    def get_users(self) -> None:
        session = self.require_session()
        if not session:
            return
        if "users" not in ROLE_PERMISSIONS.get(session["role"], []):
            self.json_response(403, {"ok": False, "error": "Accès direction requis"})
            return
        with db() as conn:
            rows = conn.execute("SELECT id,username,display_name,role,active,created_at,last_login_at FROM users ORDER BY display_name").fetchall()
        self.json_response(200, {"ok": True, "users": [dict(row) for row in rows]})

    def change_password(self) -> None:
        session = self.require_session(csrf=True)
        if not session:
            return
        payload = self.read_json()
        current_password = str(payload.get("current_password", ""))
        new_password = str(payload.get("new_password", ""))
        if len(new_password) < 12 or not any(c.isupper() for c in new_password) or not any(c.islower() for c in new_password) or not any(c.isdigit() for c in new_password):
            self.json_response(400, {"ok": False, "error": "12 caractères minimum avec majuscule, minuscule et chiffre"})
            return
        with db() as conn:
            user = conn.execute("SELECT password_hash FROM users WHERE id=?", (session["user_id"],)).fetchone()
            if not verify_password(current_password, user["password_hash"]):
                self.json_response(403, {"ok": False, "error": "Mot de passe actuel incorrect"})
                return
            conn.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(new_password), session["user_id"]))
            conn.execute("DELETE FROM sessions WHERE user_id=?", (session["user_id"],))
            conn.execute("INSERT INTO audit_log(user_id,action,created_at) VALUES(?,?,?)", (session["user_id"], "password_changed", utc_now()))
        self.json_response(200, {"ok": True})

    def reset_password(self) -> None:
        session = self.require_session(csrf=True)
        if not session:
            return
        if session["role"] not in ("Administrateur", "Directeur"):
            self.json_response(403, {"ok": False, "error": "Accès direction requis"})
            return
        payload = self.read_json()
        user_id = int(payload.get("user_id", 0))
        temporary = secrets.token_urlsafe(9) + "A1"
        with db() as conn:
            target = conn.execute("SELECT id,username FROM users WHERE id=?", (user_id,)).fetchone()
            if not target:
                self.json_response(404, {"ok": False, "error": "Utilisateur introuvable"})
                return
            conn.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(temporary), user_id))
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            conn.execute("INSERT INTO audit_log(user_id,action,details,created_at) VALUES(?,?,?,?)", (session["user_id"], "password_reset", json.dumps({"target": target["username"]}), utc_now()))
        self.json_response(200, {"ok": True, "temporary_password": temporary})

    def authorize_sensitive_action(self) -> None:
        requester = self.require_session(csrf=True)
        if not requester:
            return
        payload = self.read_json()
        reason = str(payload.get("reason", "")).strip()[:500]
        if not reason:
            self.json_response(400, {"ok": False, "error": "Motif obligatoire"})
            return
        with db() as conn:
            director = conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE AND active=1", (str(payload.get("username", "")),)).fetchone()
            if not director or director["role"] not in ("Administrateur", "Directeur") or not verify_password(str(payload.get("password", "")), director["password_hash"]):
                self.json_response(403, {"ok": False, "error": "Validation du directeur refusée"})
                return
            cursor = conn.execute("""INSERT INTO approval_requests(requested_by,approved_by,kind,details,status,created_at,decided_at)
                                     VALUES(?,?,?,?, 'approved',?,?)""",
                                  (requester["user_id"], director["id"], str(payload.get("kind", "action sensible"))[:80], json.dumps({"details": payload.get("details"), "reason": reason}, ensure_ascii=False), utc_now(), utc_now()))
            approval_id = cursor.lastrowid
            conn.execute("INSERT INTO audit_log(user_id,action,details,created_at) VALUES(?,?,?,?)", (director["id"], "sensitive_action_approved", json.dumps({"approval_id": approval_id, "requested_by": requester["display_name"], "reason": reason}, ensure_ascii=False), utc_now()))
        self.json_response(200, {"ok": True, "approval_id": approval_id})

    def create_backup(self) -> None:
        session = self.require_session(csrf=True)
        if not session:
            return
        if session["role"] not in ("Administrateur", "Directeur"):
            self.json_response(403, {"ok": False, "error": "Accès administrateur requis"})
            return
        target = backup_database("manual")
        with db() as conn:
            conn.execute("INSERT INTO audit_log(user_id,action,details,created_at) VALUES(?,?,?,?)", (session["user_id"], "backup", target.name, utc_now()))
        self.json_response(200, {"ok": True, "file": target.name})

    def list_backups(self) -> None:
        session = self.require_session()
        if not session:
            return
        if session["role"] not in ("Administrateur", "Directeur"):
            self.json_response(403, {"ok": False, "error": "Accès administrateur requis"})
            return
        files = sorted(BACKUP_DIR.glob("maman-rosa-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
        self.json_response(200, {"ok": True, "backups": [{"name": p.name, "size": p.stat().st_size, "created_at": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat()} for p in files]})

    def backup_from_query(self) -> Path | None:
        name = parse_qs(urlparse(self.path).query).get("name", [""])[0]
        if not name or Path(name).name != name:
            return None
        candidate = BACKUP_DIR / name
        return candidate if candidate.is_file() and candidate.suffix == ".db" else None

    def download_backup(self) -> None:
        session = self.require_session()
        if not session:
            return
        if session["role"] not in ("Administrateur", "Directeur"):
            self.json_response(403, {"ok": False, "error": "Accès administrateur requis"})
            return
        target = self.backup_from_query()
        if not target:
            self.json_response(404, {"ok": False, "error": "Sauvegarde introuvable"})
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.sqlite3")
        self.send_header("Content-Disposition", f'attachment; filename="{target.name}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def test_backup(self) -> None:
        session = self.require_session(csrf=True)
        if not session:
            return
        if session["role"] not in ("Administrateur", "Directeur"):
            self.json_response(403, {"ok": False, "error": "Accès administrateur requis"})
            return
        payload = self.read_json()
        name = str(payload.get("name", ""))
        target = BACKUP_DIR / name if name and Path(name).name == name else None
        if not target or not target.is_file():
            self.json_response(404, {"ok": False, "error": "Sauvegarde introuvable"})
            return
        with sqlite3.connect(target) as verification:
            result = verification.execute("PRAGMA integrity_check").fetchone()[0]
            verification.execute("SELECT state_json FROM app_state WHERE id=1").fetchone()
        with db() as conn:
            conn.execute("INSERT INTO audit_log(user_id,action,details,created_at) VALUES(?,?,?,?)", (session["user_id"], "backup_tested", json.dumps({"file": name, "result": result}), utc_now()))
        self.json_response(200, {"ok": result == "ok", "result": result})

    def restore_backup(self) -> None:
        session = self.require_session(csrf=True)
        if not session:
            return
        if session["role"] != "Administrateur":
            self.json_response(403, {"ok": False, "error": "Restauration réservée à l’administrateur"})
            return
        payload = self.read_json()
        name = str(payload.get("name", ""))
        confirmation = str(payload.get("confirmation", ""))
        target = BACKUP_DIR / name if name and Path(name).name == name else None
        if confirmation != "RESTAURER" or not target or not target.is_file():
            self.json_response(400, {"ok": False, "error": "Sauvegarde ou confirmation invalide"})
            return
        with sqlite3.connect(target) as verification:
            if verification.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                self.json_response(400, {"ok": False, "error": "Sauvegarde corrompue"})
                return
        backup_database("avant-restauration")
        with LOCK, sqlite3.connect(target) as source, db() as destination:
            source.backup(destination)
            destination.execute("DELETE FROM sessions")
            destination.execute("INSERT INTO audit_log(user_id,action,details,created_at) VALUES(NULL,?,?,?)", ("database_restored", json.dumps({"file": name, "by": session["username"]}), utc_now()))
        self.json_response(200, {"ok": True, "message": "Base restaurée. Reconnexion nécessaire."})


def main() -> None:
    parser = argparse.ArgumentParser(description="Serveur Espace Maman Rosa")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8766")))
    args = parser.parse_args()
    if os.environ.get("APP_ENV") == "production":
        required = ["MAMAN_ROSA_ADMIN_PASSWORD", "MAMAN_ROSA_DIRECTEUR_PASSWORD", "MAMAN_ROSA_RECEPTION_PASSWORD", "MAMAN_ROSA_CAISSE_PASSWORD", "MAMAN_ROSA_DATA_KEY"]
        missing = [name for name in required if len(os.environ.get(name, "")) < 12]
        if missing:
            raise RuntimeError("Variables secrètes manquantes ou trop courtes: " + ", ".join(missing))
    init_db()
    backup_database("startup")
    threading.Thread(target=daily_backup_worker, daemon=True).start()
    threading.Thread(target=expired_passage_worker, daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Espace Maman Rosa: http://127.0.0.1:{args.port}")
    print("Accès réseau: utilisez l'adresse IP de ce PC sur le même Wi-Fi/LAN")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
