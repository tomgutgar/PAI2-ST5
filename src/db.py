"""Base de datos append-only (RF1.b) y hash de contraseñas (O1, RF2). Solo sqlite3/hashlib (stdlib)."""
# ruff: noqa: I001  (el orden importa: common antes que hashlib)
import common  # noqa: F401  (fija OPENSSL_CONF antes de que hashlib cargue OpenSSL)
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone

ITER = 600_000  # PBKDF2-HMAC-SHA256 (coste medido: ~0,23 s/hash en el portátil del grupo)
ROLES = ("PDI", "PAS", "INV")

ESQUEMA = """
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY, role TEXT NOT NULL CHECK (role IN ('PDI','PAS','INV')),
    pwd_hash BLOB NOT NULL, salt BLOB NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS certs(
    serial TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username),
    sha256_fingerprint TEXT NOT NULL UNIQUE, pubkey_sha256 TEXT NOT NULL, issued_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS revocations(
    serial TEXT PRIMARY KEY REFERENCES certs(serial), revoked_at TEXT NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrol_codes(
    code_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PDI','PAS','INV')), used_at TEXT);
CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, text TEXT NOT NULL, ts TEXT NOT NULL);
"""
# RF1.b: inmutabilidad garantizada por la propia BD, no por la buena voluntad del código
for _t in ("users", "certs", "revocations", "messages"):
    ESQUEMA += f"""
CREATE TRIGGER IF NOT EXISTS {_t}_no_update BEFORE UPDATE ON {_t} BEGIN SELECT RAISE(ABORT, 'registro inmutable'); END;
CREATE TRIGGER IF NOT EXISTS {_t}_no_delete BEFORE DELETE ON {_t} BEGIN SELECT RAISE(ABORT, 'registro inmutable'); END;"""
ESQUEMA += """
CREATE TRIGGER IF NOT EXISTS enrol_codes_un_uso BEFORE UPDATE ON enrol_codes
WHEN OLD.used_at IS NOT NULL OR NEW.used_at IS NULL OR NEW.code_hash IS NOT OLD.code_hash
     OR NEW.username IS NOT OLD.username OR NEW.role IS NOT OLD.role
BEGIN SELECT RAISE(ABORT, 'registro inmutable'); END;
CREATE TRIGGER IF NOT EXISTS enrol_codes_no_delete BEFORE DELETE ON enrol_codes
BEGIN SELECT RAISE(ABORT, 'registro inmutable'); END;
"""


def ahora():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_password(pwd, salt):
    return hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, ITER)


def password_ok(pwd, salt, esperado):
    return hmac.compare_digest(hash_password(pwd, salt), esperado)


def hash_codigo(code):
    return hashlib.sha256(code.encode()).hexdigest()  # código aleatorio de 128 bits: no necesita sal


class DB:
    # una conexión + lock global; con más carga, una conexión por hilo
    def __init__(self, ruta):
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        self.cx = sqlite3.connect(ruta, check_same_thread=False, isolation_level=None)
        self.cx.execute("PRAGMA foreign_keys = ON")
        self.cx.executescript(ESQUEMA)
        self.cx.execute("PRAGMA synchronous = NORMAL")
        self.lock = threading.Lock()

    def uno(self, sql, *args):
        with self.lock:
            return self.cx.execute(sql, args).fetchone()

    def usuario(self, username):
        return self.uno("SELECT role, pwd_hash, salt FROM users WHERE username=?", username)

    def cert_activo(self, username):
        """Último certificado emitido del usuario que no esté revocado: (serial, huella) o None."""
        return self.uno("""SELECT serial, sha256_fingerprint FROM certs
                           WHERE username=? AND serial NOT IN (SELECT serial FROM revocations)
                           ORDER BY rowid DESC LIMIT 1""", username)

    def nuevo_codigo(self, username, role):
        code = secrets.token_urlsafe(16)
        with self.lock:
            self.cx.execute("INSERT INTO enrol_codes(code_hash, username, role) VALUES (?,?,?)",
                            (hash_codigo(code), username, role))
        return code

    def codigo_valido(self, code, username):
        """Rol fijado por el administrador, o None si el código no existe, es de otro usuario o ya se usó."""
        fila = self.uno("SELECT role FROM enrol_codes WHERE code_hash=? AND username=? AND used_at IS NULL",
                        hash_codigo(code), username)
        return fila[0] if fila else None

    def alta(self, username, role, pwd_hash, salt, code, cert, crear_usuario):
        """Inserta (usuario si es nuevo) + certificado y consume el código, todo o nada."""
        with self.lock:
            self.cx.execute("BEGIN IMMEDIATE")
            try:
                if crear_usuario:
                    self.cx.execute("INSERT INTO users VALUES (?,?,?,?,?)", (username, role, pwd_hash, salt, ahora()))
                self.cx.execute("INSERT INTO certs VALUES (?,?,?,?,?)",
                                (cert["serial"], username, cert["huella"], cert["pubkey_sha256"], ahora()))
                if code is not None:
                    cur = self.cx.execute("UPDATE enrol_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL",
                                          (ahora(), hash_codigo(code)))
                    if cur.rowcount != 1:
                        raise sqlite3.IntegrityError("código ya usado")
                self.cx.execute("COMMIT")
            except BaseException:
                self.cx.execute("ROLLBACK")
                raise

    def revocar(self, serial, motivo):
        with self.lock:
            self.cx.execute("INSERT OR IGNORE INTO revocations VALUES (?,?,?)", (serial, ahora(), motivo))

    def mensaje(self, username, text):
        with self.lock:
            return self.cx.execute("INSERT INTO messages(username, text, ts) VALUES (?,?,?)",
                                   (username, text, ahora())).lastrowid
