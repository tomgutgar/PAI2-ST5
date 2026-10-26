"""Alta de dispositivos y ciclo de vida de certificados (RF1.a, RF1.b, RS1.a). Compartido por server.py y seed.py."""
# ruff: noqa: I001  (el orden importa: common antes que ssl/hashlib)
import common
import base64
import hashlib
import re
import secrets
import sqlite3
import ssl
import subprocess
import tempfile
import threading

import db as dbm

USUARIO_RE = re.compile(r"^[a-z0-9_]{3,32}$")
# Serializa altas y revocaciones dentro del proceso: sin él, dos REGISTER simultáneos con el mismo código
# o el mismo usuario pasarían ambos las comprobaciones y la CA firmaría dos certificados (uno huérfano).
# Entre procesos, la CA se protege con flock en pki.sh.
_lock_alta = threading.Lock()


def info_cert(pem):
    """Serial, huella SHA-256 del certificado y SHA-256 de su clave pública (lo que se guarda en BD)."""
    der = ssl.PEM_cert_to_DER_cert(pem)
    salida = common.openssl("x509", "-noout", "-serial", "-pubkey", entrada=pem.encode()).decode()
    serial = re.search(r"serial=(\w+)", salida).group(1)
    spki = base64.b64decode("".join(salida.split("-----BEGIN PUBLIC KEY-----")[1].split("-----END")[0].split()))
    return {"serial": serial, "huella": hashlib.sha256(der).hexdigest(),
            "pubkey_sha256": hashlib.sha256(spki).hexdigest()}


def cn_de_csr(csr_pem):
    salida = common.openssl("req", "-noout", "-subject", "-nameopt", "multiline", entrada=csr_pem.encode()).decode()
    m = re.search(r"commonName\s*=\s*(\S+)", salida)
    return m.group(1) if m else None


def firmar_csr(csr_pem, username, role):
    """La CA firma la CSR: la clave privada nunca sale del dispositivo."""
    with tempfile.NamedTemporaryFile("w", suffix=".csr") as f:
        f.write(csr_pem)
        f.flush()
        pem = subprocess.run([common.PKI_SH, "sign", f.name, username, role], capture_output=True,
                             text=True, check=True, timeout=60).stdout
    return pem, info_cert(pem)


def _validar_entrada(username, role, password, csr_pem):
    """Frontera de confianza: todo lo que llega en REGISTER se valida antes de tocar la CA o la BD."""
    if not isinstance(username, str) or not USUARIO_RE.match(username):
        raise ValueError("usuario_invalido")
    if role not in dbm.ROLES:
        raise ValueError("rol_invalido")
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("password_no_cumple_politica")
    if not isinstance(csr_pem, str) or len(csr_pem) > 16384:
        raise ValueError("csr_invalida")


def registrar(base, username, role, password, csr_pem, code=None):
    """Devuelve (pem, info) o lanza ValueError(motivo). El motivo solo va al log, nunca al cliente."""
    _validar_entrada(username, role, password, csr_pem)
    try:
        if cn_de_csr(csr_pem) != username:
            raise ValueError("cn_csr_no_coincide")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        raise ValueError("csr_ilegible") from e
    salt = secrets.token_bytes(16)
    pwd_hash = dbm.hash_password(password, salt)  # fuera del lock: es lo caro (PBKDF2)
    with _lock_alta:
        existente = base.usuario(username)
        if existente:
            # RF1.b: la identidad no cambia; re-emisión solo tras revocar el certificado anterior
            if base.cert_activo(username):
                raise ValueError("ya_tiene_certificado_activo")
            if existente[0] != role or not dbm.password_ok(password, existente[2], existente[1]):
                raise ValueError("reemision_no_coincide_con_identidad")
        if code is not None and base.codigo_valido(code, username) != role:
            raise ValueError("codigo_invalido_o_usado")
        try:
            pem, info = firmar_csr(csr_pem, username, role)
        except subprocess.CalledProcessError as e:
            raise ValueError(f"csr_rechazada:{(e.stderr or '').strip()[:60]}") from e
        except subprocess.TimeoutExpired as e:
            raise ValueError("ca_no_responde") from e
        try:
            base.alta(username, role, pwd_hash, salt, code, info, crear_usuario=not existente)
        except sqlite3.IntegrityError as e:
            raise ValueError(f"bd_rechaza_alta:{e}") from e
    return pem, info


def revocar(base, username, motivo="keyCompromise"):
    """Revoca el certificado vigente: CA (CRL) + registro en BD. Devuelve el serial."""
    with _lock_alta:
        activo = base.cert_activo(username)
        if not activo:
            raise ValueError("sin_certificado_activo")
        try:
            subprocess.run([common.PKI_SH, "revoke", username, motivo], capture_output=True, text=True,
                           check=True, timeout=60)
        except subprocess.CalledProcessError as e:
            common.audit("REVOKE_FAIL", "-", user=username, serial=activo[0], error=(e.stderr or "").strip())
            raise ValueError(f"la CA no pudo revocar: {(e.stderr or '').strip() or 'motivo no válido'}") from e
        base.revocar(activo[0], motivo)
    common.audit("REVOKE", "-", user=username, serial=activo[0], motivo=motivo)
    return activo[0]
