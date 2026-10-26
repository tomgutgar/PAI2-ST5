"""Piezas compartidas: política TLS (RS2), contextos TLS (RS1.b), protocolo JSON y auditoría (RS4.b).

IMPORTANTE: este módulo debe importarse ANTES que cualquier otro que cargue OpenSSL (ssl, hashlib,
secrets, hmac...). OPENSSL_CONF solo surte efecto si está fijado antes de que OpenSSL se inicialice.
"""
import os

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["OPENSSL_CONF"] = os.path.join(RAIZ, "openssl_tls13.cnf")  # RS2.a, RS2.b (nunca uno heredado del entorno)
os.umask(0o077)  # BD, audit.log y claves solo legibles por su dueño (hashes, IPs: RGPD)

import json
import logging
import re
import ssl
import subprocess
import sys
from datetime import datetime, timezone

PKI = os.path.join(RAIZ, "pki")
CA_CRT = os.path.join(PKI, "ca", "ca.crt")
CRL = os.path.join(PKI, "ca", "crl.pem")
SERVER_CRT = os.path.join(PKI, "server", "server.crt")
SERVER_KEY = os.path.join(PKI, "server", "server.key")
PKI_SH = os.path.join(PKI, "pki.sh")
DATOS = os.path.join(RAIZ, "datos")
DB_PATH = os.environ.get("PAI2_DB", os.path.join(DATOS, "vpn.db"))
CLIENTES = os.path.join(RAIZ, "clientes")
LOGS = os.path.join(RAIZ, "evidencias", "logs")
AUDIT_LOG = os.path.join(LOGS, "audit.log")

HOST = "127.0.0.1"
SERVER_NAME = "localhost"
PUERTO_VPN = 7443   # TLS 1.3 + mTLS
PUERTO_ALTA = 8443  # TLS 1.3, solo autenticación del servidor (el dispositivo aún no tiene certificado)
SUITES_PERMITIDAS = ("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")  # RS2.b
MAX_LINEA = 64 * 1024
ENV_CLI = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}  # la CLI openssl no hereda la política TLS


def openssl(*args, entrada=None):
    """Ejecuta la CLI `openssl` (PKI y CSR). Lanza CalledProcessError/TimeoutExpired si falla."""
    return subprocess.run(["openssl", *args], input=entrada, capture_output=True, check=True,
                          env=ENV_CLI, timeout=30).stdout


def politica_efectiva(ctx=None):
    """Lo que OpenSSL va a aplicar de verdad (se audita al arrancar, sobre el contexto real del servidor)."""
    ctx = ctx or ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    suites = [c["name"] for c in ctx.get_ciphers() if c["protocol"] == "TLSv1.3"]
    with open(os.environ["OPENSSL_CONF"]) as f:  # ssl no expone los grupos: se leen del fichero cargado
        grupos = re.search(r"^Groups\s*=\s*(\S+)", f.read(), re.MULTILINE)
    return {"min": ctx.minimum_version.name, "max": ctx.maximum_version.name, "suites": suites,
            "grupos": grupos.group(1) if grupos else "?", "openssl": ssl.OPENSSL_VERSION,
            "openssl_conf": os.environ["OPENSSL_CONF"]}


def comprobar_politica():
    """Aborta si OPENSSL_CONF no se cargó (p. ej. porque se importó hashlib antes que este módulo)."""
    p = politica_efectiva()
    if sorted(p["suites"]) != sorted(SUITES_PERMITIDAS) or p["max"] != "TLSv1_3":
        sys.exit(f"✘ Política TLS no cargada ({p}). Importa common antes que ssl/hashlib "
                 f"o exporta OPENSSL_CONF={os.path.join(RAIZ, 'openssl_tls13.cnf')}")
    return p


def _tls13(ctx):
    # Defensa en profundidad: no depender solo del fichero de OpenSSL (RS2.a)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def contexto_servidor(mtls=True):
    """mtls=True -> :7443 (RS1.b: exige certificado de cliente válido y no revocado). False -> :8443 (alta)."""
    ctx = _tls13(ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=CA_CRT))
    ctx.load_cert_chain(SERVER_CRT, SERVER_KEY)
    ctx.num_tickets = 0  # sin reanudación de sesión: cada túnel con claves nuevas (RF4, PFS)
    if mtls:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        ctx.load_verify_locations(CRL)
    return ctx


def contexto_cliente(cert=None, key=None):
    """El cliente valida SIEMPRE el certificado y el nombre del gateway (RS1.b)."""
    ctx = _tls13(ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CRT))
    if cert:
        ctx.load_cert_chain(cert, key)
    return ctx


# --- Protocolo: una línea JSON por mensaje -----------------------------------------------------

def enviar(f, obj):
    f.write(json.dumps(obj, ensure_ascii=False).encode() + b"\n")
    f.flush()


def recibir(f):
    """Devuelve el dict recibido, o None si el otro extremo cerró. Valida tamaño y formato."""
    linea = f.readline(MAX_LINEA + 1)
    if not linea:
        return None
    if len(linea) > MAX_LINEA or not linea.endswith(b"\n"):
        raise ValueError("línea demasiado larga o incompleta")
    obj = json.loads(linea)
    if not isinstance(obj, dict):
        raise TypeError("se esperaba un objeto JSON")
    return obj


# --- Auditoría (RS4.b) -------------------------------------------------------------------------

class _FormatoAudit(logging.Formatter):
    def format(self, r):
        ts = datetime.fromtimestamp(r.created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return f"{ts} | AUDIT | {r.getMessage()}"


audit_logger = logging.getLogger("audit")


def configurar_auditoria(consola=True):
    if audit_logger.handlers:  # idempotente: dos llamadas no duplican líneas
        return
    os.makedirs(LOGS, exist_ok=True)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    manejadores = [logging.FileHandler(AUDIT_LOG, encoding="utf-8")]
    if consola:
        manejadores.append(logging.StreamHandler(sys.stdout))
    for h in manejadores:
        h.setFormatter(_FormatoAudit())
        audit_logger.addHandler(h)


def _limpio(v):
    """Lo que llega del cliente no puede romper el formato ni inyectar líneas falsas en el log (RS4.b)."""
    return re.sub(r"[\x00-\x1f\x7f|]", "?", str(v))[:80]


def audit(evento, origen="-", **campos):
    """Una línea por evento. NUNCA pasar contraseñas, códigos de alta ni texto de mensajes (RGPD)."""
    extra = " | ".join(f"{k}={_limpio(v)}" for k, v in campos.items())
    audit_logger.info(f"{evento:<15} | {origen} | {extra}".rstrip(" |"))
