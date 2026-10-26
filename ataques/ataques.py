"""Catálogo de pruebas de ataque contra el gateway de LABORATORIO (O4, O5). `make ataques` o `python3 ataques/ataques.py`.

Cada función Axx ataca un servidor de pruebas propio (127.0.0.1, BD temporal) y devuelve (obtenido, bloqueado).
Una sola fuente de verdad: tests/test_seguridad.py importa este módulo y asevera que todo queda BLOQUEADO.
"""
# ruff: noqa: I001  (el orden importa: common antes que ssl/hashlib)
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(AQUI, "..", "src"), os.path.join(AQUI, "..", "bench"), AQUI]
import common
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
from datetime import datetime

import altas
import client
import db as dbm
import mitm_proxy
import plain_server
import server

PWD = "claveSegura1"
CATALOGO = []   # [(id, requisito, descripcion, esperado, funcion)]
SALIDA = os.path.join(common.RAIZ, "evidencias", "ataques")


def ataque(id_, req, que, esperado):
    def deco(f):
        CATALOGO.append((id_, req, que, esperado, f))
        return f
    return deco


class Entorno:
    """Gateway de pruebas + línea base sin cifrar + cuentas de ejemplo. Una instancia por ejecución."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        common.CLIENTES = os.path.join(self.tmp.name, "clientes")
        self.vpn, self.alta, self.plano = (self._libre() for _ in range(3))
        self.db = dbm.DB(os.path.join(self.tmp.name, "atk.db"))
        common.PUERTO_VPN, common.PUERTO_ALTA = self.vpn, self.alta
        _, self.socks = server.arrancar(self.db, self.vpn, self.alta)
        p = plain_server.Plano(self.db)
        self.socks.append(p.escuchar(self.plano, p.atender_plano))
        for u, rol in (("atk_pdi", "PDI"), ("atk_pas", "PAS"), ("atk_brute", "PDI"), ("atk_rev", "INV"), ("atk_logout", "PDI")):
            client.registrar(u, PWD, self.db.nuevo_codigo(u, rol))

    @staticmethod
    def _libre():
        with socket.socket() as s:
            s.bind((common.HOST, 0))
            return s.getsockname()[1]

    def cert(self, user):
        d = os.path.join(common.CLIENTES, user)
        return os.path.join(d, "device.crt"), os.path.join(d, "device.key")

    def cerrar(self):
        for s in self.socks:
            s.close()
        self.tmp.cleanup()


E = None  # se rellena en ejecutar()


def audit_desde(pos):
    with open(common.AUDIT_LOG, encoding="utf-8") as f:
        f.seek(pos)
        return [ln.rstrip() for ln in f if "AUDIT" in ln]


def sondear(ctx, puerto=None, linea=b'{"cmd":"LOGIN","username":"x","password":"y"}\n'):
    """TLS 1.3: el rechazo del certificado de cliente puede aparecer en la 1ª lectura, así que se hace send+recv."""
    try:
        with socket.create_connection((common.HOST, puerto or E.vpn), timeout=10) as raw, \
                ctx.wrap_socket(raw, server_hostname=common.SERVER_NAME) as t:
            t.sendall(linea)
            return "ACEPTADO", t.recv(4096)
    except (ssl.SSLError, OSError) as e:
        return "RECHAZADO", getattr(e, "reason", None) or type(e).__name__


def s_client(*args):
    """openssl s_client sin la política de la app (hace de atacante con otra configuración)."""
    r = subprocess.run(["openssl", "s_client", "-connect", f"{common.HOST}:{E.vpn}", "-servername", "localhost",
                        "-CAfile", common.CA_CRT, *args], input=b"", capture_output=True, timeout=20, env=common.ENV_CLI, check=False)
    return (r.stdout + r.stderr).decode(errors="replace")


# ---------------------------------------------------------------------------------- A01-A10

@ataque("A01", "RS4.a, O1, O4", "Sniffing pasivo de credenciales: login visto por un tercero en el cable",
        "Sin cifrar: la contraseña se ve. Con TLS: 0 apariciones")
def a01():
    visto = {}
    for nombre, destino in (("sin cifrar", E.plano), ("TLS 1.3", E.vpn)):
        p = mitm_proxy.Proxy((common.HOST, destino))
        try:
            t = (client.Tunel(*E.cert("atk_pdi"), puerto=p.puerto) if nombre == "TLS 1.3"
                 else plain_server.ClientePlano(p.puerto))
            t.pedir(cmd="LOGIN", username="atk_pdi", password=PWD)
            t.logout()
            time.sleep(0.3)
            visto[nombre] = sum(d.count(PWD.encode()) for _, d in p.capturas)
        finally:
            p.cerrar()
    return f"apariciones de la contraseña en el cable: sin cifrar={visto['sin cifrar']}, TLS={visto['TLS 1.3']}", \
        visto["sin cifrar"] > 0 and visto["TLS 1.3"] == 0


CLIENTE_TLS12 = """
import socket, ssl, sys
ctx = ssl.create_default_context(cafile=sys.argv[2])
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10) as s, \\
            ctx.wrap_socket(s, server_hostname="localhost") as t:
        print("CONECTADO", t.version())
except ssl.SSLError as e:
    print("RECHAZADO", e.reason)
"""


@ataque("A02", "RS2.a", "Downgrade: cliente Python con maximum_version=TLSv1_2 y openssl s_client -tls1_2/-tls1_1/-tls1",
        "El servidor rechaza todas las versiones < 1.3")
def a02():
    py = subprocess.run([sys.executable, "-I", "-c", CLIENTE_TLS12, str(E.vpn), common.CA_CRT],  # sin nuestra política
                        capture_output=True, text=True, env=common.ENV_CLI, timeout=20, check=False).stdout.strip()
    res, bloqueado = [f"Python TLS 1.2: {py}"], py.startswith("RECHAZADO")
    for flag in ("-tls1_2", "-tls1_1", "-tls1"):
        out = s_client(flag, "-cipher", "DEFAULT:@SECLEVEL=0")
        conectado = "New, TLSv1" in out and "Cipher is (NONE)" not in out
        bloqueado &= not conectado
        res.append(f"{flag}: {'ACEPTADO' if conectado else 'rechazado'}")
    return "; ".join(res), bloqueado


@ataque("A03", "RS2.b", "Cipher suite débil: ofrecer solo TLS_AES_128_GCM_SHA256 / TLS_AES_128_CCM_SHA256", "NO_SHARED_CIPHER")
def a03():
    res, bloqueado = [], True
    for suite in ("TLS_AES_128_GCM_SHA256", "TLS_AES_128_CCM_SHA256"):
        out = s_client("-tls1_3", "-ciphersuites", suite)
        conectado = f"Cipher is {suite}" in out
        bloqueado &= not conectado
        res.append(f"{suite}: {'ACEPTADA' if conectado else 'rechazada'}")
    return "; ".join(res), bloqueado


@ataque("A04", "RS1.b, RF2", "Conexión sin certificado de cliente", "Rechazo en el handshake; sin acceso a la capa de aplicación")
def a04():
    r, motivo = sondear(common.contexto_cliente())
    return f"{r} ({motivo})", r == "RECHAZADO"


@ataque("A05", "RS1.b", "Dispositivo con certificado de una CA falsa del atacante (CN=atk_pdi)", "CERTIFICATE_VERIFY_FAILED / unknown ca")
def a05():
    with tempfile.TemporaryDirectory() as d:
        r, motivo = sondear(common.contexto_cliente(*mitm_proxy.cert_autofirmado(d, "atk_pdi", "extendedKeyUsage=clientAuth")))
    return f"{r} ({motivo})", r == "RECHAZADO"


@ataque("A06", "RS1.a, RS1.b", "Certificado del servidor (serverAuth) presentado como certificado de cliente", "Rechazo por propósito (EKU)")
def a06():
    r, motivo = sondear(common.contexto_cliente(common.SERVER_CRT, common.SERVER_KEY))
    return f"{r} ({motivo})", r == "RECHAZADO"


@ataque("A07", "RF2", "Certificado válido de A (atk_pdi) + usuario y contraseña correctos de B (atk_pas)", "LOGIN_FAIL cn_no_coincide")
def a07():
    t = client.Tunel(*E.cert("atk_pdi"))
    r = t.pedir(cmd="LOGIN", username="atk_pas", password=PWD)
    t.cerrar()
    return f"respuesta: {r}", not r["ok"]


@ataque("A08", "RF2, RS4.b", "Fuerza bruta: 10 contraseñas malas y luego la correcta", "5 LOGIN_FAIL → LOCKOUT; la correcta falla durante el bloqueo")
def a08():
    for i in range(10):
        try:
            client.sesion("atk_brute", f"intento-{i}-mala")
        except PermissionError:
            pass
    try:
        client.sesion("atk_brute", PWD)
        return "la contraseña correcta entró durante el bloqueo", False
    except PermissionError:
        return "10 intentos fallidos; la contraseña correcta también fue rechazada (cuenta bloqueada)", True


@ataque("A09", "RF1.b, RS1.a", "Certificado revocado: uso del certificado antiguo de atk_rev", "'certificate revoked' en el handshake")
def a09():
    t, _ = client.sesion("atk_rev", PWD)
    t.logout()
    altas.revocar(E.db, "atk_rev")
    time.sleep(0.1)
    r, motivo = sondear(common.contexto_cliente(*E.cert("atk_rev")))
    return f"{r} ({motivo})", r == "RECHAZADO"


@ataque("A10", "RF1.b", "Manipulación directa de la BD: cambiar rol, huella del certificado o borrar registros", "'registro inmutable' (trigger)")
def a10():
    res, bloqueado = [], True
    for sql in ("UPDATE users SET role='INV' WHERE username='atk_pdi'",
                "UPDATE certs SET sha256_fingerprint='00' WHERE username='atk_pdi'",
                "DELETE FROM certs WHERE username='atk_pdi'"):
        try:
            E.db.cx.execute(sql)
            bloqueado = False
            res.append(f"{sql.split()[0]}: APLICADO")
        except sqlite3.DatabaseError as e:
            res.append(f"{sql.split()[0]}: {e}")
    return "; ".join(res), bloqueado


# ---------------------------------------------------------------------------------- A11-A19

@ataque("A11", "RS2, O1", "Texto plano contra el puerto TLS: enviar JSON de login sin cifrar a :7443", "Rechazo en el handshake; nada procesado")
def a11():
    with socket.create_connection((common.HOST, E.vpn), timeout=10) as s:
        s.sendall(b'{"cmd":"LOGIN","username":"atk_pdi","password":"x"}\n')
        s.settimeout(5)
        try:
            resp = s.recv(4096)
        except OSError:
            resp = b""
    return f"respuesta del servidor: {resp[:20]!r} (sin JSON de aplicación)", b'"ok"' not in resp


@ataque("A12", "RS1.b, O5", "Servidor falso: (a) certificado autofirmado, (b) certificado de dispositivo (clientAuth) de otra identidad", "El cliente aborta: posible suplantación")
def a12():
    res, bloqueado = [], True
    with tempfile.TemporaryDirectory() as d:
        falso = mitm_proxy.contexto_falso(d)
        crt, key = E.cert("atk_pas")
        ajeno = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ajeno.load_cert_chain(crt, key)
        for nombre, ctx in (("autofirmado", falso), ("cert de dispositivo ajeno", ajeno)):
            srv = socket.create_server((common.HOST, 0))
            threading.Thread(target=lambda s=srv, c=ctx: _servir_una_vez(s, c), daemon=True).start()
            try:
                client.Tunel(puerto=srv.getsockname()[1])
                bloqueado = False
                res.append(f"{nombre}: el cliente CONECTÓ")
            except ssl.SSLError as e:
                res.append(f"{nombre}: {getattr(e, 'reason', 'SSLError')} → «{client.traducir(e)}»")
            finally:
                srv.close()
    return " | ".join(res), bloqueado


def _servir_una_vez(srv, ctx):
    try:
        c, _ = srv.accept()
        ctx.wrap_socket(c, server_side=True).close()
    except (ssl.SSLError, OSError):
        pass


def _sesion_por_proxy(proxy):
    t = client.Tunel(*E.cert("atk_pdi"), puerto=proxy.puerto)
    r = t.pedir(cmd="LOGIN", username="atk_pdi", password=PWD)
    t.logout()
    return r


@ataque("A13", "O5, RS4.a", "MITM pasivo (relé): el atacante reenvía y vuelca todo lo que ve", "La sesión funciona, pero el atacante solo ve registros cifrados")
def a13():
    p = mitm_proxy.Proxy((common.HOST, E.vpn))
    try:
        r = _sesion_por_proxy(p)
        time.sleep(0.3)
        flujo = b"".join(d for _, d in p.capturas)
        os.makedirs(SALIDA, exist_ok=True)
        with open(os.path.join(SALIDA, "A13_volcado_mitm_pasivo.txt"), "w") as f:
            f.write("# Lo que ve el atacante en el cable (hex, primeros 48 B de cada fragmento)\n")
            f.writelines(f"{sent} {len(d):5d} B  {d[:48].hex()}\n" for sent, d in p.capturas)
        ve_pwd = PWD.encode() in flujo or b'"cmd"' in flujo  # ni la contraseña ni el JSON de aplicación
        return f"login OK a través del relé={r['ok']}; bytes vistos={len(flujo)}; contraseña/JSON legibles={ve_pwd}", r["ok"] and not ve_pwd
    finally:
        p.cerrar()


@ataque("A14", "O5, integridad", "MITM activo: invertir un bit de un registro cifrado en tránsito", "Fallo de integridad AEAD (bad record mac); conexión abortada y auditada")
def a14():
    p = mitm_proxy.Proxy((common.HOST, E.vpn), "manipular", n=3)
    try:
        try:
            r = _sesion_por_proxy(p)
            return f"la sesión sobrevivió a la manipulación: {r}", False
        except (ssl.SSLError, OSError, ConnectionError, ValueError) as e:
            time.sleep(0.3)
            return f"{'; '.join(p.eventos)} → la víctima/servidor abortan: {getattr(e, 'reason', None) or type(e).__name__}", True
    finally:
        p.cerrar()


@ataque("A15", "O5, RS1.b", "MITM con terminación TLS: el atacante presenta su propio certificado a la víctima", "El cliente rechaza; el atacante no obtiene credenciales")
def a15():
    with tempfile.TemporaryDirectory() as d:
        p = mitm_proxy.Proxy((common.HOST, E.vpn), "suplantar", ctx_falso=mitm_proxy.contexto_falso(d))
        try:
            try:
                _sesion_por_proxy(p)
                return "la víctima conectó con el atacante", False
            except ssl.SSLError as e:
                time.sleep(0.3)
                robado = any(PWD.encode() in dat for _, dat in p.capturas)
                return f"{getattr(e, 'reason', 'SSLError')} → «{client.traducir(e)}»; credenciales robadas={robado}", not robado
        finally:
            p.cerrar()


@ataque("A16", "O5, integridad", "Replay: reenviar a :7443 en una conexión nueva los bytes cliente→servidor grabados de una sesión real", "El handshake falla; no se ejecuta nada")
def a16():
    p = mitm_proxy.Proxy((common.HOST, E.vpn))
    try:
        _sesion_por_proxy(p)
        time.sleep(0.3)
        grabado = b"".join(d for sent, d in p.capturas if sent == "c→s")
    finally:
        p.cerrar()
    pos = os.path.getsize(common.AUDIT_LOG)
    with socket.create_connection((common.HOST, E.vpn), timeout=10) as s:
        s.settimeout(5)
        try:
            s.sendall(grabado)
            s.recv(65536)
        except OSError:
            pass
        time.sleep(0.5)
    nuevos = audit_desde(pos)
    ejecutado = any("LOGIN_OK" in ln or "MSG" in ln for ln in nuevos)
    return f"reenviados {len(grabado)} bytes; LOGIN_OK/MSG tras el replay={ejecutado}", not ejecutado


@ataque("A17", "RF4", "Uso tras logout y reanudación de sesión", "El envío falla; session_reused=False; nuevo handshake completo")
def a17():
    t, _ = client.sesion("atk_logout", PWD)
    vieja, ctx = t.tls.session, t.tls.context
    t.logout()
    try:
        t.tls.send(b"{}\n")
        return "el socket aún admitía datos tras LOGOUT", False
    except (ssl.SSLError, OSError, ValueError):
        pass
    with socket.create_connection((common.HOST, E.vpn)) as raw, \
            ctx.wrap_socket(raw, server_hostname=common.SERVER_NAME, session=vieja) as t2:
        return f"envío tras LOGOUT rechazado; session_reused={t2.session_reused}", not t2.session_reused


@ataque("A18", "RF2, RF5", "Comandos sin autenticar y acceso a un recurso fuera de perfil", "Rechazo + ACCESS_DENIED auditado")
def a18():
    t = client.Tunel(*E.cert("atk_pas"))
    antes = t.pedir(cmd="GET", resource="correo")
    t.cerrar()
    t, _ = client.sesion("atk_pas", PWD)
    fuera = t.pedir(cmd="GET", resource="bd_investigacion")
    t.logout()
    return f"GET sin login → {antes}; PAS pide bd_investigacion → {fuera}", not antes["ok"] and fuera.get("error") == "ACCESS_DENIED"


@ataque("A19", "RS3.a", "Agotamiento: 50 sockets TCP abiertos sin hacer handshake (mientras entra un cliente legítimo)", "El timeout de 10 s los cierra; el cliente legítimo sigue entrando")
def a19():
    socks = [socket.create_connection((common.HOST, E.vpn)) for _ in range(50)]
    try:
        t, rol = client.sesion("atk_pdi", PWD)  # un usuario legítimo entra mientras los 50 están colgados
        t.pedir(cmd="LOGOUT")
        t.cerrar()
        time.sleep(server.TIMEOUT_HANDSHAKE + 1.5)
        cerrados = 0
        for s in socks:
            s.settimeout(1)
            try:
                cerrados += s.recv(1) == b""
            except OSError:
                cerrados += 1
        return f"cliente legítimo ({rol}) entró con 50 conexiones colgadas; {cerrados}/50 cerradas por timeout", cerrados == 50
    finally:
        for s in socks:
            s.close()


# ---------------------------------------------------------------------------------- ejecutor

def ejecutar(filtro=None, salida=print, guardar=True):
    """Devuelve [(id, bloqueado)]. Narra cada ataque y adjunta las líneas de auditoría que lo registraron."""
    global E
    common.configurar_auditoria(consola=False)
    resultados, lineas = [], []
    try:
        E = Entorno()
        for id_, req, que, esperado, f in CATALOGO:
            if filtro and id_ not in filtro:
                continue
            pos = os.path.getsize(common.AUDIT_LOG)
            try:
                obtenido, bloqueado = f()
            except Exception as e:  # noqa: BLE001  un fallo inesperado cuenta como VULNERABLE y se muestra
                obtenido, bloqueado = f"excepción inesperada: {type(e).__name__}: {e}", False
            time.sleep(0.2)
            clave = ("REJECT", "FAIL", "LOCKOUT", "DENIED", "UNAUTH", "ERROR", "REVOKE", "CAPACITY", "LOGOUT")
            ev = [ln for ln in audit_desde(pos) if any(k in ln for k in clave)][:3]
            veredicto = "BLOQUEADO" if bloqueado else "VULNERABLE"
            bloque = [f"\n{id_} · {req}", f"  Qué hace el atacante : {que}", f"  Resultado esperado   : {esperado}",
                      f"  Resultado obtenido   : {obtenido}", f"  Veredicto            : {veredicto}"]
            bloque += [f"  audit.log            : {ln[:170]}" for ln in ev] or ["  audit.log            : (el rechazo ocurre antes de la capa de aplicación o en el cliente)"]
            for ln in bloque:
                salida(ln)
            lineas += bloque
            resultados.append((id_, bloqueado))
    finally:
        if E:
            E.cerrar()
    tabla = ["\nRESUMEN"] + [f"  {i}  {'BLOQUEADO' if b else 'VULNERABLE'}" for i, b in resultados]
    tabla.append(f"  → {sum(b for _, b in resultados)}/{len(resultados)} bloqueados")
    for ln in tabla:
        salida(ln)
    if not guardar:
        return resultados
    os.makedirs(SALIDA, exist_ok=True)
    with open(os.path.join(SALIDA, f"resultado_{datetime.now().astimezone():%Y%m%d_%H%M%S}.log"), "w", encoding="utf-8") as f:
        f.write("\n".join(lineas + tabla) + "\n")
    return resultados


if __name__ == "__main__":
    res = ejecutar(set(sys.argv[1:]) or None)
    sys.exit(0 if all(b for _, b in res) else 1)
