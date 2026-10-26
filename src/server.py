"""Gateway VPN de U-Secure.

  python3 src/server.py                             arranca :7443 (VPN, TLS 1.3 + mTLS) y :8443 (alta)
  python3 src/server.py alta <usuario> <rol>        el administrador autoriza un alta -> código de un solo uso
  python3 src/server.py revocar <usuario> [motivo]  revoca el certificado vigente (RF1.b, RS1.a)
"""
# ruff: noqa: I001  (el orden importa: common antes que ssl/hashlib)
import common
from common import audit
import hashlib
import os
import socket
import ssl
import sys
import threading
import time

import altas
import db as dbm

MAX_SESIONES = 400         # RS3.a: tope de conexiones simultáneas en :7443 (> 300 exigidas)
MAX_ALTAS = 50             # :8443 no pide certificado: su propio tope, para no poder agotar el de la VPN
TIMEOUT_HANDSHAKE = 10     # s, plazo TOTAL del handshake (no por operación): nadie retiene un hilo goteando bytes
PLAZO_LOGIN = 60           # s desde el handshake hasta LOGIN correcto (300 PBKDF2 simultáneos tardan ~20 s)
PLAZO_ALTA = 60            # s para toda la conexión de alta (incluye la firma de la CA)
TIMEOUT_INACTIVIDAD = 300
MAX_TEXTO = 4096           # la tabla de mensajes es inmutable: no se deja llenar el disco con mensajes enormes
MAX_FALLOS, BLOQUEO = 5, 300  # RF2: 5 fallos -> bloqueo de 5 min
GENERICO = {"ok": False, "error": "credenciales inválidas"}

# RF5: perfiles de acceso por rol. Los recursos corporativos se simulan.
RECURSOS = {
    "correo": "Bandeja de entrada corporativa (simulada)",
    "docencia": "Campus virtual: asignaturas y calificaciones (simulado)",
    "gestion": "Gestión administrativa: expedientes, nóminas (simulado)",
    "repositorio": "Repositorio institucional de documentos (simulado)",
    "bd_investigacion": "Base de datos de proyectos de investigación (simulada)",
    "servidores_internos": "Acceso a servidores internos de cómputo (simulado)",
}
PERFILES = {
    "PDI": {"correo", "docencia", "repositorio", "bd_investigacion"},
    "PAS": {"correo", "gestion", "repositorio"},
    "INV": {"correo", "repositorio", "bd_investigacion", "servidores_internos"},
}


def plazo(sock, segundos):
    """Plazo total: al vencer cierra el socket aunque el otro extremo siga goteando bytes. Devuelve el Timer."""
    def cortar():
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # ya estaba cerrado

    t = threading.Timer(segundos, cortar)
    t.daemon = True
    t.start()
    return t


class Gateway:
    def __init__(self, base, tls=True):
        self.db = base
        self.lock = threading.Lock()
        self._lock_ctx = threading.Lock()  # recargar el contexto TLS no bloquea sesiones ni contadores
        self.sem = {"vpn": threading.BoundedSemaphore(MAX_SESIONES), "alta": threading.BoundedSemaphore(MAX_ALTAS)}
        self.fallos = {}  # usuario -> (fallos, caduca). En memoria: se pierde al reiniciar
        self.activas = self.pico = 0
        self._ctx = self._crl_mtime = None
        self.ctx_alta = common.contexto_servidor(mtls=False) if tls else None

    def ctx_vpn(self):
        """Recarga el contexto si la CRL cambió: una revocación surte efecto sin reiniciar (RS1.a).
        Si la recarga falla se lanza la excepción: nunca se sigue con un contexto sin la CRL nueva."""
        mtime = os.stat(common.CRL).st_mtime_ns
        with self._lock_ctx:
            if mtime != self._crl_mtime:
                try:
                    self._ctx, self._crl_mtime = common.contexto_servidor(mtls=True), mtime
                except (ssl.SSLError, OSError) as e:
                    audit("CRL_RELOAD_FAIL", "-", tipo=type(e).__name__)
                    raise
                audit("CRL_RELOAD", "-", crl=os.path.relpath(common.CRL, common.RAIZ))
            return self._ctx

    def _sesion(self, delta):
        with self.lock:
            self.activas += delta
            self.pico = max(self.pico, self.activas)
            if self.activas == 0 and delta < 0:
                audit("SESSIONS_PEAK", "-", pico=self.pico)
                self.pico = 0

    def reservar_intento(self, user):
        """Cuenta el intento ANTES del PBKDF2 (si no, N logins en paralelo esquivarían el bloqueo).
        Devuelve el nº de intento, o None si la cuenta está bloqueada. Los fallos caducan a los 5 min."""
        with self.lock:
            n, caduca = self.fallos.get(user, (0, 0))
            if time.monotonic() >= caduca:
                n = 0
            if n >= MAX_FALLOS:
                return None
            self.fallos[user] = (n + 1, time.monotonic() + BLOQUEO)
            return n + 1

    # -- red --
    def escuchar(self, puerto, manejador, cupo="vpn"):
        s = socket.create_server((common.HOST, puerto), backlog=512)
        threading.Thread(target=self._aceptar, args=(s, manejador, cupo), daemon=True).start()
        return s

    def _aceptar(self, s, manejador, cupo):
        while True:
            try:
                raw, addr = s.accept()
            except OSError as e:
                if s.fileno() == -1:  # socket cerrado: el servidor se está parando
                    return
                audit("ACCEPT_ERROR", "-", tipo=type(e).__name__, errno=e.errno)  # p. ej. EMFILE: se reintenta
                time.sleep(0.1)
                continue
            threading.Thread(target=self._conexion, args=(raw, f"{addr[0]}:{addr[1]}", manejador, cupo),
                             daemon=True).start()

    def _conexion(self, raw, origen, manejador, cupo):
        if not self.sem[cupo].acquire(blocking=False):
            audit("CAPACITY_REJECT", origen, puerto=cupo, limite=MAX_SESIONES if cupo == "vpn" else MAX_ALTAS)
            raw.close()
            return
        try:
            manejador(raw, origen)
        except Exception as e:  # noqa: BLE001  un hilo nunca tumba el servidor; queda auditado con su tipo
            audit("ERROR", origen, tipo=type(e).__name__, detalle=e)
        finally:
            self.sem[cupo].release()
            raw.close()

    def _handshake(self, raw, origen, ctx):
        """Handshake explícito para auditar cada rechazo con su motivo (RS4.b)."""
        audit("CONNECT", origen)
        raw.settimeout(TIMEOUT_HANDSHAKE)
        vigilante = plazo(raw, TIMEOUT_HANDSHAKE)
        conn = ctx.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
        try:
            conn.do_handshake()
        except ssl.SSLError as e:
            detalle = getattr(e, "verify_message", None)  # p. ej. "certificate revoked", "unsupported certificate purpose"
            audit("TLS_REJECT", origen, motivo=e.reason or type(e).__name__, **({"detalle": detalle} if detalle else {}))
            conn.close()
            return None
        except OSError as e:
            audit("TLS_REJECT", origen, motivo="plazo_handshake_agotado" if not vigilante.is_alive() else type(e).__name__)
            conn.close()
            return None
        finally:
            vigilante.cancel()
        version, suite = conn.version(), conn.cipher()[0]
        if version != "TLSv1.3" or suite not in common.SUITES_PERMITIDAS:  # red de seguridad si falta OPENSSL_CONF
            audit("POLICY_REJECT", origen, tls=version, suite=suite)
            conn.close()
            return None
        conn.settimeout(TIMEOUT_INACTIVIDAD)
        return conn

    # -- :8443 alta (RF1.a) --
    def atender_alta(self, raw, origen):
        conn = self._handshake(raw, origen, self.ctx_alta)
        if not conn:
            return
        vigilante = plazo(conn, PLAZO_ALTA)
        f = conn.makefile("rwb")
        try:
            msg = common.recibir(f)
            if msg is None:
                audit("ENROL_FAIL", origen, motivo="conexion_cerrada_sin_peticion")
                return
            if msg.get("cmd") != "REGISTER":  # este puerto solo admite REGISTER
                audit("ENROL_FAIL", origen, motivo="comando_no_permitido")
                common.enviar(f, {"ok": False, "error": "comando no permitido"})
                return
            user, code = msg.get("username"), msg.get("code")
            role = self.db.codigo_valido(code, user) if isinstance(code, str) and isinstance(user, str) else None
            if not role:
                audit("ENROL_FAIL", origen, user=user, motivo="codigo_invalido_o_usado")
                common.enviar(f, {"ok": False, "error": "alta no autorizada"})
                return
            try:
                pem, info = altas.registrar(self.db, user, role, msg.get("password"), msg.get("csr", ""), code)
            except ValueError as e:
                audit("ENROL_FAIL", origen, user=user, motivo=e)
                common.enviar(f, {"ok": False, "error": "alta rechazada"})
                return
            audit("ENROL_OK", origen, user=user, rol=role, serial=info["serial"])
            common.enviar(f, {"ok": True, "cert": pem, "role": role})
        except (ValueError, TypeError, OSError) as e:
            audit("ENROL_FAIL", origen, motivo=f"protocolo:{type(e).__name__}")
        finally:
            vigilante.cancel()
            self._cerrar(conn, f, origen, None)

    # -- :7443 VPN (RF2, RF4, RF5) --
    def atender_vpn(self, raw, origen):
        conn = self._handshake(raw, origen, self.ctx_vpn())
        if not conn:
            return
        try:
            cert = conn.getpeercert()
            cn = dict(x[0] for x in cert["subject"]).get("commonName")
            huella = hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest()
            ctx = {"cn": cn, "serial": cert.get("serialNumber"), "tls": conn.version(), "suite": conn.cipher()[0]}
        except (ValueError, KeyError, TypeError) as e:
            audit("POLICY_REJECT", origen, motivo=f"certificado_ilegible:{type(e).__name__}")
            conn.close()
            return
        audit("TLS_OK", origen, **ctx)
        self._bucle(conn, origen, cn, huella, ctx)

    def vigente(self, usuario, huella):
        """El certificado de la sesión sigue siendo el activo (una revocación corta las sesiones abiertas)."""
        activo = self.db.cert_activo(usuario)
        return bool(activo) and activo[1] == huella

    def _bucle(self, conn, origen, cn, huella, ctx):  # noqa: C901  (despachador de comandos; partirlo no aclara nada)
        """Capa de aplicación (login, MSG, GET, LOGOUT). Aparte del TLS para poder medir la línea base sin cifrar."""
        self._sesion(+1)
        f = conn.makefile("rwb")
        usuario = rol = None  # solo se rellenan tras LOGIN correcto
        vigilante = plazo(conn, PLAZO_LOGIN)  # hasta el LOGIN correcto
        try:
            while (msg := common.recibir(f)) is not None:
                cmd = msg.get("cmd")
                if usuario and not self.vigente(usuario, huella):
                    audit("SESSION_REVOKED", origen, user=usuario, **ctx)
                    common.enviar(f, {"ok": False, "error": "certificado revocado: sesión cerrada"})
                    break
                if cmd == "LOGIN":
                    if usuario:
                        audit("LOGIN_FAIL", origen, user=usuario, motivo="ya_autenticado", **ctx)
                        common.enviar(f, {"ok": False, "error": "ya autenticado"})
                        continue
                    rol = self._login(msg, origen, cn, huella, ctx)
                    usuario = msg.get("username") if rol else None
                    if usuario:
                        vigilante.cancel()
                    common.enviar(f, {"ok": True, "role": rol} if rol else GENERICO)
                elif cmd == "LOGOUT":
                    audit("LOGOUT", origen, user=usuario, **ctx)
                    common.enviar(f, {"ok": True})
                    break
                elif not usuario:
                    audit("UNAUTH_CMD", origen, cmd=str(cmd)[:16], **ctx)  # RF2: nada sin login previo
                    common.enviar(f, {"ok": False, "error": "no autenticado"})
                elif cmd == "MSG" and isinstance(msg.get("text"), str) and len(msg["text"]) <= MAX_TEXTO:
                    mid = self.db.mensaje(usuario, msg["text"])
                    audit("MSG", origen, user=usuario, id=mid)  # el texto nunca se registra (RGPD)
                    common.enviar(f, {"ok": True, "id": mid})
                elif cmd == "GET":
                    recurso = msg.get("resource")
                    if isinstance(recurso, str) and recurso in PERFILES[rol] and recurso in RECURSOS:
                        common.enviar(f, {"ok": True, "data": RECURSOS[recurso]})
                    else:
                        audit("ACCESS_DENIED", origen, user=usuario, rol=rol, recurso=str(recurso)[:32])
                        common.enviar(f, {"ok": False, "error": "ACCESS_DENIED"})
                else:
                    audit("BAD_REQUEST", origen, user=usuario, cmd=str(cmd)[:16], **ctx)
                    common.enviar(f, {"ok": False, "error": "petición no válida"})
        except (ValueError, TypeError, OSError) as e:
            audit("PROTO_ERROR", origen, tipo=type(e).__name__, **ctx)
        finally:
            vigilante.cancel()
            self._sesion(-1)
            self._cerrar(conn, f, origen, usuario)

    def _cerrar(self, conn, f, origen, usuario):
        """RF4: close_notify + cierre. Sin tickets no queda material de reanudación; las claves de
        tráfico (ECDHE efímero) se liberan con el objeto SSL. DISCONNECT se audita pase lo que pase."""
        try:
            conn.unwrap()
        except (ssl.SSLError, OSError, AttributeError):  # AttributeError: socket plano (solo benchmark)
            pass  # el otro extremo ya cerró
        try:
            f.close()
        except OSError:
            pass  # buffer sin vaciar hacia un socket ya roto
        finally:
            conn.close()
            audit("DISCONNECT", origen, user=usuario)

    def _login(self, msg, origen, cn, huella, ctx):
        """Capa 2 (RF2). Devuelve el rol o None. Cada fallo se audita con su motivo real."""
        user, pwd = msg.get("username"), msg.get("password")
        if not isinstance(user, str) or not isinstance(pwd, str):
            audit("LOGIN_FAIL", origen, user=user if isinstance(user, str) else "?", motivo="formato", **ctx)
            return None
        if user != cn:  # vínculo dispositivo-usuario
            audit("LOGIN_FAIL", origen, user=user, motivo="cn_no_coincide", **ctx)
            return None
        if not self.vigente(user, huella):
            audit("LOGIN_FAIL", origen, user=user, motivo="huella_no_coincide_con_cert_activo", **ctx)
            return None
        # Solo el dueño del certificado llega aquí: nadie puede bloquear la cuenta de otro
        n = self.reservar_intento(user)
        if n is None:
            audit("LOGIN_FAIL", origen, user=user, motivo="bloqueado", **ctx)
            return None
        fila = self.db.usuario(user)
        if not fila or not dbm.password_ok(pwd, fila[2], fila[1]):
            audit("LOGIN_FAIL", origen, user=user, motivo=f"password_incorrecta ({n}/{MAX_FALLOS})", **ctx)
            if n == MAX_FALLOS:
                audit("LOCKOUT", origen, user=user, segundos=BLOQUEO)
            return None
        with self.lock:
            self.fallos.pop(user, None)  # un login correcto reinicia el contador
        audit("LOGIN_OK", origen, user=user, rol=fila[0], **ctx)
        return fila[0]


def arrancar(base=None, puerto_vpn=common.PUERTO_VPN, puerto_alta=common.PUERTO_ALTA):
    """Devuelve (gateway, sockets). Usable desde los tests con puertos libres."""
    common.comprobar_politica()
    altas.subprocess.run([common.PKI_SH, "crl"], capture_output=True, check=True, timeout=60)  # CRL siempre al día
    gw = Gateway(base or dbm.DB(common.DB_PATH))
    pol = common.politica_efectiva(gw.ctx_vpn())  # política del contexto real de :7443
    audit("SERVER_START", "-", tls=f"{pol['min']}..{pol['max']}", suites=",".join(pol["suites"]), grupos=pol["grupos"],
          mtls="CERT_REQUIRED+CRL", tickets=0, ca=os.path.relpath(common.CA_CRT, common.RAIZ),
          crl=os.path.relpath(common.CRL, common.RAIZ), openssl=pol["openssl"])
    print(f"Política TLS efectiva: {pol['min']}..{pol['max']} · {', '.join(pol['suites'])} · grupos {pol['grupos']}", flush=True)
    socks = [gw.escuchar(puerto_vpn, gw.atender_vpn), gw.escuchar(puerto_alta, gw.atender_alta, "alta")]
    return gw, socks


def main():
    common.configurar_auditoria()
    base = dbm.DB(common.DB_PATH)
    args = sys.argv[1:]
    if args[:1] == ["alta"] and len(args) == 3 and args[2] in dbm.ROLES and altas.USUARIO_RE.match(args[1]):
        code = base.nuevo_codigo(args[1], args[2])
        audit("ENROL_CODE", "-", user=args[1], rol=args[2])  # el código nunca se registra
        print(f"Código de alta para {args[1]} ({args[2]}), de un solo uso:\n  {code}")
    elif args[:1] == ["revocar"] and len(args) in (2, 3):
        try:
            serial = altas.revocar(base, args[1], *args[2:])
        except ValueError as e:
            sys.exit(f"✘ {e}")
        print(f"✔ Certificado {serial} de {args[1]} revocado; el gateway recarga la CRL solo.")
    elif not args:
        arrancar(base)
        print(f"Gateway VPN escuchando en :{common.PUERTO_VPN} (túnel) y :{common.PUERTO_ALTA} (alta). Ctrl+C para parar.", flush=True)
        threading.Event().wait()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
