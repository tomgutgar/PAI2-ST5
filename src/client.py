"""Cliente road warrior de U-Secure (dispositivo BYOD).

  python3 src/client.py                                  menú interactivo
  python3 src/client.py register --user U --password P --code C
  python3 src/client.py login|msg|get|logout ...         modo no interactivo (una sola conexión por orden)
"""
# ruff: noqa: I001  (el orden importa: common antes que ssl)
import common
import argparse
import getpass
import os
import re
import socket
import ssl
import subprocess
import sys

OK, KO = "\033[32m✔\033[0m", "\033[31m✘\033[0m"


def dir_cliente(user):
    if not re.fullmatch(r"[a-z0-9_]{3,32}", user or ""):  # además evita rutas tipo ../
        raise PermissionError("usuario no válido (3-32 caracteres: minúsculas, dígitos o _)")
    return os.path.join(common.CLIENTES, user)


def traducir(e):
    """Errores TLS -> mensajes para quien no sabe redes."""
    txt = str(e)
    if "CERTIFICATE_VERIFY_FAILED" in txt or "hostname" in txt:
        return "El servidor no es de confianza: posible suplantación. Conexión cancelada."
    if "revoked" in txt or "CERTIFICATE_REVOKED" in txt:
        return "Tu certificado ha sido revocado. Pide al administrador un alta nueva."
    if "certificate" in txt.lower():
        return "El servidor no ha aceptado el certificado de este dispositivo."
    if isinstance(e, FileNotFoundError):
        return "Este dispositivo no tiene certificado: regístralo primero (opción 1)."
    if isinstance(e, ConnectionRefusedError):
        return "El gateway VPN no responde: ¿está arrancado (make server)?"
    if isinstance(e, (TimeoutError, socket.timeout)):
        return "El gateway VPN tardó demasiado en responder."
    if isinstance(e, ConnectionError):
        return f"El gateway cerró la conexión ({e})."
    return f"No se pudo establecer el túnel seguro ({e.__class__.__name__})."


class Tunel:
    """Una conexión TLS 1.3 con el gateway. Con cert -> :7443 (mTLS); sin cert -> :8443 (alta)."""

    def __init__(self, cert=None, key=None, puerto=None, timeout=60):
        ctx = common.contexto_cliente(cert, key)  # antes de conectar: si falta el certificado no queda un socket abierto
        self.sock = socket.create_connection((common.HOST, puerto or (common.PUERTO_VPN if cert else common.PUERTO_ALTA)),
                                             timeout=timeout)
        try:
            self.tls = ctx.wrap_socket(self.sock, server_hostname=common.SERVER_NAME)
        except (ssl.SSLError, OSError):
            self.sock.close()
            raise
        self.f = self.tls.makefile("rwb")

    def info(self):
        cn = dict(x[0] for x in self.tls.getpeercert()["subject"])
        return f"{self.tls.version()} · {self.tls.cipher()[0]} · servidor: {cn.get('commonName')}"

    def pedir(self, **msg):
        # TLS 1.3: si el servidor rechaza nuestro certificado el error aparece aquí, en la 1ª lectura
        common.enviar(self.f, msg)
        resp = common.recibir(self.f)
        if resp is None:
            raise ConnectionError("el servidor cerró la conexión")
        return resp

    def cerrar(self):
        try:
            self.tls.unwrap()  # close_notify (RF4)
        except (ssl.SSLError, OSError):
            pass
        try:
            self.f.close()  # makefile() retiene una referencia al socket: sin esto close() no lo cierra
        except OSError:
            pass
        self.tls.close()

    def logout(self):
        """RF4: LOGOUT y desmontaje del túnel; el socket se cierra aunque el servidor ya no conteste."""
        try:
            self.pedir(cmd="LOGOUT")
        except (ssl.SSLError, OSError, ValueError):
            pass
        finally:
            self.cerrar()


def generar_csr(user, d):
    """Clave privada RSA 3072 + CSR generadas EN el dispositivo (la clave nunca sale de aquí). Devuelve la CSR."""
    os.makedirs(d, mode=0o700, exist_ok=True)
    key, csr = os.path.join(d, "device.key.nueva"), os.path.join(d, "device.csr")
    common.openssl("req", "-new", "-newkey", "rsa:3072", "-noenc", "-keyout", key, "-out", csr, "-subj", f"/CN={user}")
    os.chmod(key, 0o600)
    with open(csr) as f:
        return f.read()


def activar(d, cert_pem):
    """Guarda el certificado y activa la clave nueva. Solo se llama si la CA ha firmado."""
    with open(os.path.join(d, "device.crt.nuevo"), "w") as f:
        f.write(cert_pem)
    os.replace(os.path.join(d, "device.key.nueva"), os.path.join(d, "device.key"))
    os.replace(os.path.join(d, "device.crt.nuevo"), os.path.join(d, "device.crt"))


def registrar(user, password, code):
    """RF1.a: pide el certificado del dispositivo. Si el alta falla, la clave y el certificado anteriores siguen intactos."""
    d = dir_cliente(user)
    csr_pem = generar_csr(user, d)
    t = Tunel()
    try:
        print(f"{OK} Túnel seguro con el servidor: {t.info()}")
        resp = t.pedir(cmd="REGISTER", username=user, password=password, code=code, csr=csr_pem)
    finally:
        t.cerrar()
    if not resp.get("ok"):
        os.remove(os.path.join(d, "device.key.nueva"))
        raise PermissionError(resp.get("error", "alta rechazada"))
    activar(d, resp["cert"])
    return resp["role"]


def sesion(user, password):
    """Abre el túnel mTLS y hace LOGIN (RF2). Devuelve (túnel, rol)."""
    d = dir_cliente(user)
    t = Tunel(os.path.join(d, "device.crt"), os.path.join(d, "device.key"))
    try:
        resp = t.pedir(cmd="LOGIN", username=user, password=password)
    except BaseException:
        t.cerrar()
        raise
    if not resp.get("ok"):
        t.cerrar()
        raise PermissionError(resp.get("error"))
    return t, resp["role"]


def uso_unico(args):
    """Modo no interactivo: LOGIN + una orden + LOGOUT."""
    t, rol = sesion(args.user, args.password)
    try:
        if args.orden == "login":
            print(f"{OK} Sesión iniciada como {args.user} ({rol}) · {t.info()}")
        elif args.orden in ("msg", "get"):
            r = (t.pedir(cmd="MSG", text=args.texto) if args.orden == "msg"
                 else t.pedir(cmd="GET", resource=args.recurso))
            print(r)
            if not r.get("ok"):
                raise PermissionError(r.get("error"))
    finally:
        t.logout()


def menu():  # noqa: C901  (menú: una rama por opción)
    t = user = None
    while True:
        print(f"\n--- U-Secure VPN ---  {'sesión: ' + user if t else 'sin sesión'}\n"
              "1) Registrar dispositivo  2) Iniciar sesión  3) Enviar mensaje\n"
              "4) Acceder a recurso      5) Cerrar sesión   0) Salir")
        op = input("> ").strip()
        try:
            if op == "1":
                u = input("Usuario: ")
                role = registrar(u, getpass.getpass("Contraseña (≥8): "), input("Código de alta: ").strip())
                print(f"{OK} Dispositivo registrado como {role}. Ya puedes iniciar sesión.")
            elif op == "2" and not t:
                user = input("Usuario: ")
                t, rol = sesion(user, getpass.getpass("Contraseña: "))
                print(f"{OK} Túnel establecido: {t.info()} · rol {rol}")
            elif op in ("3", "4") and t:
                r = (t.pedir(cmd="MSG", text=input("Mensaje: ")) if op == "3"
                     else t.pedir(cmd="GET", resource=input("Recurso (correo, docencia, gestion…): ")))
                print(f"{OK if r.get('ok') else KO} {r}")
            elif op == "5" and t:
                t.logout()
                t = None
                print(f"{OK} Sesión cerrada y túnel destruido.")
            elif op == "0":
                if t:
                    t.logout()
                return
            else:
                print("Opción no válida (¿falta iniciar sesión?).")
        except (PermissionError, subprocess.CalledProcessError) as e:
            print(f"{KO} {e}")
        except (ssl.SSLError, OSError) as e:
            print(f"{KO} {traducir(e)}")
            if t:
                t.cerrar()
            t = None


def main():  # noqa: C901  (argparse: una rama por orden)
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="orden")
    for nombre in ("register", "login", "msg", "get", "logout"):
        s = sub.add_parser(nombre)
        s.add_argument("--user", required=True)
        s.add_argument("--password", help="si se omite se pide sin eco (no queda en el historial ni en `ps`)")
        if nombre == "register":
            s.add_argument("--code", required=True)
        if nombre == "msg":
            s.add_argument("--texto", required=True)
        if nombre == "get":
            s.add_argument("--recurso", required=True)
    a = p.parse_args()
    if a.orden and not a.password:
        a.password = getpass.getpass("Contraseña: ")
    try:
        if not a.orden:
            menu()
        elif a.orden == "register":
            role = registrar(a.user, a.password, a.code)
            print(f"{OK} Dispositivo registrado como {role}")
        else:
            uso_unico(a)
    except PermissionError as e:  # antes que OSError, del que hereda
        sys.exit(f"{KO} {e}")
    except (ssl.SSLError, OSError) as e:
        sys.exit(f"{KO} {traducir(e)}")
    except subprocess.CalledProcessError as e:
        sys.exit(f"{KO} openssl no pudo generar la clave: {e.stderr.decode(errors='replace').strip()}")


if __name__ == "__main__":
    main()
