"""Línea base SIN cifrar (O3, RS3.b). SOLO para el benchmark y las comparativas de tráfico: mismo protocolo y
mismo bucle de aplicación que el gateway (se reutiliza Gateway._bucle), pero sobre TCP plano y sin capa 1.
El servidor de producción NO tiene modo inseguro.

  python3 bench/plain_server.py [puerto]
"""
# ruff: noqa: I001  (el orden importa: common antes que ssl/hashlib)
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import common
import socket
import threading

import client
import db as dbm
import server

PUERTO = 7444


class Plano(server.Gateway):
    def __init__(self, base):
        super().__init__(base, tls=False)

    def atender_plano(self, raw, origen):
        raw.settimeout(server.TIMEOUT_INACTIVIDAD)
        self._bucle(raw, origen, None, None, {"canal": "sin_cifrar"})

    def vigente(self, usuario, huella):
        self.db.cert_activo(usuario)  # misma consulta que el gateway, para que la comparativa solo mida TLS
        return True  # sin certificados no hay nada que revocar

    def _login(self, msg, origen, cn, huella, ctx):
        """Solo contraseña (el mismo PBKDF2 que en el gateway): sin certificado no hay capa 1."""
        fila = self.db.usuario(msg.get("username") or "")
        return fila[0] if fila and dbm.password_ok(msg.get("password", ""), fila[2], fila[1]) else None


class ClientePlano:
    """El mismo protocolo que client.Tunel, pero sin TLS (para medir y para enseñar qué se ve en claro)."""

    def __init__(self, puerto=PUERTO, timeout=120):
        self.sock = socket.create_connection((common.HOST, puerto), timeout=timeout)
        self.f = self.sock.makefile("rwb")

    pedir = client.Tunel.pedir
    logout = client.Tunel.logout

    def cerrar(self):
        self.f.close()
        self.sock.close()


if __name__ == "__main__":
    puerto = int(sys.argv[1]) if len(sys.argv) > 1 else PUERTO
    gw = Plano(dbm.DB(common.DB_PATH))
    gw.escuchar(puerto, gw.atender_plano)
    print(f"Servidor SIN CIFRAR (solo benchmark) en :{puerto}", flush=True)
    threading.Event().wait()
