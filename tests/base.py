"""Utilidades de test: salida narrada (como en el PAI-1), servidor en hilo con BD temporal y PKI real.

Cada test imprime qué requisito comprueba, qué hace (·), qué comprueba (✓) y lo que registra el
servidor ([srv]), para poder seguirlo y evaluarlo sin leer el código. Todo va a stderr, como la
salida de unittest, para que aparezca en el orden real.
"""
# ruff: noqa: I001  (el orden importa: common antes que ssl/hashlib)
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import common
import logging
import socket
import tempfile
import unittest

import client
import db as dbm
import server

common.configurar_auditoria(consola=False)  # audit.log completo en disco (con fecha e IP)
sys.stdout = sys.stderr  # los print del cliente/servidor, en orden con la salida de unittest


class _FormatoSrv(logging.Formatter):
    def format(self, r):
        return f"    [srv] {r.getMessage()}"


SRV = logging.StreamHandler(sys.stderr)  # en consola, versión compacta del audit.log
SRV.setFormatter(_FormatoSrv())
common.audit_logger.addHandler(SRV)


def paso(msg):
    print(f"    · {msg}", file=sys.stderr, flush=True)


def ok(msg):
    print(f"    ✓ {msg}", file=sys.stderr, flush=True)


def cabecera(nombre, doc):
    """doc = 'ID | qué se prueba | resultado esperado'."""
    partes = [p.strip() for p in (doc or "").split("|")] + ["", "", ""]
    print(f"\n{'═' * 74}\n▶ [{partes[0]}] {nombre}\n  {partes[1]}\n  Esperado: {partes[2]}\n{'─' * 74}",
          file=sys.stderr, flush=True)


def resultado(fallo):
    print(f"  Resultado: {'✘ FAIL' if fallo else '✔ PASS'}", file=sys.stderr, flush=True)


def puerto_libre():
    with socket.socket() as s:
        s.bind((common.HOST, 0))
        return s.getsockname()[1]


class Base(unittest.TestCase):
    """Docstring de cada test: 'ID | qué se prueba | resultado esperado'."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        common.CLIENTES = os.path.join(cls.tmp.name, "clientes")
        common.PUERTO_VPN, common.PUERTO_ALTA = puerto_libre(), puerto_libre()
        cls.db = dbm.DB(os.path.join(cls.tmp.name, "t.db"))
        cls.gw, cls.socks = server.arrancar(cls.db, common.PUERTO_VPN, common.PUERTO_ALTA)

    @classmethod
    def tearDownClass(cls):
        for s in cls.socks:
            s.close()
        cls.tmp.cleanup()

    def shortDescription(self):
        return None  # que unittest no repita el docstring: ya lo imprime la cabecera

    def cuenta(self, user, rol="PDI", password="claveSegura1"):
        paso(f"el administrador autoriza el alta de '{user}' ({rol}) y el dispositivo se registra")
        code = self.db.nuevo_codigo(user, rol)
        client.registrar(user, password, code)
        return password

    def setUp(self):
        cabecera(self._testMethodName, getattr(self, self._testMethodName).__doc__)

    def run(self, result=None):
        antes = len(result.failures) + len(result.errors) if result else 0
        r = super().run(result)
        resultado(result and len(result.failures) + len(result.errors) > antes)
        return r
