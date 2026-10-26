"""Genera el tráfico que captura scripts/captura.sh (RS4.a). Uso: trafico.py plano|tls|downgrade|mitm"""
# ruff: noqa: I001  (el orden importa: common antes que ssl/hashlib)
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(AQUI, "..", "src"), os.path.join(AQUI, "..", "bench"), os.path.join(AQUI, "..", "ataques")]
import common

import client
import db as dbm
import plain_server
import server

USER, PWD = "pdi_001", "Seed-pdi_001-2026"  # cuenta de pruebas de seed.py


def plano():
    gw = plain_server.Plano(dbm.DB(common.DB_PATH))
    gw.escuchar(plain_server.PUERTO, gw.atender_plano)
    t = plain_server.ClientePlano()
    for msg in ({"cmd": "LOGIN", "username": USER, "password": PWD}, {"cmd": "MSG", "text": "mensaje de prueba"}):
        print("plano →", t.pedir(**msg))
    t.logout()


def tls():
    common.configurar_auditoria(consola=False)
    server.arrancar(dbm.DB(common.DB_PATH))
    t, rol = client.sesion(USER, PWD)
    print("TLS →", t.info(), rol, t.pedir(cmd="MSG", text="mensaje de prueba"), t.pedir(cmd="GET", resource="docencia"))
    t.logout()


def ataques_(ids):
    import ataques
    ataques.ejecutar(ids, salida=lambda *_: None, guardar=False)
    print("ataques ejecutados:", ", ".join(sorted(ids)))


if __name__ == "__main__":
    {"plano": plano, "tls": tls,
     "downgrade": lambda: ataques_({"A02", "A03", "A04", "A05", "A11"}),
     "mitm": lambda: ataques_({"A13", "A14", "A15", "A16"})}[sys.argv[1]]()
