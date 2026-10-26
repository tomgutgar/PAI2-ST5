"""RF5: precarga de cuentas corporativas PDI / PAS / INV con su certificado emitido, para pruebas de carga.

  python3 src/seed.py [N_POR_ROL]    (por defecto 100 por rol = 300 cuentas). Idempotente.

SOLO ENTORNO DE PRUEBAS: las contraseñas se guardan en claro en pki/seed_credentials.csv para poder
lanzar las 300 sesiones. En producción nunca se almacenan contraseñas así.
"""
# ruff: noqa: I001  (el orden importa: common antes que hashlib)
import common
import csv
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import altas
import client
import db as dbm

CSV = os.path.join(common.PKI, "seed_credentials.csv")


def leer_credenciales():
    """[(usuario, rol, contraseña)] de las cuentas de prueba (tests de carga y benchmark)."""
    with open(CSV) as f:
        return [tuple(r) for r in csv.reader(f) if r and not r[0].startswith(("#", "usuario"))]


def cuenta(base, rol, i):
    user = f"{rol.lower()}_{i:03d}"
    password = f"Seed-{user}-2026"  # SOLO PRUEBAS
    d = os.path.join(common.CLIENTES, user)
    if base.cert_activo(user) and os.path.exists(os.path.join(d, "device.crt")):
        return user, password
    pem, _ = altas.registrar(base, user, rol, password, client.generar_csr(user, d))  # sin código: precarga del administrador
    client.activar(d, pem)
    return user, password


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    base = dbm.DB(common.DB_PATH)
    tareas = [(rol, i) for rol in dbm.ROLES for i in range(1, n + 1)]
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
        res = list(ex.map(lambda t: cuenta(base, *t), tareas))
    with open(CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["# SOLO ENTORNO DE PRUEBAS", "", ""])
        w.writerow(["usuario", "rol", "password"])
        for (rol, _), (user, pwd) in zip(tareas, res, strict=True):
            w.writerow([user, rol, pwd])
    print(f"✔ {len(res)} cuentas precargadas con certificado ({n} PDI, {n} PAS, {n} INV) → {CSV}")


if __name__ == "__main__":
    main()
