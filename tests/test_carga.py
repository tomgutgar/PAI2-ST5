"""RS3.a: 300 sesiones mTLS abiertas A LA VEZ, cada una con su cuenta y su certificado (precargados por seed.py)."""
import logging
import os
import resource
import threading
import time
import unittest

import base
from base import ok, paso

import client
import common
import db as dbm
import seed
import server

N = 300
TIMEOUT = 120  # 300 PBKDF2 a la vez cuestan ~18 s de CPU: es coste de autenticación, no de TLS


class TestCarga(unittest.TestCase):
    def shortDescription(self):
        return None

    def test_rs3a_300_sesiones_simultaneas(self):
        """RS3.a | 300 túneles mTLS autenticados abiertos A LA VEZ, cada uno con su cuenta y su certificado | pico=300, 300/300 login OK, 0 errores y 0 sesiones activas tras los logouts (RF4)"""
        base.cabecera(self._testMethodName, self.test_rs3a_300_sesiones_simultaneas.__doc__)
        cuentas = seed.leer_credenciales()[:N]
        self.assertEqual(len(cuentas), N, "falta ejecutar `make seed`")
        common.PUERTO_VPN, common.PUERTO_ALTA = base.puerto_libre(), base.puerto_libre()
        pos_audit = os.path.getsize(common.AUDIT_LOG) if os.path.exists(common.AUDIT_LOG) else 0
        gw, socks = server.arrancar(dbm.DB(common.DB_PATH), common.PUERTO_VPN, common.PUERTO_ALTA)
        listos = threading.Barrier(N + 1, timeout=TIMEOUT)    # los 300 autenticados + el test
        trabajo = threading.Barrier(N + 1, timeout=TIMEOUT)   # los 300 han hecho MSG+GET, aún conectados
        res = {"ok": 0, "err": []}
        lock = threading.Lock()

        def cliente(user, rol, pwd):
            d = os.path.join(common.CLIENTES, user)
            try:
                t = client.Tunel(os.path.join(d, "device.crt"), os.path.join(d, "device.key"), timeout=TIMEOUT)
                r = t.pedir(cmd="LOGIN", username=user, password=pwd)
                assert r["ok"], r
                listos.wait()
                assert t.pedir(cmd="MSG", text="carga")["ok"]
                recurso = min(server.PERFILES[rol])
                assert t.pedir(cmd="GET", resource=recurso)["ok"]
                trabajo.wait()
                t.logout()
                with lock:
                    res["ok"] += 1
            except Exception as e:  # noqa: BLE001  se contabiliza y se afirma abajo
                with lock:
                    res["err"].append(f"{user}: {type(e).__name__} {e}")
                listos.abort()
                trabajo.abort()

        hilos = [threading.Thread(target=cliente, args=(u, r, p), daemon=True) for u, r, p in cuentas]
        paso(f"{N} clientes precargados (PDI, PAS, INV) abren a la vez su túnel mTLS y hacen LOGIN")
        paso("el log [srv] se silencia durante la carga (miles de líneas): abajo va su resumen y todo queda en audit.log")
        base.SRV.setLevel(logging.CRITICAL)
        t0 = time.perf_counter()
        for h in hilos:
            h.start()
        listos.wait()
        tiempo = time.perf_counter() - t0
        activas, pico = gw.activas, gw.pico
        cpu = resource.getrusage(resource.RUSAGE_SELF)
        ok(f"sesiones autenticadas abiertas a la vez: {activas} (en {tiempo:.1f} s)")
        ok(f"CPU (usuario+sistema) hasta aquí: {cpu.ru_utime + cpu.ru_stime:.1f} s · RAM pico: {cpu.ru_maxrss / 1024:.0f} MiB")
        paso("con las 300 abiertas, cada una envía un MSG y pide un recurso de su perfil; después LOGOUT")
        trabajo.wait()
        for h in hilos:
            h.join(TIMEOUT)
        time.sleep(0.5)
        base.SRV.setLevel(logging.NOTSET)
        for s in socks:
            s.close()
        with open(common.AUDIT_LOG, encoding="utf-8") as f:
            f.seek(pos_audit)
            nuevas = f.read().splitlines()
        picos = [ln for ln in nuevas if "SESSIONS_PEAK" in ln]
        ok(f"audit.log: {picos[-1].split('| AUDIT | ')[-1] if picos else '(sin SESSIONS_PEAK)'}")
        ok(f"audit.log: {sum('LOGIN_OK' in ln for ln in nuevas)} LOGIN_OK · {sum('| LOGOUT ' in ln for ln in nuevas)} LOGOUT · "
           f"{sum('TLS_OK' in ln for ln in nuevas)} TLS_OK")
        ok(f"{res['ok']}/{N} sesiones OK, pico={pico}, errores={len(res['err'])}, activas tras los logouts={gw.activas}")
        self.assertTrue(picos and picos[-1].endswith(f"pico={N}"))
        self.assertEqual(res["err"], [])
        self.assertEqual(activas, N)
        self.assertEqual(pico, N)
        self.assertEqual(res["ok"], N)
        self.assertEqual(gw.activas, 0)
        base.resultado(False)


if __name__ == "__main__":
    unittest.main()
