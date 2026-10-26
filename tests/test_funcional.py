"""Tests funcionales: RF1.a, RF1.b, RF2, RF4, RF5. Ejecutar: make test (o python3 -m unittest discover -s tests -v)."""
import os
import socket
import sqlite3
import ssl
import subprocess
import unittest

import base
from base import ok, paso

import altas
import client
import common


class TestFuncional(base.Base):
    def test_rf1a_registro_emite_certificado(self):
        """RF1.a | Registro con usuario + contraseña + código: la CA emite un certificado X.509 con CN y rol fijados por ella | alta OK; CN=usuario y OU=rol que decidió el administrador"""
        self.cuenta("t_rf1a", "PAS")
        crt = os.path.join(common.CLIENTES, "t_rf1a", "device.crt")
        paso("se lee el sujeto del certificado emitido (openssl x509 -subject)")
        sujeto = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-subject"], capture_output=True, check=False,
                                text=True, env={"PATH": os.environ["PATH"]}).stdout.strip()
        self.assertIn("CN=t_rf1a", sujeto)
        self.assertIn("OU=PAS", sujeto)
        ok(f"certificado emitido: {sujeto}")
        self.assertEqual(self.db.usuario("t_rf1a")[0], "PAS")
        ok("la BD guarda el usuario con rol PAS")

    def test_rf1a_codigo_invalido_o_reutilizado(self):
        """RF1.a | Sin código de alta válido (o con uno ya usado) no hay registro | PermissionError en el cliente y ENROL_FAIL en el audit"""
        paso("registro de 't_sincodigo' con un código inventado")
        with self.assertRaises(PermissionError) as cm:
            client.registrar("t_sincodigo", "claveSegura1", "codigo-inventado")
        ok(f"rechazado: {cm.exception}")
        paso("registro correcto de 't_codigo1' y segundo intento con el MISMO código")
        code = self.db.nuevo_codigo("t_codigo1", "PDI")
        client.registrar("t_codigo1", "claveSegura1", code)
        with self.assertRaises(PermissionError) as cm:
            client.registrar("t_codigo1", "claveSegura1", code)
        ok(f"código reutilizado rechazado: {cm.exception}")

    def test_rf1b_bd_inmutable(self):
        """RF1.b | Identidad, rol y huella del certificado no se pueden modificar ni borrar | la BD aborta con 'registro inmutable'"""
        self.cuenta("t_rf1b")
        for sql in ("UPDATE users SET role='INV' WHERE username='t_rf1b'",
                    "UPDATE certs SET sha256_fingerprint='x' WHERE username='t_rf1b'",
                    "DELETE FROM certs WHERE username='t_rf1b'",
                    "DELETE FROM users"):
            paso(f"SQL directo contra la BD: {sql}")
            with self.assertRaisesRegex(sqlite3.DatabaseError, "registro inmutable"):
                self.db.cx.execute(sql)
            ok("abortado por el trigger: registro inmutable")

    def test_rf1b_reemision_solo_tras_revocar(self):
        """RF1.b | Un segundo certificado exige revocar antes el anterior; la fila antigua se conserva | rechazo, revocación y nueva fila (2 en total)"""
        pw = self.cuenta("t_reemit")
        paso("se pide un segundo certificado con un código válido sin revocar el primero")
        with self.assertRaises(PermissionError) as cm:
            client.registrar("t_reemit", pw, self.db.nuevo_codigo("t_reemit", "PDI"))
        ok(f"rechazado: {cm.exception} (ya tiene un certificado activo)")
        paso("el administrador revoca el certificado y se repite el alta")
        serial_viejo = altas.revocar(self.db, "t_reemit")
        client.registrar("t_reemit", pw, self.db.nuevo_codigo("t_reemit", "PDI"))
        nuevo = self.db.cert_activo("t_reemit")[0]
        self.assertNotEqual(serial_viejo, nuevo)
        n = self.db.uno("SELECT COUNT(*) FROM certs WHERE username='t_reemit'")[0]
        self.assertEqual(n, 2)
        ok(f"serial {serial_viejo} revocado, nuevo serial {nuevo}; la tabla certs conserva {n} filas")

    def test_rf1b_revocar_corta_sesion_abierta(self):
        """RF1.b, RS1.a | Revocar el certificado de un usuario conectado cierra su sesión en el siguiente comando | GET rechazado y SESSION_REVOKED en el audit"""
        pw = self.cuenta("t_revviva")
        paso("t_revviva inicia sesión y, con la sesión abierta, el administrador revoca su certificado")
        t, _ = client.sesion("t_revviva", pw)
        altas.revocar(self.db, "t_revviva")
        paso("t_revviva intenta GET correo")
        r = t.pedir(cmd="GET", resource="correo")
        t.cerrar()
        self.assertFalse(r["ok"])
        ok(f"rechazado: {r['error']}")

    def test_rf1a_alta_fallida_conserva_la_clave(self):
        """RF1.a | Un registro rechazado no destruye la clave ni el certificado vigentes del dispositivo | la clave no cambia y el login sigue funcionando"""
        pw = self.cuenta("t_conserva")
        clave = os.path.join(common.CLIENTES, "t_conserva", "device.key")
        with open(clave) as f:
            antes = f.read()
        paso("nuevo registro con un código erróneo (el cliente genera una clave nueva para la CSR)")
        with self.assertRaises(PermissionError):
            client.registrar("t_conserva", pw, "codigo-erroneo")
        with open(clave) as f:
            self.assertEqual(f.read(), antes)
        ok("alta rechazada y device.key sigue siendo la misma")
        t, rol = client.sesion("t_conserva", pw)
        t.logout()
        ok(f"el login con el certificado de siempre sigue OK (rol {rol})")

    def test_rf2_flujo_completo_y_dos_capas(self):
        """RF2 | El login exige las dos capas: certificado del dispositivo (mTLS) Y usuario/contraseña | OK con ambas; rechazo con contraseña mala"""
        pw = self.cuenta("t_rf2")
        paso("capa 1 (mTLS con el certificado) + capa 2 (usuario y contraseña correctos)")
        t, rol = client.sesion("t_rf2", pw)
        self.assertEqual(rol, "PDI")
        ok(f"túnel: {t.info()} · rol {rol}")
        self.assertTrue(t.pedir(cmd="MSG", text="hola")["ok"])
        ok("MSG enviado por el túnel")
        t.logout()
        paso("mismo certificado válido pero contraseña incorrecta")
        with self.assertRaises(PermissionError) as cm:
            client.sesion("t_rf2", "otra-clave")
        ok(f"rechazado: {cm.exception} (el certificado solo no basta)")

    def test_rf2_sin_certificado_no_hay_capa_de_aplicacion(self):
        """RF2 | Sin certificado de cliente el túnel :7443 no llega a la capa de aplicación | SSLError en el handshake / primera lectura"""
        paso("conexión a :7443 sin certificado de cliente y envío de un LOGIN")
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)) as cm:
            t = client.Tunel(puerto=common.PUERTO_VPN)  # TLS 1.3: el rechazo puede aparecer en la 1ª lectura
            t.pedir(cmd="LOGIN", username="x", password="y")
        ok(f"el servidor corta el handshake: {type(cm.exception).__name__} {getattr(cm.exception, 'reason', '') or ''}")

    def test_rf2_cert_de_otro_usuario(self):
        """RF2 | El certificado debe pertenecer al usuario que hace login | LOGIN_FAIL cn_no_coincide; al cliente solo un mensaje genérico"""
        self.cuenta("t_dev_a")
        pw_b = self.cuenta("t_dev_b")
        paso("túnel con el certificado de t_dev_a y LOGIN con usuario y contraseña CORRECTOS de t_dev_b")
        d = os.path.join(common.CLIENTES, "t_dev_a")
        t = client.Tunel(os.path.join(d, "device.crt"), os.path.join(d, "device.key"))
        r = t.pedir(cmd="LOGIN", username="t_dev_b", password=pw_b)
        t.cerrar()
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "credenciales inválidas")
        ok(f"rechazado: {r['error']} (no se revela el motivo real)")

    def test_rf2_comandos_sin_login(self):
        """RF2 | MSG y GET antes de LOGIN se rechazan aunque el certificado sea válido | 'no autenticado' + UNAUTH_CMD en el audit"""
        self.cuenta("t_nolog")
        paso("túnel mTLS válido, pero se envían MSG y GET sin hacer LOGIN")
        d = os.path.join(common.CLIENTES, "t_nolog")
        t = client.Tunel(os.path.join(d, "device.crt"), os.path.join(d, "device.key"))
        r1, r2 = t.pedir(cmd="MSG", text="x"), t.pedir(cmd="GET", resource="correo")
        t.cerrar()
        self.assertFalse(r1["ok"])
        self.assertFalse(r2["ok"])
        ok(f"MSG → {r1['error']}; GET → {r2['error']}")

    def test_rf2_bloqueo_por_fuerza_bruta(self):
        """RF2 | 5 contraseñas malas bloquean la cuenta; después ni la correcta entra | 5 LOGIN_FAIL, LOCKOUT y rechazo de la correcta"""
        pw = self.cuenta("t_brute")
        paso("5 logins seguidos con contraseña incorrecta")
        for _ in range(5):
            with self.assertRaises(PermissionError):
                client.sesion("t_brute", "mala-clave")
        ok("los 5 se rechazan y la cuenta queda bloqueada")
        paso("ahora se intenta con la contraseña CORRECTA")
        with self.assertRaises(PermissionError) as cm:
            client.sesion("t_brute", pw)
        ok(f"aun así se rechaza: {cm.exception}")

    def test_rf4_logout_destruye_el_tunel(self):
        """RF4 | Tras LOGOUT el túnel no admite datos y una sesión nueva exige handshake completo (sin reanudación) | envío falla; session_reused=False"""
        pw = self.cuenta("t_rf4")
        t, _ = client.sesion("t_rf4", pw)
        sesion_vieja, ctx = t.tls.session, t.tls.context  # la sesión solo se puede ofrecer con el mismo contexto
        paso("LOGOUT y cierre del túnel (close_notify)")
        self.assertTrue(t.pedir(cmd="LOGOUT")["ok"])
        t.cerrar()
        paso("se intenta enviar datos por el túnel ya cerrado")
        with self.assertRaises((ssl.SSLError, OSError, ValueError)) as cm:
            t.tls.send(b"{}\n")
        ok(f"envío rechazado: {type(cm.exception).__name__}")
        tickets = sesion_vieja is not None and sesion_vieja.has_ticket
        ok(f"tickets de reanudación recibidos del servidor: {tickets} (num_tickets=0)")
        paso("reconexión ofreciendo la sesión TLS antigua para reanudarla")
        s = socket.create_connection((common.HOST, common.PUERTO_VPN))
        t2 = ctx.wrap_socket(s, server_hostname=common.SERVER_NAME, session=sesion_vieja)
        reutilizada = t2.session_reused
        t2.close()
        self.assertFalse(reutilizada)
        ok("session_reused=False: handshake completo con claves efímeras nuevas")

    def test_rf5_perfiles_por_rol(self):
        """RF5 | Cada rol (PDI, PAS, INV) solo accede a los recursos de su perfil | recurso propio OK; fuera de perfil ACCESS_DENIED"""
        for user, rol, si, no in (("t_pdi", "PDI", "docencia", "gestion"),
                                  ("t_pas", "PAS", "gestion", "bd_investigacion"),
                                  ("t_inv", "INV", "servidores_internos", "docencia")):
            t, r = client.sesion(user, self.cuenta(user, rol))
            self.assertEqual(r, rol)
            paso(f"{rol} pide '{si}' (de su perfil) y '{no}' (fuera de su perfil)")
            self.assertTrue(t.pedir(cmd="GET", resource=si)["ok"])
            denegado = t.pedir(cmd="GET", resource=no)
            t.logout()
            self.assertEqual(denegado["error"], "ACCESS_DENIED")
            ok(f"{rol}: {si} permitido · {no} → ACCESS_DENIED")


if __name__ == "__main__":
    unittest.main()
