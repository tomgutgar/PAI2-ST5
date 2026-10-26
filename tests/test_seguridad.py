"""RS1, RS2, RS4, O4, O5: cada ataque del catálogo (ataques/ataques.py) debe quedar BLOQUEADO."""
import sys
import unittest

import base
from base import ok, paso

sys.path.insert(0, base.os.path.join(base.os.path.dirname(base.os.path.abspath(__file__)), "..", "ataques"))
import ataques


class TestSeguridad(base.Base):
    @classmethod
    def setUpClass(cls):
        ataques.E = ataques.Entorno()

    @classmethod
    def tearDownClass(cls):
        ataques.E.cerrar()

    def test_rs2_negocia_tls13_suite_aead_y_x25519(self):
        """RS2.a, RS2.b | una conexión legítima negocia TLS 1.3, suite AEAD permitida y ECDHE X25519 (PFS) | TLSv1.3 + suite + X25519"""
        paso("openssl s_client -tls1_3 con el certificado de atk_pdi (cliente legítimo)")
        out = ataques.s_client("-tls1_3", "-cert", ataques.E.cert("atk_pdi")[0], "-key", ataques.E.cert("atk_pdi")[1])
        for ln in out.splitlines():
            if "Cipher is" in ln or "Negotiated TLS1.3 group" in ln or "Protocol" in ln:
                ok(ln.strip())
        self.assertIn("Cipher is TLS_AES_256_GCM_SHA384", out)
        self.assertIn("X25519", out)
        self.assertNotIn("MLKEM", out)


def _crear(id_, req, que, esperado, f):
    def test(self):
        obtenido, bloqueado = f()
        print(f"    {'✓' if bloqueado else '✘'} {obtenido}", file=base.sys.stderr, flush=True)
        print(f"  Veredicto: {'BLOQUEADO' if bloqueado else 'VULNERABLE'}", file=base.sys.stderr, flush=True)
        self.assertTrue(bloqueado, f"{id_} VULNERABLE: {obtenido}")
    test.__doc__ = f"{id_} · {req} | {que} | {esperado}"
    return test


for _a in ataques.CATALOGO:
    setattr(TestSeguridad, f"test_{_a[0].lower()}", _crear(*_a))

if __name__ == "__main__":
    unittest.main()
