"""Proxy intermediario de LABORATORIO para demostrar que mTLS + TLS 1.3 resisten la interceptación (O5, A13-A16).
Solo escucha en 127.0.0.1 y solo reenvía hacia el gateway de pruebas del propio grupo.

Modos:
  pasivo     reenvía y registra todo lo que ve (A13, A01, A16)
  manipular  además invierte un bit del n-ésimo registro TLS cliente->servidor de tipo 23 (A14)
  suplantar  termina TLS con SU PROPIO certificado ante el cliente (A15)
"""
# ruff: noqa: I001  (el orden importa: common antes que ssl)
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import common
import socket
import ssl
import threading


class Proxy:
    def __init__(self, destino, modo="pasivo", n=2, ctx_falso=None):
        self.destino, self.modo, self.n, self.ctx_falso = destino, modo, n, ctx_falso
        self.capturas = []   # [(sentido, bytes)] lo que ve el atacante en el cable
        self.eventos = []    # texto narrado: qué intentó el atacante y qué pasó
        self.lock = threading.Lock()
        self.srv = socket.create_server((common.HOST, 0))
        self.puerto = self.srv.getsockname()[1]
        threading.Thread(target=self._aceptar, daemon=True).start()

    def cerrar(self):
        self.srv.close()

    def _ev(self, txt):
        with self.lock:
            self.eventos.append(txt)

    def _aceptar(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._sesion, args=(c,), daemon=True).start()

    def _sesion(self, c):
        if self.modo == "suplantar":
            return self._suplantar(c)
        try:
            u = socket.create_connection(self.destino, timeout=30)
        except OSError:
            c.close()
            return
        threading.Thread(target=self._bombear, args=(c, u, "c→s"), daemon=True).start()
        self._bombear(u, c, "s→c")

    def _bombear(self, origen, destino, sentido):
        buf, vistos = b"", 0
        try:
            while datos := origen.recv(65536):
                with self.lock:
                    self.capturas.append((sentido, datos))
                if self.modo == "manipular" and sentido == "c→s":
                    datos, buf, vistos = self._tocar(datos, buf, vistos)
                destino.sendall(datos)
        except OSError:
            pass
        finally:
            for s in (origen, destino):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()

    def _tocar(self, datos, buf, vistos):
        """Recorre los registros TLS (cabecera de 5 B) y corrompe 1 bit del n-ésimo de tipo 23."""
        buf += datos
        salida, pos = bytearray(), 0
        while len(buf) - pos >= 5:
            largo = 5 + int.from_bytes(buf[pos + 3:pos + 5], "big")
            if len(buf) - pos < largo:
                break
            reg = bytearray(buf[pos:pos + largo])
            if reg[0] == 23:
                vistos += 1
                if vistos == self.n:
                    reg[-1] ^= 0x01
                    self._ev(f"atacante: bit invertido en el registro cifrado nº {vistos} ({largo} bytes)")
            salida += reg
            pos += largo
        return bytes(salida), buf[pos:], vistos  # supone que los registros llegan íntegros en el flujo

    def _suplantar(self, c):
        try:
            with self.ctx_falso.wrap_socket(c, server_side=True) as t:
                leido = t.recv(65536)
            self._ev(f"atacante: el cliente envió {len(leido)} bytes en claro")
            with self.lock:
                self.capturas.append(("c→atacante", leido))
        except (ssl.SSLError, OSError) as e:
            self._ev(f"atacante: el cliente abortó el handshake ({getattr(e, 'reason', None) or type(e).__name__}); no obtiene nada")
        finally:
            c.close()


def cert_autofirmado(directorio, cn, extension):
    """Certificado autofirmado de un atacante (ninguna CA corporativa lo respalda). Devuelve (crt, key)."""
    crt, key = os.path.join(directorio, f"{cn}.crt"), os.path.join(directorio, f"{cn}.key")
    common.openssl("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1", "-keyout", key, "-out", crt,
                   "-subj", f"/O=Universidad U-Secure/OU=PDI/CN={cn}", "-addext", extension)
    return crt, key


def contexto_falso(directorio):
    """Servidor falso que se hace pasar por el gateway (localhost)."""
    crt, key = cert_autofirmado(directorio, "localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    return ctx


if __name__ == "__main__":
    import argparse
    import time
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--modo", choices=("pasivo", "manipular", "suplantar"), default="pasivo")
    a.add_argument("--destino-puerto", type=int, default=common.PUERTO_VPN)
    p = Proxy((common.HOST, a.destino_puerto), a.modo)
    print(f"Proxy {a.modo} en 127.0.0.1:{p.puerto} → :{a.destino_puerto} (Ctrl+C para volcar y salir)")
    try:
        time.sleep(3600)
    except KeyboardInterrupt:
        for sentido, d in p.capturas:
            print(sentido, d[:64].hex(), "…" if len(d) > 64 else "")
