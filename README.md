# PAI-2 BYODSEC: VPN Road Warrior con TLS 1.3 + mTLS (ST-5)

Grupo ST-5: Tomás Gutiérrez, Miguel Ridao y Julio Morales.

Requisitos: Linux, Python ≥ 3.10, OpenSSL ≥ 3 y `make`. `tcpdump` y `tshark` solo para `make captura` (necesita `sudo`).

```bash
make check      # comprueba que está todo instalado
make seed       # crea la CA, el certificado del servidor y 300 usuarios con certificado
make server     # terminal 1: arranca el gateway (:7443 túnel, :8443 alta)
make client     # terminal 2: menú del cliente (registrar · iniciar sesión · mensaje · recurso · cerrar)
make evidencias # todo de cero: tests, ataques, benchmark y capturas en evidencias/
```

Alta de un usuario nuevo: `python3 src/server.py alta ana_garcia PDI` (da un código de un solo uso) y luego, en el cliente, opción 1.
Revocar: `python3 src/server.py revocar ana_garcia`. Entrega: `make zip`.

La memoria (resumen, grado de completitud y manual de despliegue y uso) está en `docs/PAI2-ST5.pdf`.
