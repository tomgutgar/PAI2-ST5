#!/usr/bin/env bash
# RS4.a: capturas .pcap en la interfaz de loopback + verificación automática con tshark.
# Necesita sudo SOLO para tcpdump. Requiere haber hecho antes `make seed` (usa la cuenta pdi_001).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=evidencias/pcap; mkdir -p "$OUT"
PWD_PRUEBA="Seed-pdi_001-2026"
if ! command -v tcpdump >/dev/null || ! command -v tshark >/dev/null; then echo "✘ Faltan tcpdump/tshark: sudo pacman -S tcpdump wireshark-cli"; exit 1; fi
[[ -f pki/seed_credentials.csv ]] || { echo "✘ Ejecuta antes: make seed"; exit 1; }

capturar() {  # capturar <fichero.pcap> <filtro bpf> <escenario del generador de tráfico>
  sudo tcpdump -i lo -U -n -w "$OUT/$1" "$2" 2>/dev/null & local pid=$!
  sleep 1.5; python3 scripts/trafico.py "$3"; sleep 1
  sudo kill -INT "$pid"; wait "$pid" 2>/dev/null || true
  sudo chown "$USER": "$OUT/$1"
  echo "✔ $OUT/$1 ($(stat -c %s "$OUT/$1") bytes)"
}
capturar 01_login_sin_cifrar.pcap   "tcp port 7444" plano
capturar 02_login_tls13_mtls.pcap   "tcp port 7443" tls
capturar 03_ataques_downgrade_cipher.pcap "tcp" downgrade
capturar 04_mitm.pcap               "tcp" mitm

{
  echo "# Análisis automático de las capturas ($(date -Iseconds))"
  echo; echo "## 01 · sin cifrar (línea base)"
  echo "paquetes que contienen la contraseña '$PWD_PRUEBA': $(tshark -r "$OUT/01_login_sin_cifrar.pcap" -Y "frame contains \"$PWD_PRUEBA\"" 2>/dev/null | wc -l)  (se espera > 0)"
  echo; echo "## 02 · TLS 1.3 + mTLS"
  tshark -r "$OUT/02_login_tls13_mtls.pcap" -d tcp.port==7443,tls -Y "tls.handshake.type==2" \
    -T fields -e tls.handshake.version -e tls.handshake.ciphersuite -e tls.handshake.extensions.supported_version 2>/dev/null \
    | sed 's/^/ServerHello (versión, suite, supported_version): /'
  echo "paquetes con registros Application Data: $(tshark -r "$OUT/02_login_tls13_mtls.pcap" -d tcp.port==7443,tls -Y "tls.app_data" 2>/dev/null | wc -l)"
  echo "paquetes con la contraseña en claro: $(tshark -r "$OUT/02_login_tls13_mtls.pcap" -Y "frame contains \"$PWD_PRUEBA\"" 2>/dev/null | wc -l)  (se espera 0)"
  echo "apariciones de la contraseña (grep -c sobre el pcap): $(grep -a -c "$PWD_PRUEBA" "$OUT/02_login_tls13_mtls.pcap" || true)  (se espera 0)"
  echo; echo "## 03 · rechazos (downgrade / suite débil / sin certificado)"
  echo "alertas TLS (tipo 21) vistas: $(tshark -r "$OUT/03_ataques_downgrade_cipher.pcap" -Y "tls.record.content_type==21 || tls.alert_message" 2>/dev/null | wc -l)"
  echo; echo "## 04 · MITM (A13-A16)"
  echo "paquetes TCP totales: $(tshark -r "$OUT/04_mitm.pcap" 2>/dev/null | wc -l) · con la contraseña en claro: $(tshark -r "$OUT/04_mitm.pcap" -Y "frame contains \"claveSegura1\"" 2>/dev/null | wc -l)  (se espera 0)"
} | tee "$OUT/analisis.txt"
