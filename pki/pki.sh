#!/usr/bin/env bash
# PKI corporativa U-Secure (RS1.a): CA, certificado del servidor VPN, firma de CSR de dispositivos,
# revocación y CRL. Solo usa el comando `openssl`.
#
#   pki.sh init                     -> crea la CA raíz "U-Secure Root CA" (RSA 3072, 5 años) y una CRL vacía
#   pki.sh server                   -> certificado del gateway VPN (serverAuth, localhost/127.0.0.1)
#   pki.sh sign <csr> <usuario> <rol> -> firma la CSR de un dispositivo (clientAuth) y saca el PEM por stdout
#   pki.sh revoke <usuario> [motivo] -> revoca todos los certificados vigentes del usuario y regenera la CRL
#   pki.sh crl                      -> regenera la CRL
set -euo pipefail
# La CLI openssl no debe heredar la política TLS de la aplicación (solo afecta a sockets, pero mejor aislar)
unset OPENSSL_CONF
PKI="$(cd "$(dirname "$0")" && pwd)"
export CA_DIR="$PKI/ca"
CNF="$PKI/openssl_ca.cnf"
SRV="$PKI/server"

# CRL escrita en un temporal y renombrada: el gateway nunca lee una CRL a medias
crl() { openssl ca -config "$CNF" -gencrl -out "$CA_DIR/crl.pem.tmp" 2>/dev/null && mv "$CA_DIR/crl.pem.tmp" "$CA_DIR/crl.pem"; }
# index.txt y serial no admiten escrituras simultáneas (gateway, seed.py y `server.py revocar` son procesos distintos)
bloquear() { exec 9>"$CA_DIR/.lock"; flock 9; }

case "${1:-}" in
  init)
    if [[ -f "$CA_DIR/ca.crt" ]]; then echo "CA ya existe en $CA_DIR (nada que hacer)"; exit 0; fi
    mkdir -p "$CA_DIR/newcerts"; chmod 700 "$CA_DIR"
    : > "$CA_DIR/index.txt"; echo 1000 > "$CA_DIR/serial"; echo 1000 > "$CA_DIR/crlnumber"
    openssl req -config "$CNF" -x509 -new -newkey rsa:3072 -noenc -sha256 -days 1825 \
      -keyout "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" -extensions v3_ca 2>/dev/null
    chmod 600 "$CA_DIR/ca.key"
    crl
    echo "✔ CA corporativa creada: $CA_DIR/ca.crt (+ CRL vacía)"
    ;;
  server)
    if [[ -f "$SRV/server.crt" ]]; then echo "Certificado del servidor ya existe (nada que hacer)"; exit 0; fi
    mkdir -p "$SRV"
    openssl req -new -newkey rsa:3072 -noenc -keyout "$SRV/server.key" -out "$SRV/server.csr" \
      -subj "/O=Universidad U-Secure/OU=Gateway VPN/CN=localhost" 2>/dev/null
    chmod 600 "$SRV/server.key"
    openssl ca -config "$CNF" -batch -notext -extensions v3_server -in "$SRV/server.csr" -out "$SRV/server.crt" 2>/dev/null
    echo "✔ Certificado del gateway VPN emitido: $SRV/server.crt"
    ;;
  sign)
    bloquear
    csr="$2"; user="$3"; rol="$4"
    [[ "$user" =~ ^[a-z0-9_]{3,32}$ ]] || { echo "usuario inválido" >&2; exit 2; }
    [[ "$rol" =~ ^(PDI|PAS|INV)$ ]] || { echo "rol inválido" >&2; exit 2; }
    openssl req -in "$csr" -noout -verify >/dev/null 2>&1 || { echo "CSR con firma inválida" >&2; exit 3; }
    bits=$(openssl req -in "$csr" -noout -text 2>/dev/null | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p')
    openssl req -in "$csr" -noout -text 2>/dev/null | grep -q "rsaEncryption" && [[ "${bits:-0}" -ge 3072 ]] \
      || { echo "clave débil: se exige RSA ≥ 3072 bits" >&2; exit 3; }
    # El sujeto lo fija la CA (no se copia nada de la CSR salvo la clave pública)
    openssl ca -config "$CNF" -batch -notext -extensions v3_client \
      -subj "/O=Universidad U-Secure/OU=$rol/CN=$user" -in "$csr" -out /dev/stdout 2>/dev/null
    ;;
  revoke)
    bloquear
    user="$2"; motivo="${3:-keyCompromise}"
    [[ "$user" =~ ^[a-z0-9_]{3,32}$ ]] || { echo "usuario inválido" >&2; exit 2; }
    serials=$(awk -F'\t' -v cn="/CN=$user" '$1=="V" && substr($6, length($6)-length(cn)+1)==cn {print $4}' "$CA_DIR/index.txt")
    [[ -n "$serials" ]] || { echo "sin certificados vigentes para $user" >&2; exit 4; }
    trap crl EXIT  # la CRL se regenera aunque falle alguna revocación
    for s in $serials; do
      openssl ca -config "$CNF" -revoke "$CA_DIR/newcerts/$s.pem" -crl_reason "$motivo" 2>/dev/null
      echo "$s"
    done
    ;;
  crl) bloquear; crl; echo "✔ CRL regenerada: $CA_DIR/crl.pem" ;;
  *) sed -n '2,9p' "$0"; exit 1 ;;
esac
