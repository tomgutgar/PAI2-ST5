# Punto de entrada del proyecto: make <objetivo>. Ningún objetivo necesita argumentos.
SHELL := /bin/bash
.SHELLFLAGS := -eo pipefail -c
PY := python3
TS := $(shell date +%Y%m%d_%H%M%S)

.NOTPARALLEL:   # los objetivos de `evidencias` dependen unos de otros (algunos shells aliasan make a -j)
.PHONY: check pki seed server client test ataques bench captura evidencias zip clean

check:           ## versiones y herramientas
	@$(PY) --version; $(PY) -c "import ssl;print(ssl.OPENSSL_VERSION)"
	@for t in openssl tcpdump tshark; do command -v $$t >/dev/null && echo "✔ $$t" || echo "✘ $$t (falta)"; done
	@[ $$(ulimit -n) -ge 1024 ] && echo "✔ ulimit -n = $$(ulimit -n)" || echo "✘ ulimit -n bajo: ejecuta 'ulimit -n 4096'"

pki:             ## CA corporativa + certificado del servidor + CRL vacía
	@pki/pki.sh init && pki/pki.sh server

seed: pki        ## RF5: 300 usuarios precargados con certificados
	@$(PY) src/seed.py

server: pki      ## arranca el gateway VPN
	@$(PY) src/server.py

client:          ## cliente interactivo
	@$(PY) src/client.py

test: seed       ## tests con logs en evidencias/logs/
	@mkdir -p evidencias/logs
	@$(PY) -m unittest discover -s tests -v 2>&1 | tee evidencias/logs/tests_$(TS).log
	@$(PY) scripts/resumen_tests.py evidencias/logs/tests_$(TS).log

ataques: pki     ## catálogo de ataques
	@$(PY) ataques/ataques.py

bench: pki       ## benchmark TLS vs sin cifrar
	@$(PY) bench/benchmark.py

captura:         ## (necesita sudo) pcaps
	@scripts/captura.sh

evidencias: clean pki seed test ataques bench captura  ## todo, de cero

ZIP := $(notdir $(CURDIR))

zip:             ## $(ZIP).zip con lo exigido (sin claves privadas: se regeneran con make seed)
	@rm -f ../$(ZIP).zip; cd .. && zip -qr $(ZIP).zip $(ZIP) -x '*/.git/*' '*/__pycache__/*' '*/.ruff_cache/*' '*/pki/ca/ca.key' '*/pki/server/server.key' '*/clientes/*' '*/datos/*' '*/pki/ca/.lock' && echo "✔ $(ZIP).zip"

clean:           ## borra lo generado
	rm -rf pki/ca pki/server pki/seed_credentials.csv datos clientes evidencias
	find . -name __pycache__ -type d -exec rm -rf {} +
