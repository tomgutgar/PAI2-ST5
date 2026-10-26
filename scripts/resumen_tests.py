"""Tabla 'requisito · nº tests · PASS/FAIL' a partir del log de `make test` (sale en evidencias/logs/resumen_tests.md)."""
import os
import re
import sys
from collections import defaultdict

CABECERA = re.compile(r"\[([^\]]+)\] test_\w+")
RESULTADO = re.compile(r"Resultado\s*: \S+ (PASS|FAIL)")
ID = re.compile(r"\b(RF\d(?:\.[ab])?|RS\d(?:\.[ab])?|O\d|A\d\d)\b")
log = sys.argv[1]
salida = os.path.join(os.path.dirname(os.path.abspath(log)), "resumen_tests.md")
filas, actual = defaultdict(lambda: [0, 0, 0]), None  # id -> [tests, pass, fail]
with open(log, encoding="utf-8") as f:
    for ln in f:
        # se busca en cualquier punto de la línea: los hilos del servidor pueden imprimir en medio
        if m := CABECERA.search(ln):
            actual = ID.findall(m.group(1))
        if (m := RESULTADO.search(ln)) and actual:
            ok = m.group(1) == "PASS"
            for i in actual:
                filas[i][0] += 1
                filas[i][1 if ok else 2] += 1
            actual = None
md = ["| Requisito / ataque | Nº tests | PASS | FAIL |", "|---|---|---|---|"]
md += [f"| {i} | {t} | {p} | {x} |" for i, (t, p, x) in sorted(filas.items())]
tot = [sum(v[k] for v in filas.values()) for k in range(3)]
md.append(f"| **Total (por ID, un test puede cubrir varios)** | {tot[0]} | {tot[1]} | {tot[2]} |")
with open(salida, "w", encoding="utf-8") as f:
    f.write("\n".join(md) + "\n")
print("\n".join(md))
sys.exit(1 if tot[2] else 0)
