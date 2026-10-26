"""RS3.b, O3: TLS 1.3 + mTLS frente a TCP sin cifrar con 1, 50, 100, 200 y 300 clientes concurrentes.

Cada cliente: conectar (+handshake) -> LOGIN -> N_MSG mensajes de 1 KiB -> LOGOUT.
Mide: conexión, login (PBKDF2 aparte: es igual en ambos escenarios), RTT por mensaje, throughput, CPU/RAM del
servidor (/proc de su proceso), bytes en el cable (contadores de `lo`). Salida: evidencias/benchmark/.

  python3 bench/benchmark.py [reps] [niveles separados por comas]
"""
# ruff: noqa: I001  (el orden importa: common antes que ssl/hashlib)
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import common
import csv
import platform
import statistics as st
import subprocess
import threading
import time

import client
import plain_server
import seed

N_MSG, TAM = 50, 1024
NIVELES = [1, 50, 100, 200, 300]
PUERTO_PLANO = plain_server.PUERTO
SALIDA = os.path.join(common.RAIZ, "evidencias", "benchmark")
CAMPOS = ["escenario", "clientes", "rep", "ok", "conexion_ms_media", "conexion_ms_p95", "login_ms_media",
          "rtt_ms_p50", "rtt_ms_p95", "rtt_ms_p99", "msg_s", "kib_s", "cpu_s", "ram_mib", "bytes_cable", "bytes_por_msg"]


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p / 100))]


def lo_bytes():
    with open("/proc/net/dev") as f:
        for linea in f:
            if linea.strip().startswith("lo:"):
                return int(linea.split(":")[1].split()[0])  # RX de lo == todo lo transmitido por loopback
    raise RuntimeError("no se encuentra la interfaz lo en /proc/net/dev")


def proc_cpu_ram(pid):
    with open(f"/proc/{pid}/stat") as f:
        c = f.read().rsplit(")", 1)[1].split()
    cpu = (int(c[11]) + int(c[12])) / os.sysconf("SC_CLK_TCK")
    with open(f"/proc/{pid}/status") as f:
        ram = next(int(x.split()[1]) for x in f if x.startswith("VmHWM")) / 1024
    return cpu, ram


def lanzar(escenario):
    codigo = {
        "plano": f"import runpy,sys; sys.argv=['p','{PUERTO_PLANO}']; runpy.run_path('bench/plain_server.py', run_name='__main__')",
        "tls": "import sys; sys.path.insert(0,'src'); import common, server, threading; server.arrancar(); "
               "print('listo', flush=True); threading.Event().wait()",
    }[escenario]
    p = subprocess.Popen([sys.executable, "-c", codigo], cwd=common.RAIZ, stdout=subprocess.PIPE, text=True)
    if not p.stdout.readline():
        p.wait()
        sys.exit(f"✘ el servidor '{escenario}' no arrancó (código {p.returncode})")
    return p


def parar(p):
    p.kill()
    p.wait()
    p.stdout.close()


def un_cliente(escenario, user, pwd, texto, res, lock):
    t = None
    try:
        t0 = time.perf_counter()
        if escenario == "tls":
            d = os.path.join(common.CLIENTES, user)
            t = client.Tunel(os.path.join(d, "device.crt"), os.path.join(d, "device.key"), timeout=120)
        else:
            t = plain_server.ClientePlano(PUERTO_PLANO)
        t1 = time.perf_counter()
        if not t.pedir(cmd="LOGIN", username=user, password=pwd).get("ok"):
            raise PermissionError("login rechazado")
        t2 = time.perf_counter()
        rtts = []
        for _ in range(N_MSG):
            a = time.perf_counter()
            if not t.pedir(cmd="MSG", text=texto).get("ok"):
                raise RuntimeError("MSG rechazado")
            rtts.append((time.perf_counter() - a) * 1000)
        fin = time.perf_counter()
        t.logout()
        t = None
        with lock:
            res["ok"] += 1
            res["ini"].append(t2)
            res["fin"].append(fin)
            res["conn"].append((t1 - t0) * 1000)
            res["login"].append((t2 - t1) * 1000)
            res["rtt"] += rtts
    except Exception as e:  # noqa: BLE001  se cuenta como fallo en la tasa de éxito y se muestra
        with lock:
            res["err"].append(f"{user}: {type(e).__name__} {e}")
    finally:
        if t:
            t.cerrar()


def ronda(escenario, n, cuentas, srv):
    res = {"ok": 0, "conn": [], "login": [], "rtt": [], "err": [], "ini": [], "fin": []}
    lock, texto = threading.Lock(), "x" * TAM
    cpu0, _ = proc_cpu_ram(srv.pid)
    b0, t0 = lo_bytes(), time.perf_counter()
    hilos = [threading.Thread(target=un_cliente, args=(escenario, u, p, texto, res, lock)) for u, p in cuentas[:n]]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()
    bytes_ = lo_bytes() - b0
    # throughput solo sobre la fase de mensajes (el login/PBKDF2 es igual en ambos escenarios)
    dur = (max(res["fin"]) - min(res["ini"])) if res["fin"] else time.perf_counter() - t0
    cpu1, ram = proc_cpu_ram(srv.pid)
    nmsg = res["ok"] * N_MSG
    for err in res["err"][:3]:
        print(f"  ✘ {escenario} n={n}: {err}", flush=True)
    return {"escenario": escenario, "clientes": n, "ok": f"{res['ok']}/{n}",
            "conexion_ms_media": st.mean(res["conn"]) if res["conn"] else 0, "conexion_ms_p95": pct(res["conn"] or [0], 95),
            "login_ms_media": st.mean(res["login"]) if res["login"] else 0,
            "rtt_ms_p50": pct(res["rtt"] or [0], 50), "rtt_ms_p95": pct(res["rtt"] or [0], 95),
            "rtt_ms_p99": pct(res["rtt"] or [0], 99), "msg_s": nmsg / dur, "kib_s": nmsg * TAM / 1024 / dur,
            "cpu_s": cpu1 - cpu0, "ram_mib": ram, "bytes_cable": bytes_, "bytes_por_msg": bytes_ / max(nmsg, 1)}


def cpu_modelo():
    with open("/proc/cpuinfo") as f:
        return next((ln.split(":", 1)[1].strip() for ln in f if ln.startswith("model name")), platform.machine())


def ram_total():
    with open("/proc/meminfo") as f:
        return round(int(f.readline().split()[1]) / 1024 / 1024)


def resumen(filas, reps):
    def media(esc, n, campo):
        v = [f[campo] for f in filas if f["escenario"] == esc and f["clientes"] == n]
        return st.mean(v), (st.stdev(v) if len(v) > 1 else 0.0)

    md = ["# Benchmark TLS 1.3 + mTLS vs TCP sin cifrar (RS3.b, O3)\n",
          (f"- Hardware: {cpu_modelo()}, {os.cpu_count()} hilos, {ram_total()} GiB RAM · Python {platform.python_version()} · "
           f"{common.politica_efectiva()['openssl']}"),
          (f"- {reps} repeticiones por nivel (media ± desviación). Cada cliente: {N_MSG} mensajes de {TAM} B. "
           "El login incluye PBKDF2 (600 000 it.) **en ambos escenarios**: no es overhead de TLS; "
           "el throughput se mide solo sobre la fase de mensajes.\n"),
          "| Clientes | Métrica | Sin cifrar | TLS 1.3 + mTLS | Overhead TLS (%) |", "|---|---|---|---|---|"]
    metricas = [("conexion_ms_media", "Conexión+handshake (ms)"), ("conexion_ms_p95", "Conexión+handshake p95 (ms)"),
                ("login_ms_media", "Login con PBKDF2 (ms, igual en ambos)"), ("rtt_ms_p50", "RTT p50 (ms)"), ("rtt_ms_p95", "RTT p95 (ms)"),
                ("rtt_ms_p99", "RTT p99 (ms)"), ("msg_s", "Throughput (msg/s)"), ("kib_s", "Throughput (KiB/s)"),
                ("cpu_s", "CPU servidor (s)"), ("ram_mib", "RAM pico servidor (MiB, acumulada del proceso)"), ("bytes_por_msg", "Bytes en el cable / msg")]
    for n in sorted({f["clientes"] for f in filas}):
        for campo, nombre in metricas:
            (a, sa), (b, sb) = media("plano", n, campo), media("tls", n, campo)
            ov = (b - a) / a * 100 if a else float("nan")
            md.append(f"| {n} | {nombre} | {a:.2f} ± {sa:.2f} | {b:.2f} ± {sb:.2f} | {ov:+.1f} |")
    fallos = [f for f in filas if f["ok"].split("/")[0] != f["ok"].split("/")[1]]
    md.append(f"\nTasa de éxito: {'100 % en todas las rondas' if not fallos else f'{len(fallos)} rondas con fallos (ver CSV)'}.")
    return "\n".join(md) + "\n"


def main():
    reps = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    niveles = [int(x) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else NIVELES
    cuentas = [(u, p) for u, _, p in seed.leer_credenciales()][:max(niveles)]
    # repartir roles: intercalar para que cualquier nivel mezcle PDI/PAS/INV
    cuentas = [c for trio in zip(cuentas[:100], cuentas[100:200], cuentas[200:300], strict=False) for c in trio] if len(cuentas) >= 300 else cuentas
    os.makedirs(SALIDA, exist_ok=True)
    filas = []
    for escenario in ("plano", "tls"):
        srv = lanzar(escenario)
        try:
            for n in niveles:
                for rep in range(1, reps + 1):
                    fila = ronda(escenario, n, cuentas, srv)
                    fila["rep"] = rep
                    filas.append(fila)
                    print(f"{escenario:5} n={n:3} rep={rep} ok={fila['ok']} rtt_p50={fila['rtt_ms_p50']:.2f} ms "
                          f"msg/s={fila['msg_s']:.0f} cpu={fila['cpu_s']:.1f}s", flush=True)
        finally:
            parar(srv)
    with open(os.path.join(SALIDA, "resultados.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, CAMPOS)
        w.writeheader()
        w.writerows({k: (round(v, 3) if isinstance(v, float) else v) for k, v in fila.items()} for fila in filas)
    with open(os.path.join(SALIDA, "resumen.md"), "w") as f:
        f.write(resumen(filas, reps))
    fallidas = [f for f in filas if f["ok"].split("/")[0] != f["ok"].split("/")[1]]
    print(f"{'✘' if fallidas else '✔'} {SALIDA}/resultados.csv y resumen.md · rondas con fallos: {len(fallidas)}")
    sys.exit(1 if fallidas else 0)


if __name__ == "__main__":
    main()
