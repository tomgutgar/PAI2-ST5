# Benchmark TLS 1.3 + mTLS vs TCP sin cifrar (RS3.b, O3)

- Hardware: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 12 hilos, 15 GiB RAM · Python 3.14.7 · OpenSSL 3.6.4 25 Aug 2026
- 3 repeticiones por nivel (media ± desviación). Cada cliente: 50 mensajes de 1024 B. El login incluye PBKDF2 (600 000 it.) **en ambos escenarios**: no es overhead de TLS; el throughput se mide solo sobre la fase de mensajes.

| Clientes | Métrica | Sin cifrar | TLS 1.3 + mTLS | Overhead TLS (%) |
|---|---|---|---|---|
| 1 | Conexión+handshake (ms) | 0.45 ± 0.61 | 10.22 ± 1.13 | +2157.2 |
| 1 | Conexión+handshake p95 (ms) | 0.45 ± 0.61 | 10.22 ± 1.13 | +2157.2 |
| 1 | Login con PBKDF2 (ms, igual en ambos) | 248.01 ± 19.97 | 316.04 ± 9.06 | +27.4 |
| 1 | RTT p50 (ms) | 0.11 ± 0.01 | 0.13 ± 0.01 | +16.4 |
| 1 | RTT p95 (ms) | 0.23 ± 0.05 | 0.24 ± 0.04 | +5.7 |
| 1 | RTT p99 (ms) | 1.05 ± 1.17 | 0.31 ± 0.01 | -70.5 |
| 1 | Throughput (msg/s) | 6830.18 ± 1312.71 | 6944.02 ± 604.06 | +1.7 |
| 1 | Throughput (KiB/s) | 6830.18 ± 1312.71 | 6944.02 ± 604.06 | +1.7 |
| 1 | CPU servidor (s) | 0.25 ± 0.02 | 0.28 ± 0.02 | +13.3 |
| 1 | RAM pico servidor (MiB, acumulada del proceso) | 25.58 ± 0.12 | 28.23 ± 0.14 | +10.4 |
| 1 | Bytes en el cable / msg | 1198.83 ± 0.60 | 1369.16 ± 0.00 | +14.2 |
| 50 | Conexión+handshake (ms) | 0.26 ± 0.01 | 69.13 ± 11.13 | +26553.8 |
| 50 | Conexión+handshake p95 (ms) | 0.66 ± 0.15 | 144.49 ± 19.71 | +21641.0 |
| 50 | Login con PBKDF2 (ms, igual en ambos) | 2529.80 ± 76.73 | 2785.78 ± 67.81 | +10.1 |
| 50 | RTT p50 (ms) | 1.68 ± 0.57 | 2.71 ± 0.46 | +61.6 |
| 50 | RTT p95 (ms) | 7.25 ± 1.82 | 9.15 ± 0.27 | +26.3 |
| 50 | RTT p99 (ms) | 12.34 ± 3.12 | 16.12 ± 1.79 | +30.7 |
| 50 | Throughput (msg/s) | 1520.69 ± 410.91 | 1672.33 ± 328.65 | +10.0 |
| 50 | Throughput (KiB/s) | 1520.69 ± 410.91 | 1672.33 ± 328.65 | +10.0 |
| 50 | CPU servidor (s) | 32.38 ± 0.39 | 34.93 ± 0.05 | +7.9 |
| 50 | RAM pico servidor (MiB, acumulada del proceso) | 29.88 ± 0.89 | 36.90 ± 1.86 | +23.5 |
| 50 | Bytes en el cable / msg | 1198.63 ± 0.04 | 1368.69 ± 0.24 | +14.2 |
| 100 | Conexión+handshake (ms) | 0.60 ± 0.54 | 149.97 ± 15.71 | +25026.6 |
| 100 | Conexión+handshake p95 (ms) | 4.22 ± 5.05 | 273.20 ± 25.21 | +6370.9 |
| 100 | Login con PBKDF2 (ms, igual en ambos) | 5178.07 ± 131.43 | 5475.37 ± 51.81 | +5.7 |
| 100 | RTT p50 (ms) | 4.43 ± 0.76 | 6.16 ± 0.32 | +39.3 |
| 100 | RTT p95 (ms) | 19.79 ± 2.45 | 22.06 ± 0.99 | +11.5 |
| 100 | RTT p99 (ms) | 31.75 ± 3.36 | 36.93 ± 3.66 | +16.3 |
| 100 | Throughput (msg/s) | 1340.12 ± 220.43 | 1367.47 ± 124.07 | +2.0 |
| 100 | Throughput (KiB/s) | 1340.12 ± 220.43 | 1367.47 ± 124.07 | +2.0 |
| 100 | CPU servidor (s) | 66.94 ± 0.67 | 70.13 ± 0.11 | +4.8 |
| 100 | RAM pico servidor (MiB, acumulada del proceso) | 33.08 ± 0.24 | 45.74 ± 1.37 | +38.3 |
| 100 | Bytes en el cable / msg | 1198.79 ± 0.25 | 1369.48 ± 0.26 | +14.2 |
| 200 | Conexión+handshake (ms) | 0.45 ± 0.21 | 300.08 ± 38.32 | +66981.2 |
| 200 | Conexión+handshake p95 (ms) | 1.76 ± 1.02 | 553.33 ± 97.45 | +31254.8 |
| 200 | Login con PBKDF2 (ms, igual en ambos) | 10523.62 ± 167.31 | 10568.18 ± 138.00 | +0.4 |
| 200 | RTT p50 (ms) | 10.57 ± 2.01 | 12.82 ± 1.46 | +21.2 |
| 200 | RTT p95 (ms) | 46.50 ± 9.45 | 54.14 ± 17.74 | +16.4 |
| 200 | RTT p99 (ms) | 82.92 ± 25.48 | 91.40 ± 23.34 | +10.2 |
| 200 | Throughput (msg/s) | 1221.92 ± 162.05 | 1016.95 ± 31.81 | -16.8 |
| 200 | Throughput (KiB/s) | 1221.92 ± 162.05 | 1016.95 ± 31.81 | -16.8 |
| 200 | CPU servidor (s) | 136.65 ± 0.52 | 140.43 ± 0.25 | +2.8 |
| 200 | RAM pico servidor (MiB, acumulada del proceso) | 41.48 ± 2.81 | 61.26 ± 2.08 | +47.7 |
| 200 | Bytes en el cable / msg | 1202.63 ± 0.97 | 1373.28 ± 1.08 | +14.2 |
| 300 | Conexión+handshake (ms) | 0.40 ± 0.04 | 377.00 ± 7.82 | +93091.5 |
| 300 | Conexión+handshake p95 (ms) | 1.71 ± 0.13 | 705.12 ± 22.10 | +41105.9 |
| 300 | Login con PBKDF2 (ms, igual en ambos) | 15750.78 ± 43.24 | 15638.65 ± 79.23 | -0.7 |
| 300 | RTT p50 (ms) | 20.57 ± 2.04 | 24.61 ± 1.82 | +19.7 |
| 300 | RTT p95 (ms) | 108.68 ± 11.39 | 128.58 ± 7.11 | +18.3 |
| 300 | RTT p99 (ms) | 172.00 ± 17.84 | 209.86 ± 34.99 | +22.0 |
| 300 | Throughput (msg/s) | 1032.43 ± 19.45 | 1097.52 ± 72.52 | +6.3 |
| 300 | Throughput (KiB/s) | 1032.43 ± 19.45 | 1097.52 ± 72.52 | +6.3 |
| 300 | CPU servidor (s) | 206.88 ± 0.40 | 210.89 ± 0.26 | +1.9 |
| 300 | RAM pico servidor (MiB, acumulada del proceso) | 57.80 ± 8.58 | 78.33 ± 2.74 | +35.5 |
| 300 | Bytes en el cable / msg | 1206.56 ± 1.33 | 1375.67 ± 0.27 | +14.0 |

Tasa de éxito: 100 % en todas las rondas.
