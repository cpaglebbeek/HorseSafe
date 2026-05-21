# MONITORING.md — HorseSafe

> Observability + alerting. Skeleton — uitwerken bij Fase 7 (productie-deploy).

## Metrics

### Backend (FastAPI :3997)
- `horsesafe_requests_total{method, path, status}` — counter
- `horsesafe_request_duration_seconds{method, path}` — histogram
- `horsesafe_login_failures_total{reason}` — counter
- `horsesafe_login_throttled_total` — counter
- `horsesafe_vault_operations_total{op}` — counter (op = read/write/delete/etag_conflict)
- `horsesafe_storage_bytes` — gauge
- `horsesafe_users_total` — gauge
- `horsesafe_vaults_total` — gauge
- `horsesafe_audit_log_writes_total` — counter

### Server (HC55-niveau)
- Disk-gebruik `/opt/horsesafe/vaults/` — alert bij >80% partitie
- Backup-laatste-success — alert bij >36u oud
- TLS-cert-expiry — alert bij <14 dagen

## Alerting

| Alert | Conditie | Severity |
|---|---|---|
| Service down | systemd-status != active | 🔴 critical |
| 5xx error rate | >5% over 5 min | 🟡 warning |
| Login-fail spike | >100/uur op één account | 🟡 warning (mogelijk brute-force) |
| Storage > 80% | partitie-vrije ruimte | 🟡 warning |
| Backup ouder dan 36u | timestamp laatste rsync | 🔴 critical |
| TLS cert < 14 dagen | certbot-status | 🟡 warning |
| Audit-log-write-fail | log-throughput nul terwijl requests binnenkomen | 🔴 critical |
| Etag-conflict spike | >50/uur | 🟡 warning (gebroken sync?) |

## Tooling

| Tool | Doel |
|---|---|
| **Dashboard.icthorse.nl** | High-level status (al bestaand) → service-tile toevoegen |
| **Loki + Promtail** (planning) | Log-aggregatie van audit.log + access.log |
| **Prometheus + Grafana** (planning) | Metrics-scrape via FastAPI `/metrics` endpoint |
| **systemd-journal** | Default logging-laag |
| **e-mail alerts** | naar cglebbeek@gmail.com via standaard HC55 monitoring-stack |

## /health endpoint

`GET /HorseSafe/api/health` (publiek, geen auth):
```json
{
  "status": "ok",
  "version": "0.0.0-Rijndael",
  "db": "ok",
  "vaults_dir": "ok",
  "backup_age_hours": 7
}
```

## /metrics endpoint

`GET /HorseSafe/api/metrics` (Prometheus-format, alleen `127.0.0.1` accessible via nginx-restrict).

## Audit-log monitoring

Dagelijkse automated check:
- Failed-login-spikes per user/IP
- Export-events met ongebruikelijk hoog volume
- Admin-events buiten kantooruren
- DELETE-events met >5 vaults in <1u

Output → e-mail-digest naar cglebbeek@gmail.com.

## SLA-doelen (intern, v0.1.0+)

| Metric | Doel |
|---|---|
| Uptime | 99.5% (=  ~3.5u downtime/maand) |
| p95 latency `/auth/login` | < 500ms |
| p95 latency `/vault/{id}` GET | < 200ms |
| p95 latency `/vault/{id}` PUT | < 1s (Argon2id duurt) |
| Backup-RPO | 24u |
| Backup-RTO | 2u |

## Sanity-checks pre-flight

Voor elke deploy:
```bash
# Health-endpoint
curl -fsS https://horsecloud55.ddns.net/HorseSafe/api/health
# Login round-trip
./scripts/smoke-test.sh
# Vault roundtrip (encrypted blob byte-identiek?)
./scripts/kdbx-roundtrip-test.sh
```
