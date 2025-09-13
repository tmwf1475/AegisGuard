# Collectors Kit (Minimal, Reproducible, No-Remediation)

This folder provides **simple data collection scripts** aligned with reviewer comments:
- **Linux**: minimal installer + snapshot collector
- **Windows**: minimal installer + snapshot collector
- **Docker**: container snapshot
- **Logs**: Linux log sampler

All outputs are **local JSON files** under `./out/` (no network upload), suitable for feeding into your detection prompts.

## Linux

```bash
bash linux/install_min.sh
bash linux/collector_min.sh
python3 logs/collect_logs_linux.py
```

Artifacts:
- `out/system_snapshot.json` — OS/kernel/ports/services/packages/log tails
- `out/logs_sample.json` — last 100 lines from common logs

## Windows (PowerShell)

```powershell
.\windows\Install-Min.ps1
.\windows\Collector-Min.ps1
```

Artifacts:
- `out\system_snapshot_windows.json` — OS/build/services/processes/ports/updates/log tail

## Docker (optional)

```bash
bash docker/collector_docker.sh
```

Artifacts:
- `out/docker_snapshot.json` — images, containers, truncated `docker inspect`

