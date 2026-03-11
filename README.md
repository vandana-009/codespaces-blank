# AI-NIDS

AI-NIDS is an AI-powered network intrusion detection system with
support for federated learning, real-time detection, and per-client
dashboards.

> 🎓 **For Examiners & Presentations:** See [FEDERATION_DEMO_READY.md](FEDERATION_DEMO_READY.md) for complete setup instructions and talking points. Takes 5 minutes to demonstrate!

## Realtime Federated Clients & Dashboards

This repository now supports **realtime streaming federated learning** with
per-client dashboards.  Each client instance runs independently on its own
port (e.g. `localhost:8001`, `8002`, `8003`) and carries out its own live
capture, detection, mitigation, and model training.  A lightweight Flask UI
(`/client/dashboard`) is available on each node displaying:

- Recent alerts and anomaly scores
- Local & global model versions
- Update latency metrics
- Mitigation suggestions

### Running a Client

New deployments use the lightweight entrypoint `application.py` rather than
`run.py`.  You can still pass the same configuration options via CLI or
environment variables.  The easiest way to launch a set of clients and the
server is to use the provided script:

```bash
./scripts/start_federation_real_data.sh
```

which will seed each client database and start three nodes on ports
8001–8003 along with the federated server (8765) and dashboard (5000).

If you prefer to run a single client manually:

```bash
CLIENT_ID=hospital1 CLIENT_TYPE=hospital \
    python application.py --port 8001 \
        --client-id hospital1 --client-type hospital \
        --federated-server ws://localhost:8765
```

Each node automatically registers with the server, connects via WebSockets,
and streams gradient updates.

### Federated Server

The coordination server can be started on its own as well:

```bash
python application.py --port 8000
```

(or via the same start script above).

Use the CLI commands to manage the global model:

```bash
flask federated-rollback <round_number>
flask federated-upgrade
```
Model rollbacks and upgrades are only available via the terminal; no
interface exists on the UI.

### Dependencies

Realtime streaming requires the `websockets` package (added to
`requirements.txt`).  Clients automatically fall back to REST if
`websockets` is unavailable, but streaming provides lower latency.
