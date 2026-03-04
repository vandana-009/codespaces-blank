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

Start a client node with environment variables or CLI flags:

```bash
CLIENT_ID=hospital1 CLIENT_TYPE=hospital python run.py --port 8001 \
    --client-id hospital1 --client-type hospital \
    --federated-server ws://localhost:8765
```

The same command (with different IDs/ports) can be used for other sites
(`bank`, `university`, etc.).  Each node will automatically register with
the federated server, connect via WebSockets, and stream gradient updates.

### Federated Server

The coordination server runs separately (no UI necessary):

```bash
python run.py --port 8000
```

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
