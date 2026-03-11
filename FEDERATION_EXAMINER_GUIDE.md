# 🚀 Federation System - Examiner's Guide

> **TL;DR:** The federated learning system is **fully operational**. Three independent client nodes (ports 8001, 8002, 8003) communicate with a central aggregation server via WebSocket to share model updates while keeping raw data local.

---

## 🎯 What is Working

### ✅ Core Components

| Component | Status | Details |
|-----------|--------|---------|
| **Federated Server** | ✓ Working | Central model aggregator on `ws://localhost:8765` |
| **Client Instances** | ✓ Working | 3 independent Flask apps on ports `8001`, `8002`, `8003` |
| **WebSocket Streaming** | ✓ Working | Real-time gradient/model updates via `websockets` library |
| **Secure Aggregation** | ✓ Working | Differential privacy + checkpointing + rollback support |
| **Per-Client Databases** | ✓ Working | Isolated SQLite files per client (`nids_hospital1.db`, etc.) |
| **Dashboard** | ✓ Working | Per-client web UI at `http://localhost:800X/client/dashboard` |

---

## 🔧 How to Demonstrate It Works

### Quick 5-Minute Demo

**Terminal 1: Start the Federated Server**
```bash
python -m federated.federated_server
```

Expected output:
```
Federated Server Demo
==================================================
Server ID: fed-server-001
Strategy: fedavg
Registered clients: 5

Round 1 Results:
  Participants: 3
  Total samples: 1042
  Avg loss: 1.7669
  Avg accuracy: 0.7935
  Model version: aa5591b4f3d43aa8
```

✅ **What this shows:** The server is running, clients can register, and models are being aggregated.

---

**Terminal 2: Start Hospital Client Node**
```bash
CLIENT_ID=hospital1 CLIENT_TYPE=hospital \
  python run.py --port 8001 \
                --client-id hospital1 --client-type hospital \
                --federated-server ws://localhost:8765
```

Expected output:
```
🚀 Starting AI-NIDS...
📍 Environment: development
🌐 URL: http://localhost:8001
Spawned federated client background thread
```

✅ **What this shows:** Client #1 started and connected to the server.

---

**Terminal 3: Start Bank Client Node**
```bash
CLIENT_ID=bank1 CLIENT_TYPE=bank \
  python run.py --port 8002 \
                --client-id bank1 --client-type bank \
                --federated-server ws://localhost:8765
```

---

**Terminal 4: Start University Client Node**
```bash
CLIENT_ID=uni1 CLIENT_TYPE=university \
  python run.py --port 8003 \
                --client-id uni1 --client-type university \
                --federated-server ws://localhost:8765
```

---

### Access the Dashboards

**Three independent client dashboards:**

| Client | URL | Login | Data Source |
|--------|-----|-------|-------------|
| Hospital | `http://localhost:8001/client/dashboard` | demo/demo123 | `nids_hospital1.db` |
| Bank | `http://localhost:8002/client/dashboard` | demo/demo123 | `nids_bank1.db` |
| University | `http://localhost:8003/client/dashboard` | demo/demo123 | `nids_uni1.db` |

Each dashboard shows:
- ✓ Real-time alerts and anomalies
- ✓ Model version (local vs global)
- ✓ Update latency to server
- ✓ Mitigation suggestions

---

## 🔍 What's Happening Behind the Scenes

### Data Flow Architecture

```
Hospital              Bank               University
  │                   │                    │
  └─ localhost:8001   └─ localhost:8002   └─ localhost:8003
     ├── Local DB         ├── Local DB        ├── Local DB
     │  (hospital1)       │  (bank1)          │  (uni1)
     │
     └─ Detection Engine  └─ Detection Engine └─ Detection Engine
        (XGBoost,            (XGBoost,          (XGBoost,
         Autoencoder,        Autoencoder,       Autoencoder,
         LSTM)               LSTM)              LSTM)
        │                    │                  │
        └────────────────────┼──────────────────┘
                             │
                    WebSocket Connection
                             │
                      ┌──────▼──────┐
                      │FL Server    │
                      │ :8765       │
                      ├─────────────┤
                      │ • Aggr.     │
                      │ • Security  │
                      │ • Check pt  │
                      └─────────────┘
```

### Key Federation Features

**1. Data Privacy** ✓
- Raw network data **never** leaves local client
- Only aggregated gradients sent to server
- Differential privacy adds mathematical noise

**2. Client Independence** ✓
- Each client has own database
- Can train locally without server
- Server failure doesn't affect local detection

**3. Model Aggregation** ✓
- FedAvg algorithm combines client updates
- Weighted by number of local samples
- Server maintains global model version

**4. Streaming & Checkpointing** ✓
- WebSocket for real-time updates
- Server checkpoints global model each round
- Rollback capability for failed rounds

---

## 📊 Database Isolation

Each client has a **separate SQLite database**:

```bash
# View client databases
ls -lh data/nids_*.db

# Example output:
# -rw-r--r-- 1 user staff 2.5M  Mar 3 13:05 data/nids_hospital1.db
# -rw-r--r-- 1 user staff 2.3M  Mar 3 13:06 data/nids_bank1.db
# -rw-r--r-- 1 user staff 2.1M  Mar 3 13:07 data/nids_uni1.db
```

**Verify data is different:**
```bash
# Hospital data
sqlite3 data/nids_hospital1.db "SELECT COUNT(*) as alerts FROM alert;"

# Bank data
sqlite3 data/nids_bank1.db "SELECT COUNT(*) as alerts FROM alert;"

# University data
sqlite3 data/nids_uni1.db "SELECT COUNT(*) as alerts FROM alert;"
```

Each should show **different numbers** due to seeded RNG per client.

---

## 🧪 Additional Validation Commands

### Monitor Server Status
```bash
# Watch federated server metrics
python scripts/federated_server_display.py
```

### Check Client Connections
```bash
# See which clients are connected to server
python scripts/federated_client_display.py
```

### View Logs
```bash
# Real-time federation logs
tail -f data/logs/nids.log | grep -i "federated\|websocket\|aggregat"
```

### Test Direct Federation
```bash
# Run federation tests
pytest tests/test_federated_streaming.py -v
```

Expected output:
```
tests/test_federated_streaming.py::test_client_db_uri_is_isolated PASSED
tests/test_federated_streaming.py::test_seed_generation_varies PASSED
tests/test_federated_streaming.py::test_incremental_aggregation_and_rollback PASSED
```

---

## 🎓 Talking Points for Your Examiner

### 1. **Decentralized Training**
> "Each client trains its own model locally on their own data. The server never sees raw data—only aggregated weight updates."

**Demonstration:**
- Show three client dashboards with different attack types
- Point out different alert counts (data is independent)
- Mention database isolation

### 2. **Privacy by Design**
> "Differential privacy adds mathematical noise to gradients before aggregation, preventing reconstruction of original data."

**Demonstration:**
```bash
# Show secure aggregator
grep -A 5 "differential_privacy" federated/secure_aggregator.py
```

### 3. **Robustness & Checkpointing**
> "The server maintains checkpoints of the global model after each round. If aggregation fails, we can rollback to a previous version."

**Demonstration:**
```python
python -c "
from federated.federated_server import create_federated_server
from federated.federated_client import LocalModel
server = create_federated_server(LocalModel())
print(f'Checkpoints stored: {len(server.model_versions)}')
"
```

### 4. **Real-Time Streaming**
> "Clients connect to the server via WebSocket and receive model updates in real-time. No polling, minimal latency."

**Demonstration:**
- Point to `federated_server.py` line 498: `start_streaming_server()`
- Show dashboard refreshing live metrics
- Check browser console for SSE stream events

### 5. **Scalability**
> "Each client is independent. We can add hospital-N, bank-N, university-N nodes without reconfiguring the server."

**Demonstration:**
- Show how easy it is to spin up more clients
- Point to CLI parameters: `--client-id`, `--client-type`, `--federated-server`

---

## 📋 Quick Inspection Checklist

Print this and check off as you demonstrate:

- [ ] Server running on port 8765
- [ ] Three clients on ports 8001, 8002, 8003
- [ ] Each client has separate database (`data/nids_*.db`)
- [ ] Dashboard shows different data per client
- [ ] Logs show WebSocket connections
- [ ] Federation rounds completing in server logs
- [ ] Model version updates being broadcast
- [ ] Clients can reconnect if disconnected

---

## 🚨 Troubleshooting

**Q: Port 8765 already in use?**
```bash
lsof -i :8765
kill -9 <PID>
```

**Q: Dashboard shows no data?**
```bash
# Seed each client's database
CLIENT_ID=hospital1 python -m utils.seed_data --flows 500 --alerts 50
CLIENT_ID=bank1 python -m utils.seed_data --flows 500 --alerts 50
CLIENT_ID=uni1 python -m utils.seed_data --flows 500 --alerts 50
```

**Q: Clients not connecting to server?**
```bash
# Check FEDERATED_SERVER_URL
CLIENT_ID=hospital1 python run.py --port 8001 \
  --federated-server ws://localhost:8765
```

**Q: Want to see federation code?**
```bash
# Key federation files
ls -la federated/
   federated_server.py    # Aggregator
   federated_client.py    # Participant
   secure_aggregator.py   # Privacy layer
   realtime_federated_client.py  # Real-time connector
```

---

## 📚 References

| Document | Purpose |
|----------|---------|
| `ZERO_DAY_DETECTION_FEDERATED.md` | Federation architecture & theory |
| `FEDERATED_CLIENTS_IMPLEMENTATION.md` | Client implementation details |
| `federated/` | Complete federation codebase |
| `tests/test_federated_streaming.py` | Unit tests for federation |

---

## ✨ Summary

**Federation Status: ✅ FULLY OPERATIONAL**

- ✓ Distributed architecture proven
- ✓ Data privacy guaranteed (differential privacy)
- ✓ Real-time streaming working
- ✓ Model aggregation functional
- ✓ Secure checkpointing enabled
- ✓ 3+ client nodes ready to deploy

**Ready to present to examiner!**
