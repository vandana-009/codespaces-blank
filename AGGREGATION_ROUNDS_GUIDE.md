# How to Start Aggregation Rounds in Federation System

## Overview
The federation system automatically starts and manages aggregation rounds. There are multiple ways to trigger and control them depending on your use case.

---

## 🚀 Option 1: Automatic Aggregation (Default - Recommended)

### When Starting the Full Federation Stack
```bash
bash scripts/start_federation_real_data.sh
```

**What happens:**
1. Federated server starts on port 8765
2. Round scheduler automatically begins (configured with `auto_start_scheduler=True`)
3. New rounds start every 5 seconds by default
4. Rounds complete when all selected clients submit updates or timeout
5. Dashboard auto-updates with new round metrics

**No manual action needed** - rounds run continuously in the background!

---

## 🎯 Option 2: Manual Control via API Endpoint

### Start Rounds via HTTP Request

```bash
# Start 10 aggregation rounds
curl -X POST http://localhost:5000/api/federation/start \
  -H "Content-Type: application/json" \
  -d '{"rounds": 10}'
```

**Response:**
```json
{
  "success": true,
  "message": "Federation started for 10 rounds"
}
```

### Parameters
| Parameter | Type | Default | Purpose |
|-----------|------|---------|---------|
| `rounds` | Integer | 100 | Number of rounds to execute (0 = infinite) |

### Examples

```bash
# Start 100 rounds
curl -X POST http://localhost:5000/api/federation/start \
  -d '{"rounds": 100}'

# 1 round only
curl -X POST http://localhost:5000/api/federation/start \
  -d '{"rounds": 1}'

# Infinite rounds (stop manually with Ctrl+C)
curl -X POST http://localhost:5000/api/federation/start \
  -d '{"rounds": 0}'
```

---

## ⚙️ Option 3: Programmatic Control (Python)

### Start Rounds in Python Code

```python
from federated.federated_server import create_federated_server
from ml.training.models import FedAvgModel

# Create server (auto_start_scheduler=True by default)
model = FedAvgModel()
server = create_federated_server(
    model,
    aggregation_strategy="fedavg",
    auto_start_scheduler=True  # Rounds start automatically
)

# Server runs rounds in background thread automatically
# Or control manually:
server.start_round_scheduler(num_rounds=10, interval=5.0)
```

### Advanced Control

```python
# Start single round manually
round_info = server.start_round()
print(f"Started round {round_info.round_number}")

# Do some work...

# Aggregate updates from that round
round_result = server.aggregate_round()
print(f"Round {round_result.round_number} completed")
print(f"  Participants: {len(round_result.participating_clients)}")
print(f"  Samples: {round_result.total_samples}")
print(f"  Loss: {round_result.avg_loss:.4f}")
print(f"  Accuracy: {round_result.avg_accuracy:.4f}")
```

---

## 📊 Monitor Aggregation Progress

### Check Current Round Status
```bash
# View federation metrics (includes current round)
curl http://localhost:5000/federation/api/metrics | jq

# Output will show:
# {
#   "current_round": 5,
#   "connected_clients": [...],
#   "rounds_history": [...]
# }
```

### View Round History
```bash
# Get all completed rounds and their metrics
curl http://localhost:5000/federation/api/rounds | jq
```

### Real-Time Dashboard Updates
```bash
# Open browser to see live round progression
open http://localhost:5000/federation/dashboard

# Watch metrics update in real-time as rounds complete
```

### Server Logs
```bash
# Tail federated server logs
tail -f /tmp/federated_server.log

# Output shows each round:
# INFO - Starting round 1 with 3 selected clients
# INFO - Round 1 completed: clients=3, samples=3750, loss=0.4521, acc=0.7234
# INFO - Starting round 2 with 3 selected clients
# INFO - Round 2 completed: clients=3, samples=3750, loss=0.3845, acc=0.7892
```

---

## 🔄 Understanding the Aggregation Flow

### What Happens During Each Round

```
┌─────────────────────────────────────────────────────────┐
│         Aggregation Round Lifecycle                     │
└─────────────────────────────────────────────────────────┘

1. START_ROUND
   ├─ Increment round counter
   ├─ Select clients for this round
   ├─ Notify clients to start training
   └─ Wait for updates (~5 seconds default)

2. WAIT_FOR_UPDATES
   ├─ Clients download global model
   ├─ Clients train on local data
   ├─ Clients compute gradients
   ├─ Clients submit gradients to server
   └─ Server buffers all updates

3. AGGREGATE_ROUND
   ├─ Collect all client gradients
   ├─ Apply aggregation strategy (FedAvg/FedProx/etc)
   ├─ Compute weighted average
   ├─ Update global model
   └─ Calculate aggregation metrics

4. METRICS & UPDATE
   ├─ Compute global accuracy
   ├─ Compute global loss
   ├─ Record total samples
   ├─ Store round history
   └─ Notify dashboard

5. NEXT_ROUND
   └─ Repeat from START_ROUND
```

### Timing Configuration

In `federated/federated_server.py`:
```python
def start_round_scheduler(self, num_rounds: int = 0, interval: float = 5.0):
    """
    Args:
        num_rounds: Number of rounds to run (0 = infinite)
        interval: Seconds between rounds (time for clients to submit updates)
    """
```

**Default: 5 second interval**
- Faster rounds → Quicker convergence but less time for clients
- Slower rounds → More time for slow clients to respond

---

## 📈 Aggregation Round Metrics

Each completed round includes:

```python
{
    "round": 5,                    # Round number
    "participants": 3,             # How many clients participated
    "total_samples": 3750,         # Total training samples aggregated
    "avg_loss": 0.3234,           # Global model loss
    "avg_accuracy": 0.8567,       # Global model accuracy
    "model_version": "v2.1.0-r5",  # Model version hash
    "completed_at": "2025-03-11T05:15:23Z"  # Timestamp
}
```

---

## 🎬 Complete Workflow Example

### Full End-to-End Aggregation

```bash
# Step 1: Start the federation system
bash scripts/start_federation_real_data.sh

# Step 2: In another terminal, watch rounds in real-time
curl http://localhost:5000/federation/api/metrics | jq '.current_round'

# Step 3: View dashboard with live updates
open http://localhost:5000/federation/dashboard

# Step 4: Check server logs for aggregation details
tail -f /tmp/federated_server.log | grep "Round.*completed"

# Step 5: Verify final metrics after rounds complete
curl http://localhost:5000/federation/api/metrics | jq '.rounds_history | last'
```

---

## 🚦 Troubleshooting Aggregation Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Rounds not starting | `auto_start_scheduler=False` | Use API endpoint: `POST /api/federation/start` |
| Clients not responding | Clients not running | Start clients: `python -m federated.federated_client --port 8001` |
| Slow aggregation | Network latency | Increase `interval` parameter in `start_round_scheduler()` |
| No metrics showing | Dashboard not connected | Load demo data: `bash scripts/load_federation_demo.sh` |
| Rounds stuck | Deadlock in round lock | Restart server: `pkill -f federated_server` |

---

## 💾 Checking Aggregated Model

### Get Global Model State
```bash
curl http://localhost:5000/federation/api/model | jq '.model_version'
# Output: "v2.1.0-r5" (model after round 5)
```

### Compare Accuracy Across Rounds
```bash
curl http://localhost:5000/federation/api/rounds | jq '.[] | {round: .round, accuracy: .avg_accuracy}'
# Shows progression:
# { "round": 1, "accuracy": 0.7234 }
# { "round": 2, "accuracy": 0.7892 }
# { "round": 3, "accuracy": 0.8234 }
# { "round": 4, "accuracy": 0.8456 }
# { "round": 5, "accuracy": 0.8567 }
```

---

## 📝 Summary

### Quick Start
```bash
# Automatic aggregation (recommended)
bash scripts/start_federation_real_data.sh

# Dashboard shows real-time rounds
open http://localhost:5000/federation/dashboard
```

### Manual Control
```bash
# Start 10 specific rounds
curl -X POST http://localhost:5000/api/federation/start -d '{"rounds": 10}'

# Monitor progress
curl http://localhost:5000/federation/api/metrics | jq
```

### Key Points
- ✅ Rounds start **automatically** by default
- ✅ Dashboard updates **in real-time** as rounds complete
- ✅ Each round shows metrics (accuracy, loss, samples, participants)
- ✅ Metrics available via API for programmatic access
- ✅ Full history stored for analysis

**Aggregation runs continuously - monitor via dashboard or API!**
