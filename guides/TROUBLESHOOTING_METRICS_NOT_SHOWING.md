# Federation Dashboard - Metrics Not Showing Problem & Solution

## The Problem

**Symptom:**
```
✅ Federated Server ready for distributed coordination!
Recent rounds: [{'round': 3, 'participants': 3, ...}]
```

But dashboard shows NO rounds/metrics when you open `http://localhost:5000/federation/dashboard`

---

## Root Cause

The federated server (standalone process on port 8765) completes rounds successfully, but **the metrics are not reaching the Flask dashboard** (port 5000).

### Why This Happens

1. **Federated Server** (`python -m federated.federated_server`) runs as separate process
2. It completes rounds and tries to notify dashboard via HTTP POST
3. HTTP request **fails silently** because either:
   - Flask app is NOT running on port 5000
   - OR ingest endpoint is failing but errors are hidden
4. Metrics stay in federated server logs but never reach dashboard

---

## Solution

### Step 1: Verify Flask App is Running

**Check if port 5000 is listening:**
```bash
lsof -i :5000
# Should show: something like "python ... (LISTEN)"

# Or use curl to test health endpoint:
curl -v http://localhost:5000/api/federation/health
```

**Expected response:**
```json
{
  "status": "ok",
  "service": "federation-ingest-api",
  "message": "Federation Ingest API is ready..."
}
```

### Step 2: If Flask App is NOT Running

**Start the Flask dashboard app:**
```bash
# In a separate terminal:
FLASK_ENV=development python application.py --port 5000

# You should see:
# * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
```

### Step 3: Verify Metrics are Now Flowing

**Check the Flask app logs for ingest messages:**
```bash
# Look for messages like:
# INFO - push_round: Received round 3 from server fed-server-demo-001
# INFO - ✓ Round 3 successfully recorded in dashboard
```

**Test the ingest endpoint manually:**
```bash
curl -X POST http://localhost:5000/api/federation/push-round \
  -H "Content-Type: application/json" \
  -d '{
    "round": 99,
    "participants": 3,
    "samples": 3750,
    "loss": 0.3234,
    "accuracy": 0.8567,
    "model_version": "test-version"
  }' | jq
```

**Expected:**
```json
{"status": "ok", "message": "Round 99 recorded"}
```

### Step 4: Check Dashboard

Open browser to `http://localhost:5000/federation/dashboard`

**Should now show:**
- ✅ Metrics cards with current round data
- ✅ Client connection cards
- ✅ Round history with completed rounds

---

## Quick Fix: The Three-Terminal Setup

This is the **most reliable way** to run the federation system:

### Terminal 1: Start Federated Server
```bash
python -m federated.federated_server
```

Watch for output:
```
✅ Federated Server ready for distributed coordination!
INFO - Pushing round 1 to dashboard at http://localhost:5000/api/federation/push-round
INFO - Dashboard push-round response: 200 - {"status": "ok"}
```

### Terminal 2: Start Flask Dashboard App
```bash
FLASK_ENV=development python application.py --port 5000
```

Watch for output:
```
 * Running on http://127.0.0.1:5000/
INFO - push_round: Received round 1 from server fed-server-demo-001
INFO - ✓ Round 1 successfully recorded in dashboard
```

### Terminal 3: Start Clients & Reporters
```bash
bash scripts/start_federation_clients.sh
# Or start individual clients:
python -m federated.federated_client --port 8001 &
python -m federated.federated_client --port 8002 &
python -m federated.federated_client --port 8003 &
```

### Terminal 4: View Dashboard
```bash
open http://localhost:5000/federation/dashboard
```

**You should now see metrics updating in real-time!**

---

## Debugging Steps

### If Metrics Still Not Showing

**1. Check if federated server is actually running:**
```bash
ps aux | grep federated_server
# Should show a running python process
```

**2. Check if Flask app is actually running:**
```bash
ps aux | grep "application.py"
# Should show a running python process on port 5000
```

**3. Tail both log files simultaneously:**
```bash
# Terminal A:
tail -f /tmp/federated_server.log | grep -E "Pushing|Dashboard|Round"

# Terminal B:
FLASK_ENV=development python application.py --port 5000 2>&1 | grep -E "push_round|push_update|Round"
```

**4. Enable debug-level logging in federated server:**
```bash
LOGLEVEL=DEBUG python -m federated.federated_server
```

**5. Test connectivity directly:**
```bash
# From federated server machine, test if flask is reachable:
curl -v http://localhost:5000/api/federation/health

# Should get 200 OK response
```

---

## Common Issues & Fixes

| Issue | Cause | Fix |
|-------|-------|-----|
| "Connection refused" error in server logs | Flask app not running | Start Flask: `FLASK_ENV=development python application.py --port 5000` |
| `health` endpoint returns 404 | Flask app running but ingest blueprint not registered | Verify `app/__init__.py` has `federation_ingest_bp` import and registration |
| Rounds show in server logs but not dashboard | HTTP push failing silently (old code) | Use latest code with improved logging |
| Dashboard "Loading..." never changes | No data reaching dashboard | Load demo data: `curl -X POST http://localhost:5000/federation/demo-data` |
| Port 5000 already in use | Another app on same port | Use different port: `python application.py --port 5001` |

---

## Environment Setup for Success

### Ensure These Ports are Available

```bash
# Check if ports are free:
lsof -i :5000 :8765 :8001 :8002 :8003

# If occupied, kill processes:
pkill -f "python.*federated_server"
pkill -f "application.py"
pkill -f "federated_client"
```

### Set Environment Variables (Optional)

```bash
# Use custom dashboard URL if not on localhost
export DASHBOARD_PUSH_URL="http://your-server:5000"

# Then start federated server:
python -m federated.federated_server
```

---

## Verification Checklist

After making changes, verify everything works:

- [ ] Terminal 1: Federated server running, showing "✅ ready"
- [ ] Terminal 2: Flask app running on port 5000
- [ ] Server logs show: "Pushing round X to dashboard"
- [ ] Flask logs show: "✓ Round X successfully recorded"
- [ ] Browser shows metrics cards populated
- [ ] Dashboard updates every 5 seconds (watch current_round change)
- [ ] Client cards show organization names and metrics

---

## Expected vs Actual Output

### Correct Setup (Metrics Flowing)

**Server Logs:**
```
✅ Federated Server ready for distributed coordination!
Client Stats:
  client-000: 396 samples
  client-001: 215 samples
  client-002: 411 samples
INFO - Pushing round 1 to dashboard at http://localhost:5000/api/federation/push-round
INFO - Dashboard push-round response: 200 - {"status": "ok", "message": "Round 1 recorded"}
```

**Flask Logs:**
```
 * Running on http://127.0.0.1:5000/
INFO - push_round: Received round 1 from server fed-server-demo-001: participants=3, samples=3750, loss=0.4521, accuracy=0.7234
INFO - ✓ Round 1 successfully recorded in dashboard
```

**Dashboard:**
```
Current Round: 1
Connected Clients: 3
Total Samples: 3750
Last Aggregation: 2 seconds ago

Client Cards showing:
  ✓ Hospital-NYC: 1,250 samples, 0.87 accuracy
  ✓ Bank-Boston: 980 samples, 0.87 accuracy
  ✓ University-SF: 1,520 samples, 0.87 accuracy
```

### Broken Setup (Metrics NOT Flowing)

**Server Logs:**
```
✅ Federated Server ready...
Client Stats: [...]
INFO - Pushing round 1 to dashboard...
ERROR - FAILED to connect to dashboard at http://localhost:5000: Connection refused
```

**Solution:** Start Flask app

---

## Summary

**TL;DR** for metrics not showing:

```bash
# Terminal 1
python -m federated.federated_server

# Terminal 2 (NEW - This is what was missing!)
FLASK_ENV=development python application.py --port 5000

# Terminal 3
bash scripts/start_federation_clients.sh

# Browser
open http://localhost:5000/federation/dashboard
```

**The key fix:** You need BOTH processes running:
1. **Federated server** (port 8765) - generates metrics
2. **Flask dashboard** (port 5000) - receives and displays metrics

If either one is missing, metrics won't show up!

