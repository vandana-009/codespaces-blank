# AI-NIDS Federated Learning - Quick Reference Card

## 🚀 Start Everything (One Command)
```bash
cd /workspaces/codespaces-blank
bash scripts/start_federation_real_data.sh
```

**⏱️ Wait 30 seconds for system startup**

---

## 📊 View Real-Time Dashboard
Open in browser:
```
http://localhost:5000/federation/dashboard
```

You'll see:
- ✅ Connected Clients: 3 (Hospital, Bank, University)
- ✅ Current Round: incrementing (0 → 1 → 2 → ...)
- ✅ Metrics updating every 10 seconds
- ✅ Aggregation history table growing

---

## 🏢 View Individual Client Dashboards

| Organization | URL | Port |
|---|---|---|
| 🏥 Hospital | http://localhost:8001/client/dashboard | 8001 |
| 🏦 Bank | http://localhost:8002/client/dashboard | 8002 |
| 🎓 University | http://localhost:8003/client/dashboard | 8003 |

---

## 🔍 Verify Real Data Flowing

### Check Server Status
```bash
curl http://localhost:8765/api/federated/server-status
# Shows: registered_clients: 3
```

### Check Metrics Submissions
```bash
tail -f /tmp/reporter_1.log
# Shows: ✓ Metrics submitted | Round: N, Samples: XXX, Loss: Y.YY, Accuracy: Z.ZZ
```

### Check Client Isolation
```bash
sqlite3 data/nids_hospital.db "SELECT COUNT(*) FROM network_flows"
sqlite3 data/nids_bank.db "SELECT COUNT(*) FROM network_flows"
# Different counts = isolated data ✓
```

---

## 📈 Expected Behavior

```
Time    Event
─────────────────────────────────────────────────────────
T+0     System starts, all components loading
T+10    Metrics reporters register with server
T+15    First metrics submitted (Hospital, Bank, University)
T+20    Server aggregates Round 1
T+25    Dashboard shows Round 1 results
T+35    Metrics Reporter submits Round 2 data
T+40    Server aggregates Round 2
T+45    Dashboard shows Round 2 (accuracy should improve slightly)
T+60    Repeat - metrics flowing continuously
```

---

## 🛑 Stop Everything
```bash
Ctrl+C
# All processes automatically cleaned up
```

---

## 💡 Key Points to Demonstrate

1. **Real Clients Connected** 
   - Dashboard shows 3 actual Flask instances running
   - Not simulated, actually running on ports 8001-8003

2. **Real Data Flowing**
   - Metrics reporters submit actual data every 10 seconds
   - Server logs show receiving real metrics
   - Dashboard updates in real-time

3. **Data Isolation Proven**
   - Three separate SQLite databases
   - Each client trains independently
   - No raw data shared with server

4. **Aggregation Working**
   - FedAvg algorithm combines metrics
   - Global model version increments
   - Accuracy trends should improve over time

5. **Live Dashboard Proof**
   - SSE streaming updates metrics in real-time
   - Aggregation history grows
   - No page refresh needed

---

## 🐛 If It Doesn't Work

| Problem | Solution |
|---------|----------|
| Dashboard shows "Connected Clients: 0" | Wait 10 seconds, metrics reporters still registering |
| No data in aggregation history | Check `/tmp/reporter_*.log` - is reporter submitting? |
| Server not running | Check: `lsof -i :8765` and `ps aux \| grep federated_server` |
| Clients not running | Check: `ps aux \| grep "run.py"` should show 3 processes |
| Browser can't load dashboard | Ensure Flask on 5000: `curl http://localhost:5000` |

---

## 📋 What to Ask the Developer

1. "Show me the database isolation"
   ```bash
   sqlite3 data/nids_hospital.db "SELECT COUNT(*) FROM network_flows"
   ```

2. "Show me real metrics being submitted"
   ```bash
   tail /tmp/reporter_1.log
   ```

3. "Verify the server is aggregating"
   ```bash
   curl http://localhost:8765/api/federated/client-status/hospital-1
   ```

4. "Open a client dashboard and show local data"
   ```
   http://localhost:8001/client/dashboard
   ```

5. "Explain the federation flow"
   - Clients run independently
   - Metrics reporters submit to central server
   - Server aggregates using FedAvg
   - Dashboard displays real-time results

---

## 📂 Key Files to Review

| File | Purpose |
|------|---------|
| `app/routes/federated_api.py` | Server API for metrics reception |
| `scripts/client_metrics_reporter.py` | Reporting script (runs per client) |
| `scripts/start_federation_real_data.sh` | One-command startup |
| `app/routes/federation_dashboard.py` | Dashboard backend |
| `app/templates/federation_dashboard.html` | Dashboard frontend |
| `federated/metrics_bridge.py` | Server → Dashboard integration |

---

## ✅ Proof Checklist for Examiners

- [ ] Dashboard loads and shows 3 connected clients
- [ ] Aggregation history table shows completed rounds
- [ ] Metrics update every 10-30 seconds (live updates)
- [ ] Server status API returns client list
- [ ] Metrics reporter logs show submissions
- [ ] Each client database has different data (isolation proven)
- [ ] Individual client dashboards show local alerts
- [ ] No raw network flow data visible in submissions (only aggregated metrics)
- [ ] Global model version increments after each round
- [ ] System continues running without manual intervention

---

**All 10 checkpoints ✓ = Federation System Proven Real** 🎯
