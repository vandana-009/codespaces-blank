#!/bin/bash
# Load Federation Dashboard Demo Data
# Populates the dashboard with sample federation data to demonstrate functionality

echo "🚀 Loading Federation Dashboard Demo Data..."
echo ""

DASHBOARD_URL="http://localhost:5000"

# Check if dashboard is running
echo "🔍 Checking dashboard at $DASHBOARD_URL..."
if ! curl -s "$DASHBOARD_URL" > /dev/null 2>&1; then
    echo "❌ Dashboard not running at $DASHBOARD_URL"
    echo "   Start it with: FLASK_ENV=development python application.py --port 5000"
    exit 1
fi

echo "✓ Dashboard is running"
echo ""

# Load demo data
echo "📊 Populating demo data..."
RESPONSE=$(curl -s -X POST "$DASHBOARD_URL/federation/demo-data")

if echo "$RESPONSE" | grep -q '"status":"ok"'; then
    echo "✅ Demo data loaded successfully!"
    echo ""
    echo "🎉 Federation Dashboard is now ready with sample data:"
    echo "   • Hospital-NYC: 1,250 samples across 5 rounds"
    echo "   • Bank-Boston: 980 samples across 5 rounds"
    echo "   • University-SF: 1,520 samples across 5 rounds"
    echo ""
    echo "📈 Open dashboard: $DASHBOARD_URL/federation/dashboard"
    echo ""
else
    echo "⚠️  Error loading demo data:"
    echo "$RESPONSE"
    exit 1
fi
