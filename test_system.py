#!/usr/bin/env python3
"""
Quick Test Script for AI-NIDS Real-Time Components
Tests all three main features: mitigation, federated clients, and packet capture
"""

import sys
import time
from datetime import datetime

def test_imports():
    """Test that all components can be imported."""
    print("🔍 Testing component imports...")

    try:
        from realtime.orchestrator import RealtimeOrchestrator, RealtimeConfig
        print("✅ Real-time orchestrator imported")
    except ImportError as e:
        print(f"❌ Failed to import orchestrator: {e}")
        return False

    try:
        from federated.realtime_federated_client import RealtimeFederatedClient, RealtimeFederatedConfig
        print("✅ Real-time federated client imported")
    except ImportError as e:
        print(f"❌ Failed to import federated client: {e}")
        return False

    try:
        from mitigation.mitigation_module import MitigationModule, create_mitigation_module
        print("✅ Mitigation module imported")
    except ImportError as e:
        print(f"❌ Failed to import mitigation module: {e}")
        return False

    try:
        from collectors.live_capture import LiveCapture, DetectionCallback, create_live_capture
        print("✅ Live capture module imported")
    except ImportError as e:
        print(f"❌ Failed to import live capture: {e}")
        return False

    return True

def test_packet_capture():
    """Test packet capture functionality."""
    print("\n📡 Testing packet capture...")

    try:
        from collectors.live_capture import LiveCapture

        # List available interfaces
        interfaces = LiveCapture.list_interfaces()
        print(f"✅ Found {len(interfaces)} network interfaces")

        default_iface = LiveCapture.get_default_interface()
        print(f"✅ Default interface: {default_iface}")

        return True
    except Exception as e:
        print(f"❌ Packet capture test failed: {e}")
        return False

def test_mitigation():
    """Test mitigation module creation."""
    print("\n🛡️  Testing mitigation module...")

    try:
        from mitigation.mitigation_module import create_mitigation_module
        from response.firewall_manager import FirewallManager

        # Create firewall manager (mock for testing)
        firewall_manager = FirewallManager()

        # Create mitigation module
        mitigation = create_mitigation_module(firewall_manager)
        print("✅ Mitigation module created successfully")

        return True
    except Exception as e:
        print(f"❌ Mitigation test failed: {e}")
        return False

def test_federated_client():
    """Test federated client creation."""
    print("\n🤝 Testing federated client...")

    try:
        from federated.realtime_federated_client import RealtimeFederatedConfig, create_realtime_federated_client

        # Create config
        config = RealtimeFederatedConfig(
            client_id="test-client-001",
            server_url="http://localhost:5001",
            organization="test-org"
        )

        # Create client (without starting it)
        client = create_realtime_federated_client(config)
        print("✅ Federated client created successfully")

        return True
    except Exception as e:
        print(f"❌ Federated client test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("AI-NIDS Real-Time System Test")
    print("=" * 60)
    print(f"Test started at: {datetime.now()}")

    # Test imports
    if not test_imports():
        print("\n❌ Import tests failed. Cannot continue.")
        sys.exit(1)

    # Test individual components
    tests = [
        ("Packet Capture", test_packet_capture),
        ("Mitigation", test_mitigation),
        ("Federated Client", test_federated_client)
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")

    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! Your AI-NIDS system is ready.")
        print("\n🚀 To start the real-time system:")
        print("   1. Development: docker-compose up")
        print("   2. Production: cd k8s && ./deploy.sh")
        print("   3. Manual: python -m realtime.orchestrator")
    else:
        print("⚠️  Some tests failed. Check the errors above.")

    print("=" * 60)

if __name__ == "__main__":
    main()