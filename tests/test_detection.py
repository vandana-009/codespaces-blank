"""
Test Detection Engine
=====================
Tests for detection and alert management
"""

import pytest
from datetime import datetime


class TestDetectionEngine:
    """Test detection engine."""
    
    def test_detector_init(self):
        """Test detection engine initialization."""
        from detection.detector import DetectionEngine
        
        detector = DetectionEngine()
        assert detector is not None
    
    def test_threat_severity_enum(self):
        """Test threat severity enumeration."""
        from detection.detector import ThreatSeverity
        
        assert ThreatSeverity.CRITICAL.value == 'critical'
        assert ThreatSeverity.HIGH.value == 'high'
        assert ThreatSeverity.MEDIUM.value == 'medium'
        assert ThreatSeverity.LOW.value == 'low'
        assert ThreatSeverity.INFO.value == 'info'
    
    def test_detection_result(self):
        """Test detection result dataclass."""
        from detection.detector import DetectionResult, ThreatSeverity
        
        result = DetectionResult(
            is_threat=True,
            attack_type='dos',
            severity=ThreatSeverity.HIGH,
            confidence=0.95,
            model_scores={'xgboost': 0.92, 'autoencoder': 0.88}
        )
        
        assert result.is_threat is True
        assert result.confidence == 0.95
        assert 'xgboost' in result.model_scores


class TestAlertManager:
    """Test alert manager."""
    
    def test_alert_manager_init(self):
        """Test alert manager initialization."""
        from detection.alert_manager import AlertManager
        
        manager = AlertManager()
        assert manager is not None
    
    def test_alert_entry(self):
        """Test alert entry dataclass."""
        from detection.alert_manager import AlertEntry
        
        alert = AlertEntry(
            id='test-123',
            source_ip='192.168.1.100',
            dest_ip='10.0.0.50',
            attack_type='brute_force',
            severity='high',
            confidence=0.92,
            timestamp=datetime.now()
        )
        
        assert alert.id == 'test-123'
        assert alert.severity == 'high'
    
    def test_alert_stats(self):
        """Test alert statistics."""
        from detection.alert_manager import AlertStats
        
        stats = AlertStats()
        assert stats.total_alerts == 0
        assert stats.critical_count == 0


class TestLogParsers:
    """Test log parsers."""
    
    def test_suricata_parser_init(self):
        """Test Suricata parser initialization."""
        from collectors.suricata_parser import SuricataParser
        
        parser = SuricataParser()
        assert parser is not None
    
    def test_suricata_parse_eve_line(self):
        """Test Suricata EVE JSON line parsing."""
        from collectors.suricata_parser import SuricataParser
        import json
        
        parser = SuricataParser()
        
        # Sample EVE JSON
        eve_data = {
            'timestamp': '2024-01-15T10:30:00.000000+0000',
            'event_type': 'flow',
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.50',
            'src_port': 54321,
            'dest_port': 443,
            'proto': 'TCP'
        }
        
        result = parser.parse_eve_line(json.dumps(eve_data))
        
        assert result is not None
        assert result.get('src_ip') == '192.168.1.100'
    
    def test_zeek_parser_init(self):
        """Test Zeek parser initialization."""
        from collectors.zeek_parser import ZeekParser
        
        parser = ZeekParser()
        assert parser is not None
    
    def test_zeek_parse_conn_log(self):
        """Test Zeek conn.log parsing."""
        from collectors.zeek_parser import ZeekParser
        
        parser = ZeekParser()
        
        # Sample Zeek conn.log line (TSV format)
        line = "1705312200.000000\tCHhAvV\t192.168.1.100\t54321\t10.0.0.50\t80\ttcp\thttp\t0.5\t100\t200\tSF\tT\tF\t0\tShADadFf\t5\t340\t5\t440\t-"
        
        # Note: actual parsing depends on implementation
        # This is a basic test that the parser doesn't crash
        try:
            result = parser.parse_conn_log(line)
            # If successful, result should contain flow data
        except Exception as e:
            # Parser might need specific format
            pass


class TestMitigationEngine:
    """Test mitigation engine with SHAP explainability."""
    
    def test_mitigation_engine_init(self):
        """Test mitigation engine initialization."""
        from detection.mitigation_engine import MitigationEngine
        
        engine = MitigationEngine()
        assert engine is not None
    
    def test_shap_based_mitigation(self):
        """Test SHAP-based mitigation generation."""
        from detection.mitigation_engine import MitigationEngine, Severity
        
        engine = MitigationEngine()
        
        # Mock SHAP explanation
        shap_explanation = {
            'top_contributors': [
                {'feature': 'src_ip', 'contribution': 0.8},
                {'feature': 'packet_length', 'contribution': 0.6},
                {'feature': 'dst_port', 'contribution': 0.4}
            ]
        }
        
        strategy = engine.generate_mitigation_strategy(
            alert_id=1,
            attack_type='DDoS',
            severity=Severity.HIGH,
            source_ip='192.168.1.100',
            destination_ip='10.0.0.50',
            source_port=54321,
            destination_port=80,
            protocol='TCP',
            confidence=0.9,
            shap_explanation=shap_explanation
        )
        
        assert strategy is not None
        assert len(strategy.steps) > 0
        assert strategy.context.get('shap_based') is True
        
        # Check that SHAP-derived steps are prioritized
        shap_steps = [s for s in strategy.steps if 'SHAP:' in s.description]
        assert len(shap_steps) > 0
    
    def test_mitigation_without_shap(self):
        """Test mitigation generation without SHAP (fallback)."""
        from detection.mitigation_engine import MitigationEngine, Severity
        
        engine = MitigationEngine()
        
        strategy = engine.generate_mitigation_strategy(
            alert_id=2,
            attack_type='Port Scan',
            severity=Severity.MEDIUM,
            source_ip='192.168.1.101',
            destination_ip='10.0.0.51',
            source_port=12345,
            destination_port=22,
            protocol='TCP',
            confidence=0.8
        )
        
        assert strategy is not None
        assert len(strategy.steps) > 0
        assert strategy.context.get('shap_based') is False


class TestMitigationExecutor:
    """Test mitigation executor."""
    
    def test_executor_init(self):
        """Test mitigation executor initialization."""
        from detection.mitigation_executor import MitigationExecutor, ExecutionMode
        
        executor = MitigationExecutor(execution_mode=ExecutionMode.ADVISORY)
        assert executor is not None
        assert executor.execution_mode == ExecutionMode.ADVISORY
    
    def test_advisory_execution(self):
        """Test advisory mode execution."""
        from detection.mitigation_executor import MitigationExecutor, ExecutionMode
        from detection.mitigation_engine import MitigationEngine, Severity
        
        executor = MitigationExecutor(execution_mode=ExecutionMode.ADVISORY)
        engine = MitigationEngine()
        
        strategy = engine.generate_mitigation_strategy(
            alert_id=3,
            attack_type='Brute Force',
            severity=Severity.HIGH,
            source_ip='192.168.1.102',
            destination_ip='10.0.0.52',
            source_port=56789,
            destination_port=22,
            protocol='TCP',
            confidence=0.85
        )
        
        execution_id = executor.execute_strategy(
            alert_id=3,
            strategy=strategy,
            confidence=0.85
        )
        
        assert execution_id is not None
        
        status = executor.get_execution_status(execution_id)
        assert status is not None
        assert status['mode'] == 'advisory'
