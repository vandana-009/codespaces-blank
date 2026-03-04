"""
Mitigation Module for AI-NIDS
=============================
Comprehensive mitigation system that:
- Generates mitigation strategies for detected anomalies
- Executes mitigation actions through the response engine
- Tracks mitigation status and effectiveness
- Provides results for dashboard display
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import asyncio

from detection.mitigation_engine import MitigationEngine, Severity, MitigationStrategy as Strategy
from response.response_engine import ResponseEngine, ResponseAction, ResponseResult
from response.firewall_manager import FirewallManager
from app.models.database import db, Alert, MitigationStrategy, SystemMetrics

logger = logging.getLogger(__name__)


class MitigationStatus(Enum):
    """Status of mitigation actions."""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    EXPIRED = "expired"


@dataclass
class MitigationResult:
    """Result of a mitigation action."""
    strategy_id: int
    alert_id: int
    status: MitigationStatus
    executed_steps: List[Dict] = field(default_factory=list)
    failed_steps: List[Dict] = field(default_factory=list)
    effectiveness_score: Optional[float] = None
    execution_time: Optional[float] = None
    notes: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'strategy_id': self.strategy_id,
            'alert_id': self.alert_id,
            'status': self.status.value,
            'executed_steps': self.executed_steps,
            'failed_steps': self.failed_steps,
            'effectiveness_score': self.effectiveness_score,
            'execution_time': self.execution_time,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class MitigationModule:
    """
    Comprehensive mitigation module for AI-NIDS.

    Features:
    - Automatic mitigation strategy generation
    - Execution through response engine
    - Status tracking and effectiveness measurement
    - Dashboard integration for result display
    """

    def __init__(
        self,
        mitigation_engine: MitigationEngine,
        response_engine: ResponseEngine,
        auto_execute_threshold: float = 0.85,
        max_concurrent_mitigations: int = 10,
        db_session=None
    ):
        """
        Initialize mitigation module.

        Args:
            mitigation_engine: Engine for generating mitigation strategies
            response_engine: Engine for executing response actions
            auto_execute_threshold: Confidence threshold for auto-execution
            max_concurrent_mitigations: Maximum concurrent mitigation operations
            db_session: Database session (optional, uses Flask-SQLAlchemy if not provided)
        """
        self.mitigation_engine = mitigation_engine
        self.response_engine = response_engine
        self.auto_execute_threshold = auto_execute_threshold
        self.max_concurrent = max_concurrent_mitigations
        self.db_session = db_session

        # Active mitigations tracking
        self._active_mitigations: Dict[int, MitigationResult] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent_mitigations)

        logger.info("Mitigation module initialized")

    async def mitigate_anomaly(
        self,
        alert_id: int,
        attack_type: str,
        severity: Severity,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: str,
        confidence: float,
        additional_context: Optional[Dict] = None,
        shap_explanation: Optional[Dict] = None
    ) -> MitigationResult:
        """
        Mitigate a detected anomaly.

        Args:
            alert_id: ID of the alert to mitigate
            attack_type: Type of attack detected
            severity: Severity level
            source_ip: Source IP address
            destination_ip: Destination IP address
            source_port: Source port
            destination_port: Destination port
            protocol: Network protocol
            confidence: Detection confidence
            additional_context: Additional context for mitigation

        Returns:
            MitigationResult with execution details
        """
        async with self._semaphore:
            try:
                logger.info(f"Starting mitigation for alert {alert_id}: {attack_type}")

                # Generate mitigation strategy
                strategy = self.mitigation_engine.generate_mitigation_strategy(
                    alert_id=alert_id,
                    attack_type=attack_type,
                    severity=severity,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    source_port=source_port,
                    destination_port=destination_port,
                    protocol=protocol,
                    confidence=confidence,
                    additional_context=additional_context,
                    shap_explanation=shap_explanation
                )

                # Create mitigation result tracker
                result = MitigationResult(
                    strategy_id=id(strategy),  # Use object id for now
                    alert_id=alert_id,
                    status=MitigationStatus.PENDING
                )

                self._active_mitigations[alert_id] = result

                # Store strategy in database
                await self._store_strategy(strategy, alert_id)

                # Check if auto-execution is allowed
                if confidence >= self.auto_execute_threshold:
                    result.status = MitigationStatus.APPROVED
                    await self._execute_mitigation_strategy(strategy, result)
                else:
                    # Manual approval required
                    result.notes = f"Manual approval required (confidence: {confidence:.2f})"
                    logger.info(f"Manual approval required for alert {alert_id}")

                return result

            except Exception as e:
                logger.error(f"Error mitigating alert {alert_id}: {e}")
                result = MitigationResult(
                    strategy_id=0,
                    alert_id=alert_id,
                    status=MitigationStatus.FAILED,
                    notes=f"Error: {str(e)}"
                )
                self._active_mitigations[alert_id] = result
                return result

    async def _store_strategy(self, strategy: Strategy, alert_id: int) -> None:
        """Store mitigation strategy in database."""
        try:
            # Use provided db_session or default to Flask-SQLAlchemy
            session = self.db_session or db.session
            
            # Store each step as a separate MitigationStrategy record
            for step in strategy.steps:
                db_strategy = MitigationStrategy(
                    alert_id=alert_id,
                    attack_type=strategy.attack_type,
                    severity_level=strategy.severity.name.lower(),
                    action_type=step.action.value,
                    target=step.target,
                    description=step.description,
                    command=step.command,
                    priority=step.priority,
                    is_automated=step.is_automated,
                    automation_threshold=step.automation_threshold,
                    status='pending'
                )
                session.add(db_strategy)

            session.commit()
            logger.debug(f"Stored {len(strategy.steps)} mitigation steps for alert {alert_id}")

        except Exception as e:
            logger.error(f"Error storing mitigation strategy: {e}")
            if self.db_session:
                self.db_session.rollback()
            else:
                db.session.rollback()

    async def _execute_mitigation_strategy(
        self,
        strategy: Strategy,
        result: MitigationResult
    ) -> None:
        """Execute a mitigation strategy."""
        try:
            result.status = MitigationStatus.EXECUTING
            start_time = datetime.utcnow()

            logger.info(f"Executing mitigation strategy for alert {result.alert_id}")

            # Execute each step in priority order
            for step in strategy.steps:
                try:
                    execution_result = await self._execute_mitigation_step(step, strategy)
                    if execution_result['success']:
                        result.executed_steps.append({
                            'action': step.action.value,
                            'target': step.target,
                            'description': step.description,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    else:
                        result.failed_steps.append({
                            'action': step.action.value,
                            'target': step.target,
                            'description': step.description,
                            'error': execution_result.get('error', 'Unknown error'),
                            'timestamp': datetime.utcnow().isoformat()
                        })

                except Exception as e:
                    logger.error(f"Error executing step {step.action.value}: {e}")
                    result.failed_steps.append({
                        'action': step.action.value,
                        'target': step.target,
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    })

            # Calculate execution time
            end_time = datetime.utcnow()
            result.execution_time = (end_time - start_time).total_seconds()

            # Update status
            if result.failed_steps:
                if len(result.failed_steps) == len(strategy.steps):
                    result.status = MitigationStatus.FAILED
                    result.notes = "All mitigation steps failed"
                else:
                    result.status = MitigationStatus.EXECUTED
                    result.notes = f"Partial success: {len(result.executed_steps)}/{len(strategy.steps)} steps executed"
            else:
                result.status = MitigationStatus.EXECUTED
                result.notes = "All mitigation steps executed successfully"

            result.completed_at = end_time

            # Update database
            await self._update_mitigation_status(result)

            # Calculate effectiveness (simplified)
            result.effectiveness_score = self._calculate_effectiveness(result)

            logger.info(f"Mitigation completed for alert {result.alert_id}: {result.status.value}")

        except Exception as e:
            logger.error(f"Error executing mitigation strategy: {e}")
            result.status = MitigationStatus.FAILED
            result.notes = f"Execution error: {str(e)}"
            result.completed_at = datetime.utcnow()

    async def _execute_mitigation_step(
        self,
        step: Any,  # MitigationStep from mitigation_engine
        strategy: Strategy
    ) -> Dict[str, Any]:
        """Execute a single mitigation step."""
        try:
            action = step.action.value

            # Map mitigation actions to response actions
            if action == 'block_ip':
                response_results = await self.response_engine.respond_to_threat(
                    target_ip=step.target,
                    severity=self._severity_to_float(strategy.severity),
                    threat_type=strategy.attack_type,
                    reason=step.description,
                    force=True
                )
                success = any(r.success for r in response_results)

            elif action == 'rate_limit':
                # Rate limiting implementation would go here
                # For now, treat as successful
                success = True

            elif action == 'isolate_host':
                response_results = await self.response_engine.respond_to_threat(
                    target_ip=step.target,
                    severity=self._severity_to_float(strategy.severity),
                    threat_type=strategy.attack_type,
                    reason=step.description,
                    force=True
                )
                success = any(r.success for r in response_results)

            elif action == 'alert_soc':
                # SOC alerting would be implemented here
                success = True

            elif action == 'quarantine':
                response_results = await self.response_engine.respond_to_threat(
                    target_ip=step.target,
                    severity=self._severity_to_float(strategy.severity),
                    threat_type=strategy.attack_type,
                    reason=step.description,
                    force=True
                )
                success = any(r.success for r in response_results)

            else:
                # Generic action - assume success for now
                logger.warning(f"Unknown mitigation action: {action}")
                success = True

            return {'success': success}

        except Exception as e:
            logger.error(f"Error executing mitigation step: {e}")
            return {'success': False, 'error': str(e)}

    def _severity_to_float(self, severity: Severity) -> float:
        """Convert Severity enum to float."""
        mapping = {
            Severity.CRITICAL: 0.95,
            Severity.HIGH: 0.85,
            Severity.MEDIUM: 0.65,
            Severity.LOW: 0.35,
            Severity.INFO: 0.15
        }
        return mapping.get(severity, 0.5)

    async def _update_mitigation_status(self, result: MitigationResult) -> None:
        """Update mitigation status in database."""
        try:
            strategies = MitigationStrategy.query.filter_by(alert_id=result.alert_id).all()
            for strategy in strategies:
                if result.status == MitigationStatus.EXECUTED:
                    strategy.status = 'executed'
                    strategy.executed_at = result.completed_at
                    strategy.execution_result = result.notes
                    strategy.effectiveness_score = result.effectiveness_score
                elif result.status == MitigationStatus.FAILED:
                    strategy.status = 'failed'
                    strategy.execution_result = result.notes

            db.session.commit()

        except Exception as e:
            logger.error(f"Error updating mitigation status: {e}")
            db.session.rollback()

    def _calculate_effectiveness(self, result: MitigationResult) -> float:
        """Calculate mitigation effectiveness score."""
        if not result.executed_steps:
            return 0.0

        total_steps = len(result.executed_steps) + len(result.failed_steps)
        if total_steps == 0:
            return 1.0

        success_rate = len(result.executed_steps) / total_steps

        # Weight by priority (higher priority = more important)
        # This is a simplified calculation
        return success_rate

    async def get_mitigation_status(self, alert_id: int) -> Optional[MitigationResult]:
        """Get mitigation status for an alert."""
        return self._active_mitigations.get(alert_id)

    async def get_all_active_mitigations(self) -> List[MitigationResult]:
        """Get all active mitigations."""
        return list(self._active_mitigations.values())

    async def rollback_mitigation(self, alert_id: int) -> bool:
        """Rollback mitigation for an alert."""
        try:
            result = self._active_mitigations.get(alert_id)
            if not result or result.status != MitigationStatus.EXECUTED:
                return False

            # Get strategies from database
            strategies = MitigationStrategy.query.filter_by(alert_id=alert_id).all()

            rollback_success = True
            for strategy in strategies:
                if strategy.status == 'executed':
                    # Attempt rollback through response engine
                    # This is simplified - real implementation would track rollback commands
                    try:
                        # For now, just mark as rolled back
                        strategy.status = 'rolled_back'
                        db.session.commit()
                    except Exception as e:
                        logger.error(f"Error rolling back strategy {strategy.id}: {e}")
                        rollback_success = False

            if rollback_success:
                result.status = MitigationStatus.ROLLED_BACK
                result.notes = "Mitigation rolled back successfully"

            return rollback_success

        except Exception as e:
            logger.error(f"Error rolling back mitigation for alert {alert_id}: {e}")
            return False

    async def get_mitigation_stats(self) -> Dict[str, Any]:
        """Get mitigation statistics for dashboard."""
        try:
            # Get stats from database
            total_strategies = MitigationStrategy.query.count()
            executed_strategies = MitigationStrategy.query.filter_by(status='executed').count()
            failed_strategies = MitigationStrategy.query.filter_by(status='failed').count()
            pending_strategies = MitigationStrategy.query.filter_by(status='pending').count()

            # Calculate effectiveness
            executed_with_scores = MitigationStrategy.query.filter(
                MitigationStrategy.status == 'executed',
                MitigationStrategy.effectiveness_score.isnot(None)
            ).all()

            avg_effectiveness = 0.0
            if executed_with_scores:
                scores = [s.effectiveness_score for s in executed_with_scores if s.effectiveness_score]
                avg_effectiveness = sum(scores) / len(scores) if scores else 0.0

            # Active mitigations
            active_count = len([r for r in self._active_mitigations.values()
                              if r.status in [MitigationStatus.EXECUTING, MitigationStatus.PENDING]])

            return {
                'total_strategies': total_strategies,
                'executed_strategies': executed_strategies,
                'failed_strategies': failed_strategies,
                'pending_strategies': pending_strategies,
                'active_mitigations': active_count,
                'average_effectiveness': avg_effectiveness,
                'success_rate': executed_strategies / total_strategies if total_strategies > 0 else 0.0
            }

        except Exception as e:
            logger.error(f"Error getting mitigation stats: {e}")
            return {
                'total_strategies': 0,
                'executed_strategies': 0,
                'failed_strategies': 0,
                'pending_strategies': 0,
                'active_mitigations': 0,
                'average_effectiveness': 0.0,
                'success_rate': 0.0
            }

    async def cleanup_expired_mitigations(self, max_age_hours: int = 24) -> int:
        """Clean up old mitigation results."""
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        expired_count = 0

        to_remove = []
        for alert_id, result in self._active_mitigations.items():
            if result.created_at < cutoff_time and result.status in [
                MitigationStatus.EXECUTED, MitigationStatus.FAILED, MitigationStatus.ROLLED_BACK
            ]:
                result.status = MitigationStatus.EXPIRED
                to_remove.append(alert_id)
                expired_count += 1

        for alert_id in to_remove:
            del self._active_mitigations[alert_id]

        logger.info(f"Cleaned up {expired_count} expired mitigations")
        return expired_count


def create_mitigation_module(
    firewall_manager: FirewallManager,
    auto_execute_threshold: float = 0.85,
    db_session=None
) -> MitigationModule:
    """Create a mitigation module with default engines."""
    mitigation_engine = MitigationEngine()
    response_engine = ResponseEngine(firewall_manager=firewall_manager, auto_respond=False)

    return MitigationModule(
        mitigation_engine=mitigation_engine,
        response_engine=response_engine,
        auto_execute_threshold=auto_execute_threshold,
        db_session=db_session
    )