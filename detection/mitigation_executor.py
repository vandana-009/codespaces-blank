"""
Mitigation Executor for AI-NIDS
================================
Executes mitigation strategies with advisory mode by default.
Handles approval workflows and automated execution when enabled.

Author: AI-NIDS Team
"""

import logging
from typing import Dict, List, Optional, Callable, Tuple
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading
import queue
import subprocess
import shlex
import time
import json

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """Execution modes for mitigations."""
    ADVISORY = "advisory"      # Only log and notify, no execution
    APPROVAL_REQUIRED = "approval_required"  # Require manual approval
    AUTOMATED = "automated"    # Execute automatically based on thresholds


class ExecutionStatus(Enum):
    """Status of mitigation execution."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ExecutionResult:
    """Result of a mitigation execution."""
    step_id: str
    status: ExecutionStatus
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    output: Optional[str] = None
    error: Optional[str] = None
    rollback_output: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'step_id': self.step_id,
            'status': self.status.value,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'output': self.output,
            'error': self.error,
            'rollback_output': self.rollback_output
        }


@dataclass
class MitigationExecution:
    """Tracks the execution of a mitigation strategy."""
    execution_id: str
    alert_id: int
    strategy: 'MitigationStrategy'  # Forward reference
    mode: ExecutionMode
    status: ExecutionStatus = ExecutionStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    results: List[ExecutionResult] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'execution_id': self.execution_id,
            'alert_id': self.alert_id,
            'strategy': self.strategy.to_dict(),
            'mode': self.mode.value,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'approved_by': self.approved_by,
            'results': [r.to_dict() for r in self.results]
        }


class MitigationExecutor:
    """
    Executes mitigation strategies with configurable automation levels.
    Supports advisory mode, approval workflows, and automated execution.
    """
    
    def __init__(
        self,
        execution_mode: ExecutionMode = ExecutionMode.ADVISORY,
        auto_approval_threshold: float = 0.95,
        enable_notifications: bool = True,
        notification_callback: Optional[Callable] = None
    ):
        """
        Initialize mitigation executor.
        
        Args:
            execution_mode: Default execution mode
            auto_approval_threshold: Confidence threshold for auto-approval
            enable_notifications: Whether to send notifications
            notification_callback: Callback for notifications
        """
        self.execution_mode = execution_mode
        self.auto_approval_threshold = auto_approval_threshold
        self.enable_notifications = enable_notifications
        self.notification_callback = notification_callback
        
        self.logger = logging.getLogger(__name__)
        
        # Execution tracking
        self.executions: Dict[str, MitigationExecution] = {}
        self.execution_queue = queue.Queue()
        
        # Start execution worker
        self.worker_thread = threading.Thread(target=self._execution_worker, daemon=True)
        self.worker_thread.start()
        
        # Rollback commands mapping
        self.rollback_commands = {
            'iptables -I INPUT -s': 'iptables -D INPUT -s',
            'tc qdisc add': 'tc qdisc del',
            'virsh suspend': 'virsh resume',
            'vlan config add': 'vlan config remove'
        }
    
    def execute_strategy(
        self,
        alert_id: int,
        strategy: 'MitigationStrategy',
        confidence: float,
        requester: Optional[str] = None
    ) -> str:
        """
        Submit a mitigation strategy for execution.
        
        Args:
            alert_id: Alert ID
            strategy: Mitigation strategy to execute
            confidence: Detection confidence
            requester: User/system requesting execution
            
        Returns:
            Execution ID for tracking
        """
        execution_id = f"exec_{alert_id}_{int(datetime.utcnow().timestamp())}"
        
        # Determine execution mode based on confidence and settings
        if self.execution_mode == ExecutionMode.AUTOMATED and confidence >= self.auto_approval_threshold:
            mode = ExecutionMode.AUTOMATED
            status = ExecutionStatus.APPROVED
        elif self.execution_mode == ExecutionMode.APPROVAL_REQUIRED:
            mode = ExecutionMode.APPROVAL_REQUIRED
            status = ExecutionStatus.PENDING
        else:
            mode = ExecutionMode.ADVISORY
            status = ExecutionStatus.PENDING
        
        execution = MitigationExecution(
            execution_id=execution_id,
            alert_id=alert_id,
            strategy=strategy,
            mode=mode,
            status=status
        )
        
        self.executions[execution_id] = execution
        
        # Auto-approve if threshold met
        if mode == ExecutionMode.AUTOMATED:
            execution.approved_at = datetime.utcnow()
            execution.approved_by = "auto_approval"
            self._queue_execution(execution)
        
        # Send notification
        if self.enable_notifications and self.notification_callback:
            self.notification_callback(
                execution_id=execution_id,
                alert_id=alert_id,
                mode=mode.value,
                status=status.value,
                strategy=strategy
            )
        
        self.logger.info(f"Submitted mitigation strategy {execution_id} for alert {alert_id} in {mode.value} mode")
        return execution_id
    
    def approve_execution(
        self,
        execution_id: str,
        approver: str
    ) -> bool:
        """
        Approve a pending mitigation execution.
        
        Args:
            execution_id: Execution ID to approve
            approver: User approving the execution
            
        Returns:
            True if approved, False if not found or not pending
        """
        if execution_id not in self.executions:
            return False
        
        execution = self.executions[execution_id]
        if execution.status != ExecutionStatus.PENDING:
            return False
        
        execution.status = ExecutionStatus.APPROVED
        execution.approved_at = datetime.utcnow()
        execution.approved_by = approver
        
        self._queue_execution(execution)
        
        self.logger.info(f"Approved mitigation execution {execution_id} by {approver}")
        return True
    
    def reject_execution(
        self,
        execution_id: str,
        rejector: str,
        reason: Optional[str] = None
    ) -> bool:
        """
        Reject a pending mitigation execution.
        
        Args:
            execution_id: Execution ID to reject
            rejector: User rejecting the execution
            reason: Reason for rejection
            
        Returns:
            True if rejected, False if not found or not pending
        """
        if execution_id not in self.executions:
            return False
        
        execution = self.executions[execution_id]
        if execution.status != ExecutionStatus.PENDING:
            return False
        
        execution.status = ExecutionStatus.REJECTED
        
        # Add rejection note
        if reason:
            execution.strategy.context['rejection_reason'] = reason
            execution.strategy.context['rejected_by'] = rejector
            execution.strategy.context['rejected_at'] = datetime.utcnow().isoformat()
        
        self.logger.info(f"Rejected mitigation execution {execution_id} by {rejector}: {reason}")
        return True
    
    def rollback_execution(
        self,
        execution_id: str,
        rollbacker: str
    ) -> bool:
        """
        Rollback a completed mitigation execution.
        
        Args:
            execution_id: Execution ID to rollback
            rollbacker: User requesting rollback
            
        Returns:
            True if rollback initiated, False otherwise
        """
        if execution_id not in self.executions:
            return False
        
        execution = self.executions[execution_id]
        if execution.status not in [ExecutionStatus.SUCCESS, ExecutionStatus.FAILED]:
            return False
        
        # Queue rollback for successful steps
        rollback_tasks = []
        for result in execution.results:
            if result.status == ExecutionStatus.SUCCESS and result.output:
                rollback_cmd = self._get_rollback_command(result.output)
                if rollback_cmd:
                    rollback_tasks.append((result.step_id, rollback_cmd))
        
        if rollback_tasks:
            threading.Thread(
                target=self._execute_rollback,
                args=(execution, rollback_tasks, rollbacker),
                daemon=True
            ).start()
        
        self.logger.info(f"Initiated rollback for execution {execution_id} by {rollbacker}")
        return True
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict]:
        """Get the status of a mitigation execution."""
        execution = self.executions.get(execution_id)
        return execution.to_dict() if execution else None
    
    def _queue_execution(self, execution: MitigationExecution):
        """Queue execution for processing."""
        self.execution_queue.put(execution)
    
    def _execution_worker(self):
        """Worker thread for executing mitigations."""
        while True:
            try:
                execution = self.execution_queue.get(timeout=1)
                self._execute_mitigation_strategy(execution)
                self.execution_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in execution worker: {e}")
    
    def _execute_mitigation_strategy(self, execution: MitigationExecution):
        """Execute all steps in a mitigation strategy.
        Advisory mode: log and notify only.
        Executable mode: run mitigation commands.
        """
        execution.status = ExecutionStatus.EXECUTING
        for step in execution.strategy.steps:
            if execution.mode == ExecutionMode.ADVISORY or step.requires_approval:
                # Advisory mode: just log and notify
                result = ExecutionResult(
                    step_id=f"{execution.execution_id}_{step.action.value}",
                    status=ExecutionStatus.SUCCESS,
                    executed_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                    output=f"ADVISORY: {step.description}"
                )
            else:
                # Executable mode: run mitigation command
                result = self._execute_mitigation_step(step, execution.execution_id)
            execution.results.append(result)
        # Update overall status
        if all(r.status == ExecutionStatus.SUCCESS for r in execution.results):
            execution.status = ExecutionStatus.SUCCESS
        elif any(r.status == ExecutionStatus.FAILED for r in execution.results):
            execution.status = ExecutionStatus.FAILED
        else:
            execution.status = ExecutionStatus.SUCCESS  # Advisory mode
    
    def _execute_mitigation_step(self, step: 'MitigationStep', execution_id: str) -> ExecutionResult:
        """Execute a single mitigation step."""
        step_id = f"{execution_id}_{step.action.value}"
        result = ExecutionResult(
            step_id=step_id,
            status=ExecutionStatus.EXECUTING,
            executed_at=datetime.utcnow()
        )
        
        try:
            if not step.command:
                # No command to execute
                result.output = f"No command available for {step.action.value}"
                result.status = ExecutionStatus.SUCCESS
            else:
                # Execute command
                self.logger.info(f"Executing mitigation: {step.command}")
                
                # Use subprocess with timeout
                process = subprocess.run(
                    shlex.split(step.command),
                    capture_output=True,
                    text=True,
                    timeout=30  # 30 second timeout
                )
                
                result.output = process.stdout
                if process.stderr:
                    result.output += f"\nSTDERR: {process.stderr}"
                
                if process.returncode == 0:
                    result.status = ExecutionStatus.SUCCESS
                    self.logger.info(f"Successfully executed mitigation: {step.action.value}")
                else:
                    result.status = ExecutionStatus.FAILED
                    result.error = f"Command failed with return code {process.returncode}"
                    self.logger.error(f"Failed to execute mitigation {step.action.value}: {result.error}")
        
        except subprocess.TimeoutExpired:
            result.status = ExecutionStatus.FAILED
            result.error = "Command execution timed out"
            self.logger.error(f"Mitigation execution timed out: {step.action.value}")
        except Exception as e:
            result.status = ExecutionStatus.FAILED
            result.error = str(e)
            self.logger.error(f"Error executing mitigation {step.action.value}: {e}")
        
        result.completed_at = datetime.utcnow()
        return result
    
    def _execute_rollback(self, execution: MitigationExecution, rollback_tasks: List[Tuple[str, str]], rollbacker: str):
        """Execute rollback commands."""
        execution.status = ExecutionStatus.ROLLED_BACK
        
        for step_id, rollback_cmd in rollback_tasks:
            try:
                self.logger.info(f"Executing rollback: {rollback_cmd}")
                
                process = subprocess.run(
                    shlex.split(rollback_cmd),
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Find the corresponding result and update
                for result in execution.results:
                    if result.step_id == step_id:
                        result.rollback_output = process.stdout
                        if process.stderr:
                            result.rollback_output += f"\nSTDERR: {process.stderr}"
                        break
                
                if process.returncode == 0:
                    self.logger.info(f"Successfully rolled back: {rollback_cmd}")
                else:
                    self.logger.error(f"Failed to rollback: {rollback_cmd}")
            
            except Exception as e:
                self.logger.error(f"Error during rollback: {e}")
    
    def _get_rollback_command(self, original_output: str) -> Optional[str]:
        """Generate rollback command from original command output."""
        # Simple rollback command generation based on original command
        for trigger, rollback_prefix in self.rollback_commands.items():
            if trigger in original_output:
                # Extract target from original command
                parts = original_output.split()
                if len(parts) > 1:
                    target = parts[-1]  # Assume target is last part
                    return f"{rollback_prefix} {target}"
        
        return None