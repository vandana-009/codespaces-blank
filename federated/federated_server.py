"""
Federated Server - Central Aggregation Coordinator
===================================================
The brain of the federated learning system:
1. Coordinates training rounds across all clients
2. Aggregates model updates using FedAvg or advanced methods
3. Maintains global model state
4. Handles client selection and scheduling

This is how 1,000 networks become 1 unified defense system.
"""

import torch
import torch.nn as nn
from typing import Dict, List, Tuple, Optional, Any, Callable
import numpy as np
from dataclasses import dataclass, field
from collections import OrderedDict, defaultdict
import logging
import threading
import queue
import time
from datetime import datetime, timedelta
import json
import hashlib
import copy
from enum import Enum

# async/io for streaming
import asyncio
import ssl
try:
    import websockets
except ImportError:
    websockets = None  # streaming features will not be available without the package

logger = logging.getLogger(__name__)

# global instance reference for CLI and other modules
GLOBAL_SERVER: Optional['FederatedServer'] = None

def get_global_server() -> Optional['FederatedServer']:
    """Return the globally-created FederatedServer instance, if any."""
    return GLOBAL_SERVER


class AggregationStrategy(Enum):
    """Available aggregation strategies."""
    FEDAVG = "fedavg"           # Federated Averaging (standard)
    FEDPROX = "fedprox"         # Proximal term for heterogeneous data
    FEDOPT = "fedopt"           # Server-side optimization
    SCAFFOLD = "scaffold"       # Variance reduction
    WEIGHTED = "weighted"       # Sample-weighted averaging


@dataclass
class ServerConfig:
    """Configuration for the federated server."""
    server_id: str = "fed-server-001"
    
    # Round configuration
    min_clients_per_round: int = 3
    max_clients_per_round: int = 100
    round_timeout: int = 300  # seconds
    
    # Aggregation config
    aggregation_strategy: AggregationStrategy = AggregationStrategy.FEDAVG
    fedprox_mu: float = 0.01  # Proximal term coefficient
    
    # Model versioning
    model_save_frequency: int = 10  # Save every N rounds
    max_model_versions: int = 10
    
    # Client selection
    client_selection: str = "random"  # random, weighted, active
    selection_fraction: float = 0.3  # Fraction of clients per round
    
    # Security
    require_minimum_samples: int = 100
    require_fresh_data: bool = True
    max_staleness_rounds: int = 5


@dataclass
class ClientInfo:
    """Information about a registered client."""
    client_id: str
    organization: str
    subnet: str
    
    # Registration info
    registered_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    # Participation stats
    rounds_participated: int = 0
    total_samples_contributed: int = 0
    last_contribution: Optional[datetime] = None
    
    # Performance stats
    avg_loss: float = 0.0
    avg_accuracy: float = 0.0
    avg_training_time: float = 0.0
    
    # Reliability score (for client selection)
    reliability_score: float = 1.0
    
    def update_from_metrics(self, metrics: Dict):
        """Update client info from training metrics."""
        self.last_seen = datetime.now()
        self.rounds_participated += 1
        self.total_samples_contributed += metrics.get('samples', 0)
        self.last_contribution = datetime.now()
        
        # Exponential moving average
        alpha = 0.3
        self.avg_loss = alpha * metrics.get('loss', 0) + (1 - alpha) * self.avg_loss
        self.avg_accuracy = alpha * metrics.get('accuracy', 0) + (1 - alpha) * self.avg_accuracy
        self.avg_training_time = alpha * metrics.get('time', 0) + (1 - alpha) * self.avg_training_time


@dataclass
class RoundInfo:
    """Information about a federated learning round."""
    round_number: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Participants
    selected_clients: List[str] = field(default_factory=list)
    participating_clients: List[str] = field(default_factory=list)
    
    # Aggregation results
    total_samples: int = 0
    avg_loss: float = 0.0
    avg_accuracy: float = 0.0
    
    # Model info
    model_version: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'round': self.round_number,
            'started': self.started_at.isoformat(),
            'completed': self.completed_at.isoformat() if self.completed_at else None,
            'selected': len(self.selected_clients),
            'participated': len(self.participating_clients),
            'samples': self.total_samples,
            'loss': self.avg_loss,
            'accuracy': self.avg_accuracy,
            'model_version': self.model_version
        }


class ModelAggregator:
    """
    Aggregates model updates from multiple clients.
    Implements various federated aggregation algorithms.
    """
    
    def __init__(self, strategy: AggregationStrategy = AggregationStrategy.FEDAVG):
        self.strategy = strategy
        
        # For FedOpt (server optimizer)
        self.server_optimizer = None
        self.server_momentum: Dict[str, torch.Tensor] = {}
        
        # For SCAFFOLD (control variates)
        self.control_variates: Dict[str, Dict[str, torch.Tensor]] = {}
        self.global_control: Dict[str, torch.Tensor] = {}
    
    def aggregate(
        self,
        global_model: Dict[str, torch.Tensor],
        client_updates: List[Dict[str, torch.Tensor]],
        client_weights: List[float],
        fedprox_mu: float = 0.01
    ) -> Dict[str, torch.Tensor]:
        """
        Aggregate client updates into global model.
        
        Args:
            global_model: Current global model state
            client_updates: List of client gradient updates
            client_weights: Weight for each client (typically num_samples)
            fedprox_mu: Proximal term for FedProx
            
        Returns:
            Updated global model state
        """
        if self.strategy == AggregationStrategy.FEDAVG:
            return self._fedavg(global_model, client_updates, client_weights)
        elif self.strategy == AggregationStrategy.FEDPROX:
            return self._fedprox(global_model, client_updates, client_weights, fedprox_mu)
        elif self.strategy == AggregationStrategy.FEDOPT:
            return self._fedopt(global_model, client_updates, client_weights)
        elif self.strategy == AggregationStrategy.WEIGHTED:
            return self._weighted_average(global_model, client_updates, client_weights)
        else:
            return self._fedavg(global_model, client_updates, client_weights)
    
    def _fedavg(
        self,
        global_model: Dict[str, torch.Tensor],
        client_updates: List[Dict[str, torch.Tensor]],
        client_weights: List[float]
    ) -> Dict[str, torch.Tensor]:
        """
        Federated Averaging (McMahan et al., 2017).
        The foundational algorithm for federated learning.
        """
        if not client_updates:
            return global_model
        
        # Normalize weights
        total_weight = sum(client_weights)
        normalized_weights = [w / total_weight for w in client_weights]
        
        # Average the updates
        aggregated = {}
        for key in global_model.keys():
            aggregated[key] = torch.zeros_like(global_model[key])
            
            for update, weight in zip(client_updates, normalized_weights):
                if key in update:
                    aggregated[key] += weight * update[key]
        
        # Apply updates to global model
        new_model = {}
        for key in global_model.keys():
            new_model[key] = global_model[key] + aggregated[key]
        
        return new_model
    
    def _fedprox(
        self,
        global_model: Dict[str, torch.Tensor],
        client_updates: List[Dict[str, torch.Tensor]],
        client_weights: List[float],
        mu: float
    ) -> Dict[str, torch.Tensor]:
        """
        FedProx: Adds proximal term to handle heterogeneous data.
        """
        # FedProx mainly affects client training, aggregation is similar to FedAvg
        return self._fedavg(global_model, client_updates, client_weights)
    
    def _fedopt(
        self,
        global_model: Dict[str, torch.Tensor],
        client_updates: List[Dict[str, torch.Tensor]],
        client_weights: List[float],
        server_lr: float = 1.0,
        momentum: float = 0.9
    ) -> Dict[str, torch.Tensor]:
        """
        FedOpt: Server-side optimization with momentum.
        """
        if not client_updates:
            return global_model
        
        # Compute pseudo-gradient (average of client updates)
        total_weight = sum(client_weights)
        normalized_weights = [w / total_weight for w in client_weights]
        
        pseudo_gradient = {}
        for key in global_model.keys():
            pseudo_gradient[key] = torch.zeros_like(global_model[key])
            
            for update, weight in zip(client_updates, normalized_weights):
                if key in update:
                    pseudo_gradient[key] += weight * update[key]
        
        # Apply server momentum
        new_model = {}
        for key in global_model.keys():
            if key not in self.server_momentum:
                self.server_momentum[key] = torch.zeros_like(global_model[key])
            
            # Momentum update
            self.server_momentum[key] = (
                momentum * self.server_momentum[key] +
                pseudo_gradient[key]
            )
            
            # Apply to model
            new_model[key] = global_model[key] + server_lr * self.server_momentum[key]
        
        return new_model
    
    def _weighted_average(
        self,
        global_model: Dict[str, torch.Tensor],
        client_updates: List[Dict[str, torch.Tensor]],
        client_weights: List[float]
    ) -> Dict[str, torch.Tensor]:
        """Simple weighted average based on sample counts."""
        return self._fedavg(global_model, client_updates, client_weights)


class FederatedServer:
    """
    Complete federated learning server.
    Coordinates clients, manages rounds, aggregates models.
    """
    
    def __init__(
        self,
        initial_model: nn.Module,
        config: Optional[ServerConfig] = None,
        device: str = 'cpu'
    ):
        self.config = config or ServerConfig()
        self.device = device
        
        # Global model
        self.global_model = copy.deepcopy(initial_model).to(device)
        self.global_model_state = copy.deepcopy(self.global_model.state_dict())
        
        # Aggregator (round-based)
        self.aggregator = ModelAggregator(self.config.aggregation_strategy)
        
        # Optional secure/incremental aggregator (for streaming)
        self.secure_aggregator = None  # type: Optional[SecureAggregator]
        
        # Client registry
        self.clients: Dict[str, ClientInfo] = {}
        
        # Round management
        self.current_round = 0
        self.round_history: List[RoundInfo] = []
        
        # Update buffer for current round
        self.round_updates: List[Tuple[str, Dict[str, torch.Tensor], Dict]] = []
        
        # Model versioning (also used for checkpoints when streaming)
        self.model_versions: List[Dict] = []
        
        # Thread safety
        self._lock = threading.RLock()

        # Streaming websocket state
        self.ws_clients = set()
        self.ws_ssl_context = None
        self._ws_host = None
        self._ws_port = None
        
        logger.info(f"Federated server initialized: {self.config.server_id}")
    
    def register_client(
        self,
        client_id: str,
        organization: str = "unknown",
        subnet: str = "0.0.0.0/0",
        metadata: Optional[Dict] = None
    ) -> bool:
        """Register a new client with the server."""
        with self._lock:
            if client_id in self.clients:
                # Update last seen
                self.clients[client_id].last_seen = datetime.now()
                return True
            
            self.clients[client_id] = ClientInfo(
                client_id=client_id,
                organization=organization,
                subnet=subnet
            )
            
            logger.info(f"Registered client: {client_id} from {organization}")
            
            # Notify dashboard of client connection
            try:
                from .metrics_bridge import notify_client_connected
                notify_client_connected(client_id, organization, subnet)
            except ImportError:
                pass
            
            return True
    
    def unregister_client(self, client_id: str):
        """Unregister a client from the server."""
        with self._lock:
            if client_id in self.clients:
                del self.clients[client_id]
                logger.info(f"Unregistered client: {client_id}")
    
    def get_global_model(self) -> Dict[str, torch.Tensor]:
        """Get current global model state for clients."""
        with self._lock:
            return copy.deepcopy(self.global_model_state)

    # ------------------------------------------------------------------
    # Secure/incremental aggregation helpers
    # ------------------------------------------------------------------
    def set_secure_aggregator(self, aggregator) -> None:
        """Attach a SecureAggregator instance for streaming updates.

        The server will call :meth:`initialize_global_model` on the
        aggregator so that it is aware of the current state.
        """
        self.secure_aggregator = aggregator
        if hasattr(aggregator, 'initialize_global_model'):
            aggregator.initialize_global_model(self.global_model_state)

    def incremental_update(
        self,
        client_id: str,
        gradients: Dict[str, torch.Tensor],
        num_samples: int
    ) -> Dict[str, Any]:
        """Apply a single update from a client in streaming mode.

        The operation will either use the attached secure_aggregator if one
        is available (preferred for privacy and checkpoints) or fall back to
        a simple additive update.  Returns metadata including new model hash
        and any information supplied by the aggregator.
        """
        with self._lock:
            if self.secure_aggregator:
                # perform privacy-preserving incremental update
                new_state, metadata = self.secure_aggregator.incremental_aggregate(
                    client_id,
                    gradients,
                    num_samples
                )
                self.global_model_state = new_state
                self.global_model.load_state_dict(new_state)
                # save version as part of server bookkeeping
                self._save_model_version()
                logger.info(f"Incremental update applied from {client_id}: {metadata}")
                return metadata
            else:
                # fallback additive update
                for name, grad in gradients.items():
                    if name in self.global_model_state:
                        self.global_model_state[name] += grad
                self.global_model.load_state_dict(self.global_model_state)
                self._save_model_version()
                new_hash = self._compute_model_hash()
                logger.info(f"Incremental additive update from {client_id}, new_hash={new_hash}")
                return {'client_id': client_id, 'new_hash': new_hash}

    # ------------------------------------------------------------------
    # WebSocket streaming support
    # ------------------------------------------------------------------
    async def _ws_handler(self, websocket, path):
        """Handle an individual websocket connection from a client."""
        self.ws_clients.add(websocket)
        client_id = None
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                except Exception:
                    logger.warning("Received invalid JSON over websocket")
                    continue

                msg_type = data.get('type')
                if msg_type == 'register':
                    client_id = data.get('client_id')
                    self.register_client(
                        client_id,
                        organization=data.get('organization', 'unknown'),
                        subnet=data.get('subnet', '0.0.0.0/0')
                    )
                    # echo registration and current model hash
                    await websocket.send(json.dumps({
                        'type': 'registered',
                        'model_hash': self._compute_model_hash()
                    }))
                elif msg_type == 'update':
                    client_id = data.get('client_id')
                    # gradients serialized as lists; convert back to tensors
                    gradients = {
                        k: torch.tensor(v)
                        for k, v in data.get('gradients', {}).items()
                    }
                    num_samples = data.get('samples', 1)
                    metadata = self.incremental_update(client_id, gradients, num_samples)
                    # broadcast update to all clients
                    # include a timestamp so clients can compute latency
                    metadata['timestamp'] = datetime.utcnow().isoformat()
                    await self._broadcast({
                        'type': 'model_update',
                        'model_hash': metadata.get('new_hash'),
                        'metadata': metadata
                    })
                elif msg_type == 'heartbeat':
                    # simple pass-through for heartbeats if desired
                    pass
                else:
                    logger.debug(f"Unhandled websocket message type: {msg_type}")
        except Exception as e:
            logger.error(f"Websocket handler error: {e}")
        finally:
            self.ws_clients.discard(websocket)

    async def _broadcast(self, message: Dict[str, Any]) -> None:
        """Send a JSON message to all connected websocket clients."""
        if not self.ws_clients:
            return
        msg_text = json.dumps(message)
        await asyncio.gather(*[client.send(msg_text) for client in list(self.ws_clients)])

    def start_streaming_server(
        self,
        host: str = '0.0.0.0',
        port: int = 8765,
        use_tls: bool = False,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None
    ) -> None:
        """Start an asynchronous websocket server for real‑time updates.

        This method spins up a background thread running an asyncio event
        loop; it does not block the caller.
        """
        if websockets is None:
            raise RuntimeError("websockets library is required for streaming mode")

        self._ws_host = host
        self._ws_port = port

        if use_tls:
            self.ws_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if not certfile or not keyfile:
                raise ValueError("certfile and keyfile must be provided for TLS")
            self.ws_ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        def _run_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            start_coro = websockets.serve(
                self._ws_handler,
                host,
                port,
                ssl=self.ws_ssl_context
            )
            server = loop.run_until_complete(start_coro)
            logger.info(f"Websocket streaming server listening on {host}:{port}")
            try:
                loop.run_forever()
            finally:
                server.close()
                loop.run_until_complete(server.wait_closed())
                loop.close()

        thread = threading.Thread(target=_run_loop, daemon=True)
        thread.start()
    
    def select_clients(self, available_clients: Optional[List[str]] = None) -> List[str]:
        """Select clients for the next round."""
        with self._lock:
            if available_clients is None:
                available_clients = list(self.clients.keys())
            
            # Filter to registered clients
            valid_clients = [c for c in available_clients if c in self.clients]
            
            if len(valid_clients) < self.config.min_clients_per_round:
                return []
            
            # Number to select
            num_to_select = min(
                max(
                    self.config.min_clients_per_round,
                    int(len(valid_clients) * self.config.selection_fraction)
                ),
                self.config.max_clients_per_round
            )
            
            if self.config.client_selection == "random":
                selected = list(np.random.choice(
                    valid_clients,
                    size=min(num_to_select, len(valid_clients)),
                    replace=False
                ))
            elif self.config.client_selection == "weighted":
                # Weight by reliability score
                weights = [
                    self.clients[c].reliability_score
                    for c in valid_clients
                ]
                weights = np.array(weights) / sum(weights)
                selected = list(np.random.choice(
                    valid_clients,
                    size=min(num_to_select, len(valid_clients)),
                    replace=False,
                    p=weights
                ))
            else:
                # Active: prefer clients that haven't participated recently
                sorted_clients = sorted(
                    valid_clients,
                    key=lambda c: self.clients[c].rounds_participated
                )
                selected = sorted_clients[:num_to_select]
            
            return selected
    
    def start_round(self) -> RoundInfo:
        """Start a new federated learning round."""
        with self._lock:
            self.current_round += 1
            self.round_updates = []
            
            selected = self.select_clients()
            
            round_info = RoundInfo(
                round_number=self.current_round,
                started_at=datetime.now(),
                selected_clients=selected
            )
            
            logger.info(
                f"Starting round {self.current_round} with "
                f"{len(selected)} selected clients"
            )
            
            return round_info
    
    def submit_update(
        self,
        client_id: str,
        gradients: Dict[str, torch.Tensor],
        metrics: Dict
    ) -> bool:
        """
        Submit a training update from a client.
        
        Args:
            client_id: ID of the submitting client
            gradients: Gradient updates (or model deltas)
            metrics: Training metrics
            
        Returns:
            True if update was accepted
        """
        with self._lock:
            if client_id not in self.clients:
                logger.warning(f"Unknown client attempted update: {client_id}")
                return False
            
            # Validate update
            if metrics.get('samples', 0) < self.config.require_minimum_samples:
                logger.warning(
                    f"Client {client_id} submitted too few samples: "
                    f"{metrics.get('samples', 0)}"
                )
                return False
            
            # Convert to device
            device_gradients = {
                k: v.to(self.device) if isinstance(v, torch.Tensor) else v
                for k, v in gradients.items()
            }
            
            # Add to round buffer
            self.round_updates.append((client_id, device_gradients, metrics))
            
            # Update client info
            self.clients[client_id].update_from_metrics(metrics)
            
            logger.info(
                f"Received update from {client_id}: "
                f"samples={metrics.get('samples', 0)}, "
                f"loss={metrics.get('loss', 0):.4f}"
            )
            
            return True
    
    def aggregate_round(self) -> RoundInfo:
        """
        Aggregate all updates from the current round.
        
        Returns:
            Round information with results
        """
        with self._lock:
            if not self.round_updates:
                logger.warning("No updates to aggregate")
                return RoundInfo(
                    round_number=self.current_round,
                    started_at=datetime.now()
                )
            
            # Extract updates and weights
            client_ids = []
            all_gradients = []
            all_weights = []
            total_samples = 0
            total_loss = 0
            total_acc = 0
            
            for client_id, gradients, metrics in self.round_updates:
                client_ids.append(client_id)
                all_gradients.append(gradients)
                
                samples = metrics.get('samples', 1)
                all_weights.append(samples)
                total_samples += samples
                total_loss += metrics.get('loss', 0) * samples
                total_acc += metrics.get('accuracy', 0) * samples
            
            # Aggregate
            new_model_state = self.aggregator.aggregate(
                self.global_model_state,
                all_gradients,
                all_weights,
                fedprox_mu=self.config.fedprox_mu
            )
            
            # Update global model
            self.global_model_state = new_model_state
            self.global_model.load_state_dict(new_model_state)
            
            # Create round info
            round_info = RoundInfo(
                round_number=self.current_round,
                started_at=datetime.now(),
                completed_at=datetime.now(),
                selected_clients=client_ids,
                participating_clients=client_ids,
                total_samples=total_samples,
                avg_loss=total_loss / max(total_samples, 1),
                avg_accuracy=total_acc / max(total_samples, 1),
                model_version=self._compute_model_hash()
            )
            
            self.round_history.append(round_info)
            
            # Save model if needed
            if self.current_round % self.config.model_save_frequency == 0:
                self._save_model_version()
            
            logger.info(
                f"Round {self.current_round} completed: "
                f"clients={len(client_ids)}, "
                f"samples={total_samples}, "
                f"loss={round_info.avg_loss:.4f}, "
                f"acc={round_info.avg_accuracy:.4f}"
            )
            
            # Notify dashboard of round completion
            try:
                from .metrics_bridge import notify_round_completed
                notify_round_completed(
                    self.current_round,
                    len(client_ids),
                    total_samples,
                    round_info.avg_loss,
                    round_info.avg_accuracy,
                    round_info.model_version
                )
            except ImportError:
                pass
            
            # Clear round buffer
            self.round_updates = []
            
            return round_info
    
    def run_round(
        self,
        client_updates: List[Tuple[str, Dict[str, torch.Tensor], Dict]]
    ) -> RoundInfo:
        """
        Convenience method to run a complete round.
        
        Args:
            client_updates: List of (client_id, gradients, metrics) tuples
            
        Returns:
            Round information with results
        """
        # Start round
        self.start_round()
        
        # Submit all updates
        for client_id, gradients, metrics in client_updates:
            if client_id not in self.clients:
                self.register_client(client_id)
            self.submit_update(client_id, gradients, metrics)
        
        # Aggregate
        return self.aggregate_round()
    
    def _compute_model_hash(self) -> str:
        """Compute hash of current model for versioning."""
        hasher = hashlib.sha256()
        for key, value in sorted(self.global_model_state.items()):
            hasher.update(key.encode())
            hasher.update(value.cpu().numpy().tobytes())
        return hasher.hexdigest()[:16]
    
    def _save_model_version(self):
        """Save current model version."""
        version = {
            'round': self.current_round,
            'timestamp': datetime.now().isoformat(),
            'hash': self._compute_model_hash(),
            'state': copy.deepcopy(self.global_model_state)
        }
        
        self.model_versions.append(version)
        
        # Limit stored versions
        if len(self.model_versions) > self.config.max_model_versions:
            self.model_versions = self.model_versions[-self.config.max_model_versions:]
        
        logger.info(f"Saved model version: round {self.current_round}")
    
    def get_model_version(self, round_number: int) -> Optional[Dict[str, torch.Tensor]]:
        """Get a specific model version by round number."""
        for version in self.model_versions:
            if version['round'] == round_number:
                return version['state']
        return None
    
    def rollback_model(self, target_round: int, rollback_reason: str = "") -> bool:
        """
        Rollback the global model to a previous version.
        
        Args:
            target_round: Round number to rollback to
            rollback_reason: Reason for rollback
            
        Returns:
            True if rollback successful, False otherwise
        """
        with self._lock:
            target_version = self.get_model_version(target_round)
            if not target_version:
                logger.error(f"Cannot rollback: model version for round {target_round} not found")
                return False
            
            # Validate target version exists and is not corrupted
            try:
                # Basic validation - check if state dict has expected keys
                if not target_version:
                    logger.error("Target version state is empty")
                    return False
                
                # Restore the model state
                self.global_model_state = copy.deepcopy(target_version)
                
                # also update any attached secure aggregator
                if self.secure_aggregator and hasattr(self.secure_aggregator, 'rollback'):
                    self.secure_aggregator.rollback(self._compute_model_hash(), reason=rollback_reason)

                # Update current round to reflect rollback
                self.current_round = target_round
                
                # Log the rollback
                logger.warning(f"Model rolled back to round {target_round}. Reason: {rollback_reason}")
                
                # Notify all clients about the rollback
                self._notify_clients_rollback(target_round, rollback_reason)
                
                return True
                
            except Exception as e:
                logger.error(f"Error during model rollback: {e}")
                return False
    
    def _notify_clients_rollback(self, target_round: int, reason: str):
        """Notify clients about model rollback."""
        notification = {
            'type': 'model_rollback',
            'target_round': target_round,
            'reason': reason,
            'timestamp': datetime.now().isoformat(),
            'new_model_hash': self._compute_model_hash()
        }
        
        # Send notification to all connected clients
        for client_id, client in self.clients.items():
            try:
                # This would typically send via the client's communication channel
                # For now, just log it
                logger.info(f"Notified client {client_id} about model rollback to round {target_round}")
            except Exception as e:
                logger.error(f"Failed to notify client {client_id} about rollback: {e}")
    
    def list_model_versions(self) -> List[Dict[str, Any]]:
        """List all available model versions."""
        return [
            {
                'round': v['round'],
                'timestamp': v['timestamp'],
                'hash': v['hash']
            }
            for v in self.model_versions
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics."""
        with self._lock:
            return {
                'server_id': self.config.server_id,
                'current_round': self.current_round,
                'registered_clients': len(self.clients),
                'model_hash': self._compute_model_hash(),
                'aggregation_strategy': self.config.aggregation_strategy.value,
                'total_samples_seen': sum(
                    c.total_samples_contributed for c in self.clients.values()
                ),
                'model_versions_saved': len(self.model_versions),
                'recent_rounds': [
                    r.to_dict() for r in self.round_history[-10:]
                ]
            }
    
    def get_client_stats(self) -> List[Dict[str, Any]]:
        """Get statistics for all clients."""
        with self._lock:
            return [
                {
                    'client_id': c.client_id,
                    'organization': c.organization,
                    'subnet': c.subnet,
                    'rounds_participated': c.rounds_participated,
                    'samples_contributed': c.total_samples_contributed,
                    'avg_loss': c.avg_loss,
                    'avg_accuracy': c.avg_accuracy,
                    'reliability': c.reliability_score,
                    'last_seen': c.last_seen.isoformat()
                }
                for c in self.clients.values()
            ]
    
    def save_state(self, path: str):
        """Save complete server state."""
        with self._lock:
            state = {
                'config': self.config.__dict__,
                'current_round': self.current_round,
                'global_model': self.global_model_state,
                'clients': {
                    k: {
                        'client_id': v.client_id,
                        'organization': v.organization,
                        'subnet': v.subnet,
                        'rounds_participated': v.rounds_participated,
                        'total_samples_contributed': v.total_samples_contributed
                    }
                    for k, v in self.clients.items()
                },
                'round_history': [r.to_dict() for r in self.round_history]
            }
            torch.save(state, path)
            logger.info(f"Saved server state to {path}")
    
    def load_state(self, path: str):
        """Load server state from disk."""
        with self._lock:
            state = torch.load(path, map_location=self.device)
            self.current_round = state['current_round']
            self.global_model_state = state['global_model']
            self.global_model.load_state_dict(self.global_model_state)
            logger.info(f"Loaded server state from {path}")


def create_federated_server(
    model: nn.Module,
    aggregation_strategy: str = "fedavg",
    min_clients: int = 3,
    device: str = 'cpu',
    **kwargs
) -> FederatedServer:
    """
    Factory function to create a federated server.
    
    Args:
        model: Initial model architecture
        aggregation_strategy: "fedavg", "fedprox", "fedopt", "scaffold", or "weighted"
        min_clients: Minimum clients per round
        device: Device to run on
        **kwargs: Additional ServerConfig parameters
        
    Returns:
        Configured FederatedServer
    """
    strategy = AggregationStrategy(aggregation_strategy)
    
    config = ServerConfig(
        aggregation_strategy=strategy,
        min_clients_per_round=min_clients,
        **kwargs
    )
    
    server = FederatedServer(model, config, device)
    global GLOBAL_SERVER
    GLOBAL_SERVER = server
    # Initialize dashboard (either in-process or via HTTP ingest)
    try:
        from .metrics_bridge import initialize_federation_dashboard_metrics
        initialize_federation_dashboard_metrics(server)
    except Exception:
        pass
    return server


if __name__ == "__main__":
    from .federated_client import LocalModel
    
    print("Federated Server Demo")
    print("=" * 50)
    
    # Create server with initial model
    initial_model = LocalModel(input_dim=78, num_classes=10)
    server = create_federated_server(
        initial_model,
        aggregation_strategy="fedavg",
        min_clients=2
    )
    
    print(f"Server ID: {server.config.server_id}")
    print(f"Strategy: {server.config.aggregation_strategy.value}")
    
    # Register some clients
    for i in range(5):
        server.register_client(
            f"client-{i:03d}",
            organization=f"Org-{i}",
            subnet=f"192.168.{i}.0/24"
        )
    
    print(f"Registered clients: {len(server.clients)}")
    
    # Simulate a training round
    global_weights = server.get_global_model()
    
    # Create fake client updates
    client_updates = []
    for i in range(3):
        client_id = f"client-{i:03d}"
        
        # Fake gradients (small random updates) - only for float tensors
        gradients = {
            key: torch.randn_like(value) * 0.01
            for key, value in global_weights.items()
            if value.dtype in (torch.float32, torch.float64)
        }
        
        metrics = {
            'samples': np.random.randint(100, 500),
            'loss': np.random.uniform(0.5, 2.0),
            'accuracy': np.random.uniform(0.6, 0.9),
            'time': np.random.uniform(10, 60)
        }
        
        client_updates.append((client_id, gradients, metrics))
    
    # Run round
    round_info = server.run_round(client_updates)
    
    print(f"\nRound {round_info.round_number} Results:")
    print(f"  Participants: {len(round_info.participating_clients)}")
    print(f"  Total samples: {round_info.total_samples}")
    print(f"  Avg loss: {round_info.avg_loss:.4f}")
    print(f"  Avg accuracy: {round_info.avg_accuracy:.4f}")
    print(f"  Model version: {round_info.model_version}")
    
    # Server stats
    print(f"\nServer Stats:")
    for key, value in server.get_stats().items():
        if key != 'recent_rounds':
            print(f"  {key}: {value}")

    # ------------------------------------------------------------------
    # Demonstrate streaming mode if websockets available
    if websockets is not None:
        print("\nStarting local websocket streaming server for demo...")
        server.start_streaming_server(host='127.0.0.1', port=8765)
        import asyncio
        async def demo_stream():
            # simulate a client connecting and sending an update
            async with websockets.connect('ws://127.0.0.1:8765') as ws:
                await ws.send(json.dumps({'type': 'register', 'client_id': 'demo-client'}))
                greeting = await ws.recv()
                print("Received from server:", greeting)
                # send a small fake update
                await ws.send(json.dumps({
                    'type': 'update',
                    'client_id': 'demo-client',
                    'gradients': {k: v.cpu().tolist() for k,v in global_weights.items()},
                    'samples': 10
                }))
                resp = await ws.recv()
                print("Broadcast from server:", resp)
        try:
            asyncio.get_event_loop().run_until_complete(demo_stream())
        except Exception:
            pass
            print(f"  {key}: {value}")
    
    # Client stats
    print(f"\nClient Stats:")
    for client in server.get_client_stats()[:3]:
        print(f"  {client['client_id']}: {client['samples_contributed']} samples")
    
    print("\n✅ Federated Server ready for distributed coordination!")
