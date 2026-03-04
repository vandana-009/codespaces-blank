"""
Mitigation Routes
=================
API endpoints for mitigation management and dashboard integration.
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required
from datetime import datetime, timedelta
import json

from app import db
from app.models.database import Alert, MitigationStrategy
from mitigation.mitigation_module import MitigationModule, MitigationStatus

mitigation_bp = Blueprint('mitigation', __name__)


@mitigation_bp.route('/dashboard')
@login_required
def mitigation_dashboard():
    """Mitigation dashboard view."""
    return render_template('mitigation_dashboard.html')


@mitigation_bp.route('/api/mitigation/stats')
@login_required
def get_mitigation_stats():
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
            scores = [s.effectiveness_score for s in executed_with_scores if s.effectiveness_score is not None]
            avg_effectiveness = sum(scores) / len(scores) if scores else 0.0

        # Recent mitigations
        recent_mitigations = MitigationStrategy.query.order_by(
            MitigationStrategy.created_at.desc()
        ).limit(10).all()

        recent_data = []
        for m in recent_mitigations:
            recent_data.append({
                'id': m.id,
                'alert_id': m.alert_id,
                'attack_type': m.attack_type,
                'action_type': m.action_type,
                'target': m.target,
                'status': m.status,
                'severity_level': m.severity_level,
                'created_at': m.created_at.isoformat() if m.created_at else None,
                'executed_at': m.executed_at.isoformat() if m.executed_at else None,
                'effectiveness_score': m.effectiveness_score
            })

        # Mitigation by attack type
        attack_type_stats = db.session.query(
            MitigationStrategy.attack_type,
            db.func.count(MitigationStrategy.id).label('count')
        ).group_by(MitigationStrategy.attack_type).all()

        attack_data = [{'attack_type': at, 'count': count} for at, count in attack_type_stats]

        # Status distribution
        status_stats = db.session.query(
            MitigationStrategy.status,
            db.func.count(MitigationStrategy.id).label('count')
        ).group_by(MitigationStrategy.status).all()

        status_data = [{'status': status, 'count': count} for status, count in status_stats]

        return jsonify({
            'stats': {
                'total_strategies': total_strategies,
                'executed_strategies': executed_strategies,
                'failed_strategies': failed_strategies,
                'pending_strategies': pending_strategies,
                'average_effectiveness': round(avg_effectiveness, 2),
                'success_rate': round(executed_strategies / total_strategies, 2) if total_strategies > 0 else 0.0
            },
            'recent_mitigations': recent_data,
            'attack_type_distribution': attack_data,
            'status_distribution': status_data
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@mitigation_bp.route('/api/mitigation/alert/<int:alert_id>')
@login_required
def get_mitigation_for_alert(alert_id):
    """Get mitigation strategies for a specific alert."""
    try:
        strategies = MitigationStrategy.query.filter_by(alert_id=alert_id).all()

        data = []
        for strategy in strategies:
            data.append({
                'id': strategy.id,
                'attack_type': strategy.attack_type,
                'severity_level': strategy.severity_level,
                'action_type': strategy.action_type,
                'target': strategy.target,
                'description': strategy.description,
                'priority': strategy.priority,
                'status': strategy.status,
                'is_automated': strategy.is_automated,
                'effectiveness_score': strategy.effectiveness_score,
                'created_at': strategy.created_at.isoformat() if strategy.created_at else None,
                'executed_at': strategy.executed_at.isoformat() if strategy.executed_at else None,
                'execution_result': strategy.execution_result,
                'notes': strategy.notes
            })

        return jsonify({'strategies': data})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@mitigation_bp.route('/api/mitigation/strategy/<int:strategy_id>/execute', methods=['POST'])
@login_required
def execute_mitigation_strategy(strategy_id):
    """Manually execute a mitigation strategy."""
    try:
        strategy = MitigationStrategy.query.get_or_404(strategy_id)

        if strategy.status != 'pending':
            return jsonify({'error': 'Strategy is not in pending status'}), 400

        # Mark as executed (simplified - in real implementation would call mitigation module)
        strategy.status = 'executed'
        strategy.executed_at = datetime.utcnow()
        strategy.execution_result = 'Manually executed via API'

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Mitigation strategy executed successfully'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@mitigation_bp.route('/api/mitigation/strategy/<int:strategy_id>/rollback', methods=['POST'])
@login_required
def rollback_mitigation_strategy(strategy_id):
    """Rollback a mitigation strategy."""
    try:
        strategy = MitigationStrategy.query.get_or_404(strategy_id)

        if strategy.status != 'executed':
            return jsonify({'error': 'Strategy is not in executed status'}), 400

        # Mark as rolled back
        strategy.status = 'rolled_back'
        strategy.notes = 'Rolled back via API'

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Mitigation strategy rolled back successfully'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@mitigation_bp.route('/api/mitigation/effectiveness')
@login_required
def get_mitigation_effectiveness():
    """Get mitigation effectiveness over time."""
    try:
        # Get effectiveness data for the last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)

        effectiveness_data = db.session.query(
            db.func.date(MitigationStrategy.executed_at).label('date'),
            db.func.avg(MitigationStrategy.effectiveness_score).label('avg_effectiveness'),
            db.func.count(MitigationStrategy.id).label('count')
        ).filter(
            MitigationStrategy.executed_at >= thirty_days_ago,
            MitigationStrategy.effectiveness_score.isnot(None)
        ).group_by(db.func.date(MitigationStrategy.executed_at)).all()

        data = []
        for date, avg_effectiveness, count in effectiveness_data:
            data.append({
                'date': date.isoformat() if date else None,
                'effectiveness': round(avg_effectiveness, 2) if avg_effectiveness else 0.0,
                'count': count
            })

        return jsonify({'effectiveness_over_time': data})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@mitigation_bp.route('/api/mitigation/active')
@login_required
def get_active_mitigations():
    """Get currently active mitigations."""
    try:
        # Get pending and executing strategies
        active_strategies = MitigationStrategy.query.filter(
            MitigationStrategy.status.in_(['pending', 'executing'])
        ).order_by(MitigationStrategy.created_at.desc()).all()

        data = []
        for strategy in active_strategies:
            alert = Alert.query.get(strategy.alert_id)
            data.append({
                'id': strategy.id,
                'alert_id': strategy.alert_id,
                'attack_type': strategy.attack_type,
                'severity_level': strategy.severity_level,
                'action_type': strategy.action_type,
                'target': strategy.target,
                'description': strategy.description,
                'status': strategy.status,
                'created_at': strategy.created_at.isoformat() if strategy.created_at else None,
                'alert_info': {
                    'source_ip': alert.source_ip if alert else None,
                    'confidence': alert.confidence if alert else None
                }
            })

        return jsonify({'active_mitigations': data})

    except Exception as e:
        return jsonify({'error': str(e)}), 500