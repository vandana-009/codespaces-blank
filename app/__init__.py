"""
AI-NIDS Flask Application Factory
==================================
Main application package initialization.
"""

import os
import logging
import click
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS

from config import config, Config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

# Configure login manager
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'


def create_app(config_name=None):
    """
    Application factory function.
    
    Args:
        config_name: Configuration name ('development', 'testing', 'production')
    
    Returns:
        Flask application instance
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    # if running as a client node, isolate database per client/port
    client_id = os.environ.get('CLIENT_ID') or os.environ.get('CLIENT_PORT')
    if client_id:
        uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        # skip in-memory testing database
        if uri.startswith('sqlite:///') and ':memory:' not in uri:
            base = uri.rsplit('/', 1)[0]
            new_db = f"{base}/nids_{client_id}.db"
            app.config['SQLALCHEMY_DATABASE_URI'] = new_db
            app.logger.info(f"Using client-specific database: {new_db}")
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Setup logging
    setup_logging(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        from app.models.database import User
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@ainids.local',
                role='admin'
            )
            admin.set_password('admin123')  # Change in production!
            db.session.add(admin)
            db.session.commit()
            app.logger.info('Created default admin user')
        
        # Initialize federated server if not already initialized
        try:
            from federated.federated_server import get_global_server, create_federated_server
            import torch.nn as nn
            
            if get_global_server() is None:
                # Create simple model for federated learning
                model = nn.Sequential(
                    nn.Linear(80, 64),
                    nn.ReLU(),
                    nn.Linear(64, 32),
                    nn.ReLU(),
                    nn.Linear(32, 10)
                )
                
                server = create_federated_server(
                    model=model,
                    aggregation_strategy="fedavg",
                    min_clients=2,
                    device='cpu',
                    auto_start_scheduler=False
                )
                app.logger.info(f'Federated server initialized with ID: {server.config.server_id}')
            else:
                app.logger.info('Federated server already initialized')
        except Exception as e:
            app.logger.warning(f'Could not initialize federated server: {e}')
    
    # Register CLI commands
    register_cli_commands(app)
    
    # Register custom Jinja filters
    register_template_filters(app)
    
    app.logger.info(f'AI-NIDS initialized in {config_name} mode')
    
    # if running as a federated client, start background services
    try:
        from app.services.client_node import start_client_services
        start_client_services(app)
    except Exception as e:
        app.logger.warning(f'Client node service failed to start: {e}')

    return app


def setup_logging(app):
    """Configure application logging."""
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))
    log_format = app.config.get('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=log_format
    )
    
    # Configure file handler if log file specified
    log_file = app.config.get('LOG_FILE')
    if log_file:
        from pathlib import Path
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(log_format))
        app.logger.addHandler(file_handler)


def register_blueprints(app):
    """Register all application blueprints."""
    from app.routes.dashboard import dashboard_bp
    from app.routes.auth import auth_bp
    from app.routes.api import api_bp
    from app.routes.alerts import alerts_bp
    from app.routes.analytics import analytics_bp
    from app.routes.ai_models import ai_models_bp
    from app.routes.zero_day import zero_day_bp
    from app.routes.federated_clients_api import federated_clients_bp
    from app.routes.mitigation import mitigation_bp
    from app.routes.federated import federated_bp
    
    # optionally register client-local dashboard if running as a federated client
    client_bp = None
    client_flag = app.config.get('CLIENT_ID') or os.environ.get('CLIENT_ID')
    if client_flag:
        try:
            from app.routes.client_dashboard import client_dashboard_bp
            client_bp = client_dashboard_bp
        except ImportError:
            client_bp = None
    
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    # For local development allow auth endpoints without CSRF to simplify api testing
    csrf.exempt(auth_bp)
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    app.register_blueprint(alerts_bp, url_prefix='/alerts')
    app.register_blueprint(analytics_bp, url_prefix='/analytics')
    app.register_blueprint(ai_models_bp)
    app.register_blueprint(zero_day_bp)
    app.register_blueprint(federated_clients_bp)
    app.register_blueprint(mitigation_bp, url_prefix='/mitigation')
    app.register_blueprint(federated_bp)
    csrf.exempt(federated_bp)
    
    # Register federation server dashboard
    try:
        from app.routes.federation_dashboard import federation_dashboard_bp
        app.register_blueprint(federation_dashboard_bp)
        csrf.exempt(federation_dashboard_bp)
        # Start optional local client poller (development/demo convenience)
        try:
            from app.routes.federation_dashboard import start_local_client_poller
            # Only enable automatic polling in development/testing by default
            if app.config.get('POLL_LOCAL_CLIENTS', app.config.get('ENV') != 'production'):
                start_local_client_poller(app)
        except Exception:
            pass
    except ImportError as e:
        app.logger.warning(f'Federation dashboard not available: {e}')
    
    # Register federated API for clients to submit metrics
    try:
        from app.routes.federated_api import federated_api_bp
        app.register_blueprint(federated_api_bp)
        csrf.exempt(federated_api_bp)
    except ImportError as e:
        app.logger.warning(f'Federated API not available: {e}')

    # Ingest endpoints for external federated server processes
    try:
        from app.routes.federation_ingest import federation_ingest_bp
        app.register_blueprint(federation_ingest_bp)
        csrf.exempt(federation_ingest_bp)
    except ImportError as e:
        app.logger.warning(f'Federation ingest API not available: {e}')
    
    if client_bp:
        app.register_blueprint(client_bp)
    
    # Exempt API blueprints from CSRF protection
    csrf.exempt(api_bp)
    csrf.exempt(federated_clients_bp)
    csrf.exempt(mitigation_bp)


def register_error_handlers(app):
    """Register error handlers."""
    from flask import render_template, jsonify, request
    
    @app.errorhandler(400)
    def bad_request(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Bad Request', 'message': str(error)}), 400
        return render_template('errors/400.html'), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401
        return render_template('errors/401.html'), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Forbidden', 'message': 'Access denied'}), 403
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not Found', 'message': 'Resource not found'}), 404
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500
        return render_template('errors/500.html'), 500


def register_cli_commands(app):
    """Register CLI commands."""
    
    @app.cli.command('init-db')
    def init_db():
        """Initialize the database."""
        db.create_all()
        print('Database initialized.')
    
    @app.cli.command('create-admin')
    def create_admin():
        """Create admin user."""
        from app.models.database import User
        
        username = input('Username: ')
        email = input('Email: ')
        password = input('Password: ')
        
        user = User(username=username, email=email, role='admin')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f'Admin user {username} created.')
    
    @app.cli.command('train-models')
    def train_models():
        """Train ML models."""
        from ml.training.trainer import ModelTrainer
        trainer = ModelTrainer()
        trainer.train_all()
        print('Models trained successfully.')

    @app.cli.command('federated-rollback')
    @click.argument('round_number', type=int)
    def federated_rollback(round_number):
        """Rollback the global federated model to a previous round number."""
        # server instance must be accessible via app context variable set by startup script
        from federated.federated_server import get_global_server
        server = get_global_server()
        if server is None:
            print('Federated server not initialized in this process')
            return
        success = server.rollback_model(round_number, rollback_reason='manual CLI')
        if success:
            print(f'Rolled back global model to round {round_number}')
        else:
            print(f'Failed to rollback to round {round_number}')

    @app.cli.command('federated-upgrade')
    def federated_upgrade():
        """Manually trigger an upgrade of the global model (save checkpoint)."""
        from federated.federated_server import get_global_server
        server = get_global_server()
        if server is None:
            print('Federated server not initialized in this process')
            return
        server._save_model_version()
        print('Manual global model checkpoint saved.')


def register_template_filters(app):
    """Register custom Jinja2 template filters."""
    
    @app.template_filter('format_number')
    def format_number(value):
        """Format number with thousands separator."""
        try:
            return '{:,}'.format(int(value or 0))
        except (ValueError, TypeError):
            return '0'
    
    @app.template_filter('number_format')
    def number_format(value):
        """Format number with thousands separator (alias)."""
        try:
            return '{:,}'.format(int(value or 0))
        except (ValueError, TypeError):
            return '0'
    
    @app.template_filter('abs_value')
    def abs_value(value):
        """Return absolute value."""
        try:
            return abs(float(value or 0))
        except (ValueError, TypeError):
            return 0
    
    @app.template_filter('clamp')
    def clamp(value, min_val=0, max_val=100):
        """Clamp a value between min and max."""
        try:
            val = float(value or 0)
            return max(min_val, min(max_val, val))
        except (ValueError, TypeError):
            return min_val
    
    @app.template_filter('percentage')
    def percentage(value, total=100):
        """Calculate percentage with clamping to 100."""
        try:
            if total == 0:
                return 0
            pct = (float(value or 0) / float(total)) * 100
            return min(100, max(0, pct))
        except (ValueError, TypeError):
            return 0
