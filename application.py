"""
AI-NIDS Application Entry Point
================================
Main application entry point for running the Flask server.
"""

import os
import argparse

from app import create_app


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='AI-NIDS Flask application entry point'
    )
    parser.add_argument('--host', type=str, default=os.environ.get('HOST', '0.0.0.0'),
                        help='Host to bind to')
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT',
                        os.environ.get('CLIENT_PORT', 5000))),
                        help='Port to bind to')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode (overrides env)')
    parser.add_argument('--client-id', type=str,
                        help='Optional client identifier for federated clients')
    parser.add_argument('--client-type', type=str,
                        help='Logical client type (hospital, bank, etc)')
    parser.add_argument('--federated-server', type=str,
                        help='URL of federated server websocket endpoint')
    return parser.parse_args()


# Create the Flask application
args = parse_arguments()

# propagate CLI args to environment so create_app picks them up
if args.client_id:
    os.environ['CLIENT_ID'] = args.client_id
if args.client_type:
    os.environ['CLIENT_TYPE'] = args.client_type
if args.federated_server:
    os.environ['FEDERATED_SERVER_URL'] = args.federated_server
# also allow user to override HOST/PORT via CLI
os.environ['HOST'] = args.host
os.environ['PORT'] = str(args.port)

app = create_app()

if __name__ == '__main__':
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug or os.environ.get('FLASK_ENV', '').startswith('dev')
    )
