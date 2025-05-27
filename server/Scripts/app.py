from flask import Flask, request, jsonify
from flask_cors import CORS
from main_avant import run_avant_workflow
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import os
from pathlib import Path

app = Flask(__name__)
CORS(app)

# Simple in-memory credentials store (for demo; use secure storage in production)
session_credentials = {}

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')
    if not all([ip, username, password]):
        return jsonify({"status": "error", "message": "IP, username, and password are required."}), 400
    try:
        device = {
            'device_type': 'juniper_junos',
            'host': ip,
            'username': username,
            'password': password,
            'timeout': 10
        }
        conn = ConnectHandler(**device)
        conn.disconnect()
        # Save credentials in memory (keyed by IP+username)
        session_credentials[(ip, username)] = password
        return jsonify({"status": "success", "message": f"Connexion à {ip} réussie."})
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        return jsonify({"status": "error", "message": f"Connexion échouée: {str(e)}"}), 401
    except Exception as e:
        return jsonify({"status": "error", "message": f"Erreur: {str(e)}"}), 500

@app.route('/api/run_avant', methods=['POST'])
def api_run_avant():
    data = request.json
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')
    avant_logs = []
    if not all([ip, username, password]):
        return jsonify({"status": "error", "message": "IP, username, and password are required."}), 400
    try:
        result = run_avant_workflow(ip, username, password, avant_logs)
        # Remove non-serializable connection_obj from result
        if 'connection_obj' in result:
            result.pop('connection_obj')
        return jsonify(result)
    except Exception as e:
        avant_logs.append(f"Erreur dans /api/run_avant: {str(e)}")
        return jsonify({"status": "error", "message": str(e), "log_messages": avant_logs}), 500
    
script_dir = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(script_dir, "generated_files")

@app.route('/api/files', methods=['GET'])
def list_files():
    try:
        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)
        files = [f for f in os.listdir(GENERATED_FILES_DIR) if os.path.isfile(os.path.join(GENERATED_FILES_DIR, f))]
        return jsonify({"status": "success", "files": files})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


