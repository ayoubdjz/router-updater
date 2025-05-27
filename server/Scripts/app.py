from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
import main_avant as avant_api
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import os
from pathlib import Path

react_build_path = os.path.abspath("../../frontend/router-management-ui/build")

app = Flask(
    __name__,
    static_folder=os.path.join(react_build_path, "static"),
    template_folder=react_build_path,
)


CORS(app)

# Simple in-memory credentials store (for demo; use secure storage in production)
session_credentials = {}
script_dir = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(script_dir, "generated_files")

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
        result = avant_api.run_avant_workflow(ip, username, password, avant_logs)
        # Remove non-serializable connection_obj from result
        if 'connection_obj' in result:
            result.pop('connection_obj')
        return jsonify(result)
    except Exception as e:
        avant_logs.append(f"Erreur dans /api/run_avant: {str(e)}")
        return jsonify({"status": "error", "message": str(e), "log_messages": avant_logs}), 500
    


@app.route('/api/files', methods=['GET'])
def list_files():
    try:
        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)
        files = [f for f in os.listdir(GENERATED_FILES_DIR) if os.path.isfile(os.path.join(GENERATED_FILES_DIR, f))]
        return jsonify({"status": "success", "files": files})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/files/<filename>', methods=['GET'])
def get_file(filename):
    try:
        if ".." in filename or filename.startswith("/"):
            return jsonify({"status": "error", "message": "Invalid filename."}), 400
        if not os.path.isdir(GENERATED_FILES_DIR):
             return jsonify({"status": "error", "message": f"Directory {GENERATED_FILES_DIR} not found."}), 404
        return send_from_directory(GENERATED_FILES_DIR, filename, as_attachment=False)
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "File not found in directory."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/files/<filename>', methods=['DELETE'])
def delete_file(filename):
    try:
        if ".." in filename or filename.startswith("/"): 
            return jsonify({"status": "error", "message": "Invalid filename."}), 400
        
        file_path = os.path.join(GENERATED_FILES_DIR, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({"status": "success", "message": f"File {filename} deleted."})
        else:
            return jsonify({"status": "error", "message": "File not found."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    

if __name__ == '__main__':
    if not os.path.exists(GENERATED_FILES_DIR): 
        os.makedirs(GENERATED_FILES_DIR)
    app.run(debug=True, host='0.0.0.0', port=5000)
