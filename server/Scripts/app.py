from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
import main_avant as avant_api
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import os
from pathlib import Path
from locking_utils import verrouiller_routeur, liberer_verrou_et_fichier
import portalocker
from common_utils import sanitize_for_json
from locking_utils import liberer_verrou_et_fichier, verrouiller_routeur

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
avant_logs = []

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

# @app.route('/api/run_avant', methods=['POST'])
# def api_run_avant():
#     data = request.json
#     ip = data.get('ip')
#     username = data.get('username')
#     password = data.get('password')
#     if not all([ip, username, password]):
#         return jsonify({"status": "error", "message": "IP, username, and password are required."}), 400
#     try:
#         result = avant_api.run_avant_workflow(ip, username, password, avant_logs)
#         # Remove non-serializable connection_obj from result
#         if 'connection_obj' in result:
#             result.pop('connection_obj')
#         return jsonify(result)
#     except Exception as e:
#         avant_logs.append(f"Erreur dans /api/run_avant: {str(e)}")
#         return jsonify({"status": "error", "message": str(e), "log_messages": avant_logs}), 500
    
@app.route('/api/run_avant', methods=['POST'])
def api_run_avant():
    data = request.json
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')    
    result_from_avant_module = None # To store the full result
    lock_file_path_from_avant_run = None 
    connection_obj_from_avant_run = None

    if not all([ip, username, password]):
        return jsonify({"status": "error", "message": "IP, username, and password are required."}), 400

    try:
        result_from_avant_module = avant_api.run_avant_workflow(ip, username, password, avant_logs)
        lock_file_path_from_avant_run = result_from_avant_module.get("lock_file_path")
        lock_aquired = result_from_avant_module.get("lock_acquired", False)
        connection_obj_from_avant_run = result_from_avant_module.get("connection_obj")
        if connection_obj_from_avant_run in result_from_avant_module:
            result_from_avant_module.pop("connection_obj") # Remove connection_obj from the result to avoid serialization issues
        serializable_result = sanitize_for_json(result_from_avant_module)
        if result_from_avant_module.get("status") == "error":
            if lock_file_path_from_avant_run:
                liberer_verrou_et_fichier(lock_aquired, lock_file_path_from_avant_run, avant_logs)
            return jsonify(serializable_result), 500
        return jsonify(serializable_result)
    except Exception as e_api_avant: 
        avant_logs.append(f"API /run_avant Erreur inattendue: {str(e_api_avant)}")
        if lock_file_path_from_avant_run: # If known from a partial result_from_avant_module
             avant_api.liberer_verrou_et_fichier(lock_file_path_from_avant_run, avant_logs)
        
        # Construct a safe error response
        error_response = {
            "status": "error", 
            "message": f"Erreur inattendue dans l'API /run_avant: {str(e_api_avant)}",
            "logs": avant_logs
        }
        if result_from_avant_module: # If we have some result, try to include its safe parts
            error_response["partial_result_summary"] = {
                k:v for k,v in sanitize_for_json(result_from_avant_module).items() if k not in ["logs"]
            }
        return jsonify(error_response), 500
    finally:
        if connection_obj_from_avant_run and connection_obj_from_avant_run.is_alive():
            avant_logs.append("API /run_avant (finally): Fermeture de la connexion après l'exécution de AVANT.")
            connection_obj_from_avant_run.disconnect()

    


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
    
@app.route('/api/lock_router', methods=['POST'])
def api_lock_router():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"status": "error", "message": "IP is required."}), 400
    lock, lock_file = verrouiller_routeur(ip)
    if lock is None or lock_file is None:
        return jsonify({"status": "error", "message": f"Router {ip} is already locked or lock failed."}), 423
    return jsonify({"status": "success", "message": f"Router {ip} locked.", "lock_file": lock_file})

@app.route('/api/unlock_router', methods=['POST'])
def api_unlock_router():
    data = request.json
    ip = data.get('ip')
    lock_file = data.get('lock_file')
    if not ip or not lock_file:
        return jsonify({"status": "error", "message": "IP and lock_file are required."}), 400
    lock = None
    try:
        if os.path.exists(lock_file):
            lock = portalocker.Lock(lock_file, flags=portalocker.LOCK_EX)
            try:
                lock.acquire(timeout=1)
            except Exception:
                pass  # If already locked, just try to release/delete
        liberer_verrou_et_fichier(lock, lock_file, avant_logs= avant_logs)
        return jsonify({"status": "success", "message": f"Router {ip} unlocked."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Unlock failed: {e}"}), 500
    

if __name__ == '__main__':
    if not os.path.exists(GENERATED_FILES_DIR): 
        os.makedirs(GENERATED_FILES_DIR)
    app.run(debug=True, host='0.0.0.0', port=5000)
