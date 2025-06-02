from flask import Flask, send_from_directory, request, jsonify, Response
from flask_cors import CORS
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import os
from pathlib import Path
from locking_utils import verrouiller_routeur, liberer_verrou_et_fichier
import portalocker
from common_utils import sanitize_for_json, stream_log
from locking_utils import liberer_verrou_et_fichier, verrouiller_routeur
from updater import run_update_procedure
import time
import datetime
import main_avant as avant_api
import time_stream
import main_apres


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
apres_logs = []
update_logs = []

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

    if not all([ip, username, password]):
        return jsonify({"status": "error", "message": "IP, username, and password are required."}), 400

    current_run_operation_logs = []
    result_from_avant_module = None
    connection_obj_from_avant_run = None
    lock_file_path_from_avant_run = None
    try:
        result_from_avant_module = avant_api.run_avant_workflow(ip, username, password, current_run_operation_logs)
        avant_logs.clear()
        avant_logs.extend(current_run_operation_logs)
        if not result_from_avant_module:
            return jsonify({
                "status": "error",
                "message": "Erreur inattendue: Aucun résultat final structuré du workflow avant.",
                "logs": current_run_operation_logs
            }), 500
        lock_file_path_from_avant_run = result_from_avant_module.get("lock_file_path")
        connection_obj_from_avant_run = result_from_avant_module.get("connection_obj")
        if 'connection_obj' in result_from_avant_module:
            result_from_avant_module.pop("connection_obj")
        serializable_result = sanitize_for_json(result_from_avant_module)
        serializable_result["logs"] = result_from_avant_module.get("log_messages", current_run_operation_logs)
        if result_from_avant_module.get("status") == "error":
            return jsonify(serializable_result), 500
        return jsonify(serializable_result)
    except Exception as e_api_avant:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_msg = f"[{timestamp}] API /run_avant (non-SSE) Erreur critique: {str(e_api_avant)}"
        current_run_operation_logs.append(error_msg)
        avant_logs.clear()
        avant_logs.extend(current_run_operation_logs)
        error_response = {
            "status": "error",
            "message": f"Erreur critique dans l'API /run_avant (non-SSE): {str(e_api_avant)}",
            "logs": current_run_operation_logs
        }
        if result_from_avant_module:
            error_response["partial_result_summary"] = {
                k: v for k, v in sanitize_for_json(result_from_avant_module).items()
                if k not in ["logs", "connection_obj"]
            }
        return jsonify(error_response), 500
    finally:
        if connection_obj_from_avant_run and \
           hasattr(connection_obj_from_avant_run, 'is_alive') and \
           connection_obj_from_avant_run.is_alive():
            api_finally_log_msg = "API /run_avant (non-SSE finally): La connexion Netmiko était encore active. Tentative de fermeture."
            avant_logs.append(api_finally_log_msg)
            try:
                connection_obj_from_avant_run.disconnect()
            except Exception as e_disconnect_api_finally:
                api_finally_err_msg = f"API /run_avant (non-SSE finally): Erreur lors de la tentative de fermeture de la connexion: {str(e_disconnect_api_finally)}"
                avant_logs.append(api_finally_err_msg)

@app.route('/api/run_apres', methods=['POST'])
def api_run_apres():
    data = request.json
    avant_ident_file = data.get('ident_file')
    password_apres = data.get('password')
    if not password_apres:
        return jsonify({"status": "error", "message": "Password is required for APRES."}), 400
    current_run_operation_logs = []
    result_from_apres_module = None
    try:
        result_from_apres_module = main_apres.run_apres_workflow(avant_ident_file, current_run_operation_logs, password_apres)
        apres_logs.clear()
        apres_logs.extend(current_run_operation_logs)
        if not result_from_apres_module:
            return jsonify({
                "status": "error",
                "message": "Erreur inattendue: Aucun résultat final du workflow apres.",
                "logs": current_run_operation_logs
            }), 500
        if 'connection_obj' in result_from_apres_module:
            result_from_apres_module.pop('connection_obj')
        serializable_result = sanitize_for_json(result_from_apres_module)
        serializable_result["logs"] = result_from_apres_module.get("logs", current_run_operation_logs)
        if result_from_apres_module.get("status") == "error":
            return jsonify(serializable_result), 500
        return jsonify(serializable_result)
    except Exception as e_api_apres:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_msg = f"[{timestamp}] API /run_apres (non-SSE) Erreur critique: {str(e_api_apres)}"
        current_run_operation_logs.append(error_msg)
        apres_logs.clear()
        apres_logs.extend(current_run_operation_logs)
        error_response = {
            "status": "error",
            "message": f"Erreur critique dans l'API /run_apres (non-SSE): {str(e_api_apres)}",
            "logs": current_run_operation_logs
        }
        if result_from_apres_module:
            error_response["partial_result_summary"] = {
                k: v for k, v in sanitize_for_json(result_from_apres_module).items() if k not in ["logs"]
            }
        return jsonify(error_response), 500

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
    

@app.route('/api/run_update', methods=['POST'])
def api_run_update():
    data = request.json
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')
    image_file = data.get('image_file')
    def event_stream():
        logs = []
        # This function will be called on every log() call in run_update_procedure
        def sse_stream(msg):
            yield f"data: {msg}\n\n"
        # Use a generator to yield logs in real time
        result_holder = {'done': False, 'result': None}
        def run_update():
            # Pass sse_stream as a callback to run_update_procedure
            def log_yielder(msg):
                logs.append(msg)
                # This will be picked up in the main generator loop
            result = run_update_procedure(ip, username, password, image_file, logs, log_callback=None, sse_stream=None)
            result_holder['result'] = result
            result_holder['done'] = True
        import threading
        import time
        t = threading.Thread(target=run_update)
        t.start()
        last_len = 0
        while not result_holder['done'] or last_len < len(logs):
            while last_len < len(logs):
                msg = logs[last_len]
                yield f"data: {msg}\n\n"
                last_len += 1
            time.sleep(0.5)
        import json
        yield f"event: result\ndata: {json.dumps(result_holder['result'])}\n\n"
    return Response(event_stream(), mimetype='text/event-stream')
    

@app.route('/api/test_sse')
def api_test_sse():
    import time_stream
    import json
    def event_stream():
        logs = []
        gen = time_stream.time_stream_log_generator(logs, count=5, delay=1)
        try:
            while True:
                try:
                    log_line = next(gen)
                    yield f"data: {log_line}\n\n"
                except StopIteration as e:
                    # At the end, send the full logs as a JSON event
                    logs_table = e.value if e.value is not None else logs
                    yield f"event: logs\ndata: {json.dumps(logs_table)}\n\n"
                    break
        except Exception as ex:
            yield f"data: [SSE error: {str(ex)}]\n\n"
    return Response(event_stream(), mimetype='text/event-stream')
    

if __name__ == '__main__':
    if not os.path.exists(GENERATED_FILES_DIR): 
        os.makedirs(GENERATED_FILES_DIR)
    app.run(debug=True, host='0.0.0.0', port=5000)
