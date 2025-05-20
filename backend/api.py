from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import AVANT_API 
import APRES_API 
from netmiko import ConnectHandler, BaseConnection # Import BaseConnection for type checking
from pathlib import Path

app = Flask(__name__)
CORS(app)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")

# --- Helper function to sanitize results for jsonify ---
def sanitize_for_json(data_dict):
    if not isinstance(data_dict, dict):
        return data_dict # Should not happen if our functions return dicts

    # Explicitly remove known non-serializable keys and check for Netmiko connection objects
    # Create a new dictionary to avoid modifying the original during iteration if it's complex
    sanitized_dict = {}
    for k, v in data_dict.items():
        if k in ['connection_obj', 'lock_obj']: # Known keys for objects
            continue
        if isinstance(v, BaseConnection): # Check if value is a Netmiko connection object
            continue
        sanitized_dict[k] = v
    return sanitized_dict

# ... (test_router_connection - no changes needed here for this error) ...
@app.route('/api/test_connection', methods=['POST'])
def test_router_connection():
    data = request.json
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')
    log_messages = []

    if not all([ip, username, password]):
        return jsonify({"status": "error", "message": "IP, username, and password are required."}), 400
    if not AVANT_API.valider_ip(ip):
        return jsonify({"status": "error", "message": "Adresse IP invalide."}), 400

    device = {'device_type': 'juniper', 'host': ip, 'username': username, 'password': password, 'timeout': 10}
    conn = None
    try:
        log_messages.append(f"Test Connection: Attempting to connect to {ip}...")
        conn = ConnectHandler(**device)
        log_messages.append("Test Connection: Successfully connected.")
        if AVANT_API.verifier_connexion(conn, log_messages):
            conn.disconnect()
            log_messages.append("Test Connection: Verification successful, disconnected.")
            return jsonify({"status": "success", "message": f"Connexion à {ip} réussie.", "logs": log_messages})
        else:
            if conn and conn.is_alive(): conn.disconnect()
            return jsonify({"status": "error", "message": f"Vérification post-connexion à {ip} échouée.", "logs": log_messages}), 500
    except Exception as e:
        if conn and conn.is_alive(): conn.disconnect()
        log_messages.append(f"Test Connection: Exception - {str(e)}")
        return jsonify({"status": "error", "message": f"Échec de la connexion à {ip}: {str(e)}", "logs": log_messages}), 500


@app.route('/api/run_avant', methods=['POST'])
def api_run_avant():
    data = request.json
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')
    log_messages_avant = []
    
    result_from_avant_module = None # To store the full result
    lock_file_path_from_avant_run = None 
    connection_obj_from_avant_run = None

    if not all([ip, username, password]):
        return jsonify(sanitize_for_json({"status": "error", "message": "IP, username, and password are required."})), 400

    try:
        result_from_avant_module = AVANT_API.run_avant_checks(ip, username, password, log_messages_avant)
        
        lock_file_path_from_avant_run = result_from_avant_module.get("lock_file_path") 
        connection_obj_from_avant_run = result_from_avant_module.get("connection_obj")

        # Sanitize the result BEFORE any jsonify attempt, for both success and error paths from run_avant_checks
        serializable_result = sanitize_for_json(result_from_avant_module)
        # Ensure logs collected by this endpoint are also included if not already part of result
        serializable_result["logs"] = log_messages_avant 

        if result_from_avant_module.get("status") == "error":
            if lock_file_path_from_avant_run:
                AVANT_API.liberer_verrou(lock_file_path_from_avant_run, log_messages_avant)
            # serializable_result should now be safe for jsonify
            return jsonify(serializable_result), 500
        
        # SUCCESS from run_avant_checks:
        return jsonify(serializable_result) # serializable_result is now safe

    except Exception as e_api_avant: 
        log_messages_avant.append(f"API /run_avant Erreur inattendue: {str(e_api_avant)}")
        if lock_file_path_from_avant_run: # If known from a partial result_from_avant_module
             AVANT_API.liberer_verrou(lock_file_path_from_avant_run, log_messages_avant)
        
        # Construct a safe error response
        error_response = {
            "status": "error", 
            "message": f"Erreur inattendue dans l'API /run_avant: {str(e_api_avant)}",
            "logs": log_messages_avant
        }
        if result_from_avant_module: # If we have some result, try to include its safe parts
            error_response["partial_result_summary"] = {
                k:v for k,v in sanitize_for_json(result_from_avant_module).items() if k not in ["logs"]
            }

        return jsonify(error_response), 500
    finally:
        if connection_obj_from_avant_run and connection_obj_from_avant_run.is_alive():
            log_messages_avant.append("API /run_avant (finally): Fermeture de la connexion après l'exécution de AVANT.")
            # This log won't make it to client if error occurs before jsonify, but good for server logs
            connection_obj_from_avant_run.disconnect()


@app.route('/api/run_update', methods=['POST'])
def api_run_update():
    data = request.json
    ident_data = data.get('ident_data')
    password = data.get('password')
    image_file = data.get('image_file')
    log_messages_update = []
    result_from_update_module = None # To store full result

    if not all([ident_data, password, image_file]):
        return jsonify(sanitize_for_json({"status": "error", "message": "Ident_data, password, and image_file are required."})), 400

    ip = ident_data.get('ip')
    username = ident_data.get('username')
    lock_file_path_from_ident = ident_data.get('lock_file_path')
    connection_for_update = None 

    if not lock_file_path_from_ident or not os.path.exists(lock_file_path_from_ident):
        msg = (f"Fichier de verrou requis ({lock_file_path_from_ident}) non trouvé. "
               "Exécutez AVANT d'abord ou le flux de travail est interrompu.")
        log_messages_update.append(msg)
        return jsonify(sanitize_for_json({"status": "error", "message": msg, "logs": log_messages_update})), 412

    try:
        update_device_details = {
            'device_type': 'juniper', 'host': ip, 'username': username, 'password': password,
            'timeout': 30, 'auth_timeout': 45, 'banner_timeout': 45,
        }
        log_messages_update.append(f"API UPDATE: Connexion à {ip} pour la mise à jour...")
        connection_for_update = ConnectHandler(**update_device_details) # This is the connection object for this scope
        if not AVANT_API.verifier_connexion(connection_for_update, log_messages_update):
            raise Exception("Échec de la vérification de la connexion avant la mise à jour.")
        
        log_messages_update.append("API UPDATE: Lancement de la procédure de mise à jour...")
        result_from_update_module = AVANT_API.run_update_procedure(
            connection_for_update, # Pass the live connection
            update_device_details, 
            image_file, 
            log_messages_update
        )
        
        serializable_result = sanitize_for_json(result_from_update_module)
        serializable_result["ident_data"] = ident_data 
        serializable_result["logs"] = log_messages_update

        if result_from_update_module.get("status") == "success":
            return jsonify(serializable_result)
        else:
            return jsonify(serializable_result), 500

    except Exception as e:
        error_msg = f"API UPDATE: Erreur majeure - {str(e)}"
        log_messages_update.append(error_msg)
        error_response = {
            "status": "error", "message": error_msg, 
            "logs": log_messages_update, "ident_data": ident_data
        }
        if result_from_update_module:
             error_response["partial_result_summary"] = {
                k:v for k,v in sanitize_for_json(result_from_update_module).items() if k not in ["logs"]
            }
        return jsonify(error_response), 500
    finally:
        # The connection_for_update is local to this function's scope for the update operation.
        # run_update_procedure might return this same object or a new one if it handled reconnects.
        # For simplicity, we assume run_update_procedure uses the passed connection.
        if connection_for_update and connection_for_update.is_alive():
            connection_for_update.disconnect()
            log_messages_update.append("API UPDATE (finally): Connexion pour la mise à jour fermée.")


@app.route('/api/run_apres', methods=['POST'])
def api_run_apres():
    data = request.json
    ident_data = data.get('ident_data') 
    password = data.get('password')     
    log_messages_apres = []
    result_from_apres_module = None # To store full result
    connection_obj_from_apres_run = None 

    if not all([ident_data, password]):
        return jsonify(sanitize_for_json({"status": "error", "message": "Ident_data and password are required."})), 400

    lock_file_to_release = ident_data.get('lock_file_path') 

    if not lock_file_to_release or not os.path.exists(lock_file_to_release):
        msg = (f"Fichier de verrou requis ({lock_file_to_release}) non trouvé pour APRES. "
               "Le flux normal est AVANT -> (UPDATE) -> APRES. Le verrou aurait dû persister.")
        log_messages_apres.append(msg)
        log_messages_apres.append("AVERTISSEMENT: Poursuite d'APRES sans fichier de verrou actif (ou attendu).")
        # Depending on strictness, could return 412 here.

    try:
        result_from_apres_module = APRES_API.run_apres_checks_and_compare(ident_data, password, log_messages_apres, avant_connection=None)
        connection_obj_from_apres_run = result_from_apres_module.get("connection_obj")
        
        serializable_result = sanitize_for_json(result_from_apres_module)
        serializable_result["logs"] = log_messages_apres
        
        if result_from_apres_module.get("status") == "error":
            return jsonify(serializable_result), 500
        
        return jsonify(serializable_result)

    except Exception as e_api_apres:
        error_msg = f"API APRES: Erreur majeure inattendue - {str(e_api_apres)}"
        log_messages_apres.append(error_msg)
        error_response = {
            "status": "error", "message": error_msg, "logs": log_messages_apres
        }
        if result_from_apres_module:
             error_response["partial_result_summary"] = {
                k:v for k,v in sanitize_for_json(result_from_apres_module).items() if k not in ["logs"]
            }
        return jsonify(error_response), 500
    finally:
        if lock_file_to_release: 
            AVANT_API.liberer_verrou(lock_file_to_release, log_messages_apres)
        
        if connection_obj_from_apres_run and connection_obj_from_apres_run.is_alive():
            connection_obj_from_apres_run.disconnect()
            log_messages_apres.append("API APRES (finally): Connexion pour APRES fermée.")

# ... (unlock_router, list_files, get_file, delete_file, and __main__ remain the same as the last full api.py)
@app.route('/api/unlock_router', methods=['POST'])
def api_unlock_router():
    data = request.json
    lock_file_path = data.get('lock_file_path')
    log_messages = []

    if not lock_file_path:
        return jsonify({"status": "error", "message": "lock_file_path is required."}), 400

    if AVANT_API.liberer_verrou(lock_file_path, log_messages):
        return jsonify({"status": "success", "message": f"Tentative de libération du verrou {lock_file_path} effectuée.", "logs": log_messages})
    else:
        return jsonify({"status": "error", "message": f"Échec de la tentative de libération du verrou {lock_file_path}. Vérifiez les logs.", "logs": log_messages}), 500

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
            if os.path.abspath(AVANT_API.LOCK_DIR) in os.path.abspath(file_path):
                 return jsonify({"status": "error", "message": "Cannot delete lock files via this generic file endpoint. Use /api/unlock_router."}), 403
            os.remove(file_path)
            return jsonify({"status": "success", "message": f"File {filename} deleted."})
        else:
            return jsonify({"status": "error", "message": "File not found."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    if not os.path.exists(GENERATED_FILES_DIR): 
        os.makedirs(GENERATED_FILES_DIR)
    if not os.path.exists(AVANT_API.LOCK_DIR): 
        os.makedirs(AVANT_API.LOCK_DIR)
    
    app.run(debug=True, host='0.0.0.0', port=5001)