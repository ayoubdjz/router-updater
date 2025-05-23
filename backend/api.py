from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import os
import json
import avant_api 
import apres_api 
from netmiko import ConnectHandler, BaseConnection # Import BaseConnection for type checking
from pathlib import Path

react_build_path = os.path.abspath("../../frontend/router-management-ui/build")

app = Flask(
    __name__,
    static_folder=os.path.join(react_build_path, "static"),
    template_folder=react_build_path,
)


CORS(app)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")

# --- Helper function to sanitize results for jsonify ---pa
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
    if not avant_api.valider_ip(ip):
        return jsonify({"status": "error", "message": "Adresse IP invalide."}), 400

    device = {'device_type': 'juniper', 'host': ip, 'username': username, 'password': password, 'timeout': 10}
    conn = None
    try:
        log_messages.append(f"Test Connection: Attempting to connect to {ip}...")
        conn = ConnectHandler(**device)
        log_messages.append("Test Connection: Successfully connected.")
        if avant_api.verifier_connexion(conn, log_messages):
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
        result_from_avant_module = avant_api.run_avant_checks(ip, username, password, log_messages_avant)
        lock_file_path_from_avant_run = result_from_avant_module.get("lock_file_path") 
        connection_obj_from_avant_run = result_from_avant_module.get("connection_obj")

        serializable_result = sanitize_for_json(result_from_avant_module)
        serializable_result["logs"] = log_messages_avant

        if result_from_avant_module.get("status") == "error":
            if lock_file_path_from_avant_run:
                avant_api.liberer_verrou(lock_file_path_from_avant_run, log_messages_avant)
            return jsonify(serializable_result), 500
        return jsonify(serializable_result)
    except Exception as e_api_avant: 
        log_messages_avant.append(f"API /run_avant Erreur inattendue: {str(e_api_avant)}")
        if lock_file_path_from_avant_run: # If known from a partial result_from_avant_module
             avant_api.liberer_verrou(lock_file_path_from_avant_run, log_messages_avant)
        
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
    ident_data = data.get('ident_data')  # Contains device_details_for_update, lock_file_path, ip, username
    password_from_req = data.get('password') # Password explicitly provided for the update operation
    image_file = data.get('image_file')
    
    log_messages_update = []
    result_from_update_module = None # This will store the direct output from avant_api.run_update_procedure
    current_connection = None  # This will hold the active connection object for this API call

    if not all([ident_data, password_from_req, image_file]):
        log_messages_update.append("API UPDATE ERREUR: ident_data, password, et image_file sont requis.")
        # Sanitize even this basic error response if needed, though it's simple
        return jsonify(sanitize_for_json({
            "status": "error", 
            "message": "ident_data, password, et image_file sont requis.",
            "logs": log_messages_update
        })), 400

    lock_file_path_from_ident = ident_data.get('lock_file_path')
    # device_details_for_reconnect is crucial for run_update_procedure's internal reconnections.
    # It's sourced from ident_data (output of run_avant) and updated with the current password.
    device_details_for_reconnect = ident_data.get('device_details_for_update')

    if not device_details_for_reconnect:
        log_messages_update.append("API UPDATE ERREUR: 'device_details_for_update' manquant dans ident_data.")
        return jsonify(sanitize_for_json({
            "status": "error", 
            "message": "Données de configuration (device_details_for_update) manquantes dans ident_data. Exécutez AVANT d'abord.",
            "logs": log_messages_update
        })), 400

    # Ensure the device_details_for_reconnect uses the password explicitly sent for this update operation,
    # and the correct host IP and username from ident_data.
    device_details_for_reconnect['password'] = password_from_req
    device_details_for_reconnect['host'] = ident_data.get('ip')
    if 'username' not in device_details_for_reconnect or not device_details_for_reconnect['username']:
        device_details_for_reconnect['username'] = ident_data.get('username')


    if not lock_file_path_from_ident or not os.path.exists(lock_file_path_from_ident):
        msg = (f"Fichier de verrou requis ({lock_file_path_from_ident}) non trouvé. "
               "Exécutez AVANT d'abord ou le flux de travail est interrompu.")
        log_messages_update.append(msg)
        return jsonify(sanitize_for_json({"status": "error", "message": msg, "logs": log_messages_update})), 412 # Precondition Failed

    try:
        log_messages_update.append(f"API UPDATE: Tentative de connexion à {device_details_for_reconnect['host']} pour la mise à jour...")
        # Establish the initial connection for this API call using the prepared device details
        current_connection = ConnectHandler(**device_details_for_reconnect)
        log_messages_update.append(f"API UPDATE: Connecté avec succès à {device_details_for_reconnect['host']}.")

        if not avant_api.verifier_connexion(current_connection, log_messages_update, context="UPDATE PRE-CHECK"):
            # verifier_connexion appends its own logs to log_messages_update
            raise Exception("Échec de la vérification de la connexion avant la mise à jour.")
        
        log_messages_update.append("API UPDATE: Lancement de la procédure de mise à jour via avant_api.run_update_procedure...")
        
        # Call avant_api.run_update_procedure.
        # It will use current_connection and may return a new one if RE switchover occurs.
        # It will also append its logs to log_messages_update.
        result_from_update_module = avant_api.run_update_procedure(
            current_connection, 
            device_details_for_reconnect, # For its own internal reconnections
            image_file, 
            log_messages_update
            # skip_re0_final_switchback could be a param: data.get('skip_final_switchback', False)
        )
        
        # The result_from_update_module contains {status, message, updated_junos_info, connection_obj, log_messages (same as log_messages_update)}
        
        # Update current_connection to the one returned by the procedure,
        # as it might have changed due to RE switchovers handled within run_update_procedure.
        returned_connection_obj = result_from_update_module.get("connection_obj")
        
        if returned_connection_obj:
            if returned_connection_obj != current_connection: # If a new connection object was made and returned
                log_messages_update.append(f"API UPDATE: Un nouvel objet de connexion a été retourné par run_update_procedure.")
                if current_connection and current_connection.is_alive():
                    log_messages_update.append("API UPDATE: Fermeture de l'objet de connexion initial qui n'est plus le principal.")
                    current_connection.disconnect() # Disconnect the old one
            current_connection = returned_connection_obj # This is now the definitive connection object to manage
        # If no connection_obj is in result_from_update_module (e.g., on critical error within run_update_procedure),
        # current_connection remains the one established at the start of this try block. It might have been closed 
        # by run_update_procedure itself in its own error handling.

        # Prepare the result from avant_api.run_update_procedure for sending to the client
        serializable_result = sanitize_for_json(result_from_update_module)
        # Add context and ensure the most complete logs are sent
        serializable_result["ident_data"] = ident_data 
        serializable_result["logs"] = log_messages_update # This list contains all logs

        status_code = 500 # Default to server error
        if result_from_update_module.get("status") == "success":
            status_code = 200
        elif result_from_update_module.get("status") == "success_with_warning":
             status_code = 200 # Still a success from HTTP perspective; frontend handles warning
        
        log_messages_update.append(f"API UPDATE: Envoi de la réponse au client avec status {status_code}.")
        return jsonify(serializable_result), status_code

    except Exception as e_api_update:
        import traceback
        error_msg = f"API UPDATE: Erreur majeure inattendue - {str(e_api_update)}"
        log_messages_update.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        
        error_response_payload = {
            "status": "error", "message": error_msg, 
            "logs": log_messages_update, "ident_data": ident_data
        }
        # If result_from_update_module exists (meaning avant_api.run_update_procedure was called and returned something)
        if result_from_update_module: 
             error_response_payload["partial_result_summary"] = {
                k:v for k,v in sanitize_for_json(result_from_update_module).items() 
                if k not in ["logs", "connection_obj"] # Exclude already handled/non-serializable
            }
        return jsonify(error_response_payload), 500
    finally:
        # current_connection is the definitive connection object after all operations.
        if current_connection:
            if current_connection.is_alive():
                current_connection.disconnect()
                log_messages_update.append("API UPDATE (finally): Connexion active pour la mise à jour fermée.")
            else:
                log_messages_update.append("API UPDATE (finally): Connexion pour la mise à jour trouvée mais déjà fermée (probablement gérée par avant_api).")
        else:
            log_messages_update.append("API UPDATE (finally): Aucune connexion pour la mise à jour trouvée à fermer (potentiellement jamais établie, ou déjà gérée par avant_api).")

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
        result_from_apres_module = apres_api.run_apres_checks_and_compare(ident_data, password, log_messages_apres, avant_connection=None)
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
            avant_api.liberer_verrou(lock_file_to_release, log_messages_apres)
        
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

    if avant_api.liberer_verrou(lock_file_path, log_messages):
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
            if os.path.abspath(avant_api.LOCK_DIR) in os.path.abspath(file_path):
                 return jsonify({"status": "error", "message": "Cannot delete lock files via this generic file endpoint. Use /api/unlock_router."}), 403
            os.remove(file_path)
            return jsonify({"status": "success", "message": f"File {filename} deleted."})
        else:
            return jsonify({"status": "error", "message": "File not found."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react(path):
    file_path = os.path.join(app.template_folder, path)
    if path != "" and os.path.exists(file_path):
        return send_from_directory(app.template_folder, path)
    else:
        return send_from_directory(app.template_folder, "index.html")

# === Example API route ===
@app.route("/api/test")
def test():
    return {"message": "Flask API is working"}

if __name__ == '__main__':
    if not os.path.exists(GENERATED_FILES_DIR): 
        os.makedirs(GENERATED_FILES_DIR)
    if not os.path.exists(avant_api.LOCK_DIR): 
        os.makedirs(avant_api.LOCK_DIR)
    
    app.run(debug=True, host='0.0.0.0', port=5001)