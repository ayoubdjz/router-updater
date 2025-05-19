from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS # For local development with React on different port
import os
import json
import AVANT_API # Import your refactored avant script
import APRES_API # Import your refactored apres script
from netmiko import ConnectHandler # For quick connection test

app = Flask(__name__)
CORS(app) # Allow all origins for simplicity in dev

# Configuration for generated files and locks (must match AVANT_API/APRES_API)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
LOCK_DIR = os.path.join(SCRIPT_DIR, "router_locks") # AVANT_API handles creation

# Global dictionary to keep track of active connections/locks if needed across requests
# For simplicity, we are not doing this yet. Each main operation establishes its own connection
# or expects one to be passed. The lock file on disk is the primary synchronization.
# active_sessions = {} # Could store {'ip': {'lock': lock_obj, 'connection': conn_obj, 'ident_data': ...}}


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

    device = {
        'device_type': 'juniper',
        'host': ip,
        'username': username,
        'password': password,
        'timeout': 10, # Shorter timeout for a quick test
    }
    conn = None
    try:
        log_messages.append(f"Test Connection: Attempting to connect to {ip}...")
        conn = ConnectHandler(**device)
        log_messages.append("Test Connection: Successfully connected.")
        if AVANT_API.verifier_connexion(conn, log_messages): # Use verifier_connexion from AVANT_API
            conn.disconnect()
            log_messages.append("Test Connection: Verification successful, disconnected.")
            return jsonify({"status": "success", "message": f"Connexion à {ip} réussie.", "logs": log_messages})
        else:
            if conn and conn.is_alive(): conn.disconnect()
            log_messages.append("Test Connection: Verification failed after connection.")
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
    log_messages_avant = [] # Initialize log list for this run

    if not all([ip, username, password]):
        return jsonify({"status": "error", "message": "IP, username, and password are required."}), 400

    result = AVANT_API.run_avant_checks(ip, username, password, log_messages_avant)

    # The lock is acquired by run_avant_checks.
    # For the API, if AVANT is one step and UPDATE is another,
    # the lock must persist or be re-acquired.
    # For now, AVANT returns the lock_file_path. The API must ensure it's cleaned up.
    # If avant fails, or if it succeeds but no update follows, lock should be released.
    
    # IMPORTANT: The lock acquired by run_avant_checks is NOT released here yet if successful,
    # because it might be needed for an immediate follow-up 'run_update' call.
    # The frontend flow should be: run_avant -> (if success) -> confirm update -> run_update (which uses avant's lock/conn)
    # OR run_avant -> (if success & no update) -> explicit unlock call OR run_apres (which might unlock)
    # This makes the API stateful regarding the lock. Simpler for now: unlock if AVANT fails.

    if result.get("status") == "error":
        # If avant checks fail, try to release the lock if one was made
        lock_file_to_clean = result.get("lock_file_path")
        if lock_file_to_clean:
            # We don't have the lock object here, so can only delete the file.
            # AVANT_API.liberer_verrou(None, lock_file_to_clean, log_messages_avant)
             if os.path.exists(lock_file_to_clean):
                try:
                    os.remove(lock_file_to_clean)
                    log_messages_avant.append(f"API: Fichier de verrou {lock_file_to_clean} supprimé après échec AVANT.")
                except Exception as e_del_lock:
                    log_messages_avant.append(f"API: Erreur suppression fichier verrou {lock_file_to_clean} après échec AVANT: {e_del_lock}")
        result["logs"] = log_messages_avant # Ensure logs are part of the error response
        return jsonify(result), 500
    
    result["logs"] = log_messages_avant # Add logs to success response
    return jsonify(result)


@app.route('/api/run_update', methods=['POST'])
def api_run_update():
    data = request.json
    ident_data = data.get('ident_data') # This should come from the AVANT call's response
    password = data.get('password')     # Router password needed again
    image_file = data.get('image_file')
    log_messages_update = []

    if not all([ident_data, password, image_file]):
        return jsonify({"status": "error", "message": "Ident_data, password, and image_file are required."}), 400

    ip = ident_data.get('ip')
    username = ident_data.get('username')
    lock_file_path_from_avant = ident_data.get('lock_file_path') # Critical: lock from AVANT

    # Re-acquire lock object using the path. This is tricky if AVANT_API holds the lock object.
    # For true statefulness, the lock object and connection should be managed by the API session.
    # Simplified: Assume lock file exists, try to use it.
    # A more robust way: AVANT returns, if update chosen, API makes sure lock is still valid
    # or re-establishes everything.

    # For this API call, we need a live connection.
    # The `run_update_procedure` expects one.
    connection_for_update = None
    lock_for_update = None
    update_device_details = {
        'device_type': 'juniper',
        'host': ip,
        'username': username,
        'password': password, # Password from current request
        'timeout': 30, # Standard timeout
        'auth_timeout': 45,
        'banner_timeout': 45,
    }

    try:
        # Verify and potentially re-acquire lock for this operation
        # This simplistic lock re-acquisition might not be fully robust with portalocker's object model
        # if the lock object from AVANT isn't passed. The file lock is the main guard.
        if not lock_file_path_from_avant or not os.path.exists(lock_file_path_from_avant):
            log_messages_update.append(f"API UPDATE: Fichier de verrou {lock_file_path_from_avant} non trouvé. Tentative de verrouillage.")
            lock_for_update, lock_file_path_from_avant = AVANT_API.verrouiller_routeur(ip, log_messages_update)
            if not lock_for_update:
                 raise Exception(f"Impossible de réacquérir le verrou pour {ip} pour la mise à jour.")
            ident_data['lock_file_path'] = lock_file_path_from_avant # update ident_data
        else:
            # If lock file exists, we assume it's ours. Portalocker file lock should prevent others.
            # We create a new lock object instance for this scope.
            lock_for_update = portalocker.Lock(lock_file_path_from_avant, flags=portalocker.LOCK_EX)
            try:
                lock_for_update.acquire(timeout=0.1) # Try to acquire, should succeed if we own it.
                log_messages_update.append(f"API UPDATE: Verrou {lock_file_path_from_avant} réacquis.")
            except (portalocker.LockException, BlockingIOError):
                # This means another process truly holds it, or our previous lock object is still active
                # and we didn't release it (portalocker locks are often process-specific)
                raise Exception(f"Verrou {lock_file_path_from_avant} est activement détenu par un autre processus/thread.")


        log_messages_update.append(f"API UPDATE: Connexion à {ip} pour la mise à jour...")
        connection_for_update = ConnectHandler(**update_device_details)
        if not AVANT_API.verifier_connexion(connection_for_update, log_messages_update):
            raise Exception("Échec de la vérification de la connexion avant la mise à jour.")
        
        log_messages_update.append("API UPDATE: Lancement de la procédure de mise à jour...")
        update_result = AVANT_API.run_update_procedure(connection_for_update, update_device_details, image_file, log_messages_update)
        
        # update_result might contain 'connection' if it's still alive
        returned_connection = update_result.get("connection")

        if update_result.get("status") == "success":
            # If APRES is to follow immediately, keep connection and lock
            # Otherwise, release them. For now, let's assume APRES is separate call.
            # The 'ident_data' is returned for the APRES call.
            # The lock remains. APRES will handle its release.
            update_result["ident_data"] = ident_data # Pass ident_data along
            update_result["logs"] = log_messages_update
            return jsonify(update_result)
        else: # Update failed
            update_result["logs"] = log_messages_update
            # Lock and connection cleaning in finally
            return jsonify(update_result), 500

    except Exception as e:
        error_msg = f"API UPDATE: Erreur majeure - {str(e)}"
        log_messages_update.append(error_msg)
        return jsonify({"status": "error", "message": error_msg, "logs": log_messages_update, "ident_data": ident_data}), 500
    finally:
        # Clean up connection established specifically for update if it's not the one returned
        if 'connection_for_update' in locals() and connection_for_update:
            if 'returned_connection' in locals() and connection_for_update == returned_connection:
                if not connection_for_update.is_alive(): # if returned but died
                    log_messages_update.append("API UPDATE: Connexion retournée par update est morte.")
            elif connection_for_update.is_alive(): # if not returned, clean it up
                connection_for_update.disconnect()
                log_messages_update.append("API UPDATE: Connexion locale pour MAJ fermée.")
        
        # If update fails badly or an exception occurs before lock release in run_update_procedure,
        # the lock file might persist. This 'finally' should try to release the lock object
        # acquired in *this* API endpoint's scope.
        if lock_for_update:
            AVANT_API.liberer_verrou(lock_for_update, lock_file_path_from_avant, log_messages_update)
            log_messages_update.append(f"API UPDATE: Verrou {lock_file_path_from_avant} libéré en sortie de l'API /run_update.")


@app.route('/api/run_apres', methods=['POST'])
def api_run_apres():
    data = request.json
    ident_data = data.get('ident_data') # Should come from AVANT (and persist through UPDATE)
    password = data.get('password')     # Router password
    log_messages_apres = []

    if not all([ident_data, password]):
        return jsonify({"status": "error", "message": "Ident_data and password are required."}), 400

    # The connection from a previous step (AVANT or UPDATE) might be passed.
    # For this stateless API design, APRES will establish its own connection for now.
    # Or, if stateful, API would manage and pass the live connection.
    # For simplicity, let's assume no live connection is passed from previous API call directly.
    # The 'run_apres_checks_and_compare' can take an optional 'avant_connection'.

    # The lock file path is in ident_data. APRES run should be the final step for this lock.
    lock_file_to_release_finally = ident_data.get('lock_file_path')
    lock_for_apres = None # Lock object for this scope

    try:
        # Acquire lock for APRES operation duration
        if lock_file_to_release_finally and os.path.exists(lock_file_to_release_finally):
            lock_for_apres = portalocker.Lock(lock_file_to_release_finally, flags=portalocker.LOCK_EX)
            try:
                lock_for_apres.acquire(timeout=0.1)
                log_messages_apres.append(f"API APRES: Verrou {lock_file_to_release_finally} acquis.")
            except (portalocker.LockException, BlockingIOError):
                 raise Exception(f"Verrou {lock_file_to_release_finally} est activement détenu (ne devrait pas si AVANT/UPDATE a libéré).")
        else: # If no lock file path from AVANT, something is wrong or it's a standalone APRES (not typical for flow)
            # For the defined flow, lock_file_path should always be there.
            # If not, we could try to lock again, but it implies a broken sequence.
            log_messages_apres.append(f"API APRES: Pas de fichier de verrouillage d'AVANT ({lock_file_to_release_finally}). Procédure potentiellement anormale.")
            # Let it proceed but it's a warning sign. run_apres_checks_and_compare might fail on file reads.

        # Pass the original ident_file_path so APRES can delete it
        ident_data["ident_file_path_from_avant_run"] = ident_data.get("ident_file_path") # if AVANT returned this key

        result = APRES_API.run_apres_checks_and_compare(ident_data, password, log_messages_apres, avant_connection=None)
        result["logs"] = log_messages_apres # Ensure logs are part of the response

        if result.get("status") == "error":
            return jsonify(result), 500
        return jsonify(result)

    except Exception as e:
        error_msg = f"API APRES: Erreur majeure - {str(e)}"
        log_messages_apres.append(error_msg)
        return jsonify({"status": "error", "message": error_msg, "logs": log_messages_apres}), 500
    finally:
        # APRES is the end of the line for this lock. Release it.
        if lock_for_apres: # If lock object was acquired in this scope
            AVANT_API.liberer_verrou(lock_for_apres, lock_file_to_release_finally, log_messages_apres)
            log_messages_apres.append(f"API APRES: Verrou {lock_file_to_release_finally} libéré en sortie de l'API /run_apres.")
        elif lock_file_to_release_finally and os.path.exists(lock_file_to_release_finally):
            # If lock_for_apres object wasn't made, but file exists, attempt removal (less clean)
            try:
                os.remove(lock_file_to_release_finally)
                log_messages_apres.append(f"API APRES: Fichier de verrou {lock_file_to_release_finally} supprimé (nettoyage final).")
            except Exception as e_del_lock_final:
                log_messages_apres.append(f"API APRES: Erreur nettoyage final fichier verrou {lock_file_to_release_finally}: {e_del_lock_final}")


@app.route('/api/unlock_router', methods=['POST'])
def api_unlock_router():
    data = request.json
    lock_file_path = data.get('lock_file_path')
    log_messages = []

    if not lock_file_path:
        return jsonify({"status": "error", "message": "lock_file_path is required."}), 400

    # We don't have the lock object here. Portalocker locks are typically released by the process
    # that acquired them using the lock object. Deleting the file is a more forceful way.
    if os.path.exists(lock_file_path):
        try:
            # Attempt to acquire and release to see if it's truly free, or just delete
            # For simplicity, just delete. The frontend calls this if a flow is abandoned.
            AVANT_API.liberer_verrou(None, lock_file_path, log_messages) # Will try to delete file
            msg = f"Tentative de libération/suppression du fichier de verrou {lock_file_path} effectuée."
            log_messages.append(msg)
            return jsonify({"status": "success", "message": msg, "logs": log_messages})
        except Exception as e:
            error_msg = f"Erreur lors de la tentative de suppression du fichier de verrou {lock_file_path}: {str(e)}"
            log_messages.append(error_msg)
            return jsonify({"status": "error", "message": error_msg, "logs": log_messages}), 500
    else:
        msg = f"Fichier de verrou {lock_file_path} non trouvé. Supposé déjà libéré."
        log_messages.append(msg)
        return jsonify({"status": "success", "message": msg, "logs": log_messages})


@app.route('/api/files', methods=['GET'])
def list_files():
    try:
        files = [f for f in os.listdir(GENERATED_FILES_DIR) if os.path.isfile(os.path.join(GENERATED_FILES_DIR, f))]
        return jsonify({"status": "success", "files": files})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/files/<filename>', methods=['GET'])
def get_file(filename):
    try:
        # Sanitize filename to prevent directory traversal
        if ".." in filename or filename.startswith("/"):
            return jsonify({"status": "error", "message": "Invalid filename."}), 400
        return send_from_directory(GENERATED_FILES_DIR, filename, as_attachment=False) # View in browser
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "File not found."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/files/<filename>', methods=['DELETE'])
def delete_file(filename):
    try:
        if ".." in filename or filename.startswith("/"): # Sanitize
            return jsonify({"status": "error", "message": "Invalid filename."}), 400
        
        file_path = os.path.join(GENERATED_FILES_DIR, filename)
        if os.path.exists(file_path):
            # Extra check: don't delete lock files via this generic endpoint
            if LOCK_DIR in os.path.abspath(file_path):
                 return jsonify({"status": "error", "message": "Cannot delete lock files via this endpoint."}), 403
            os.remove(file_path)
            return jsonify({"status": "success", "message": f"File {filename} deleted."})
        else:
            return jsonify({"status": "error", "message": "File not found."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    if not os.path.exists(GENERATED_FILES_DIR):
        os.makedirs(GENERATED_FILES_DIR)
    if not os.path.exists(LOCK_DIR):
        os.makedirs(LOCK_DIR)
    app.run(debug=True, host='0.0.0.0', port=5001) # Changed port to avoid conflict if React runs on 5000