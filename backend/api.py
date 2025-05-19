import os
import sys
import subprocess
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import re
from pathlib import Path

app = Flask(__name__)
CORS(app)

# --- Configuration ---
# Directory where app.py is located
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__)) # C:\...\router_updater\web_app\backend

# Directory where AVANT.py and APRES.py scripts are located
# This goes up two levels from BACKEND_DIR: backend -> web_app -> router_updater
SCRIPTS_DIR = os.path.abspath(os.path.join(BACKEND_DIR, "..", ".."))
# SCRIPTS_DIR should now be C:\...\router_updater

PYTHON_EXEC = sys.executable # Path to current python interpreter (the one running Flask)

# Directory to store generated files (AVANT, APRES, CONFIG, JSON reports)
# These files will be created by AVANT.py/APRES.py in SCRIPTS_DIR
REPORTS_DIR = SCRIPTS_DIR

# Create router_locks directory if it doesn't exist, relative to SCRIPTS_DIR
# (AVANT.py will look for router_locks in its own directory, which is SCRIPTS_DIR)
Path(os.path.join(SCRIPTS_DIR, "router_locks")).mkdir(exist_ok=True, parents=True)

# ... rest of your app.py code ...

# In your run_script function, ensure cwd is SCRIPTS_DIR for the scripts
def run_script(script_name, args_list):
    """Helper function to run a Python script and capture its output."""
    # Construct the full path to the script
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    cmd = [PYTHON_EXEC, script_path] + args_list # PYTHON_EXEC defined above
    try:
        # Run the script with its working directory set to SCRIPTS_DIR
        # This ensures AVANT.py/APRES.py can find 'router_locks' and save files correctly.
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=SCRIPTS_DIR)
        stdout, stderr = process.communicate(timeout=7200) # Long timeout for updates (2 hours)
        
        # Try to find key file paths from stdout
        identifiants_file = re.search(r"IDENTIFIANT_FILE_PATH:(.*)", stdout)
        avant_file = re.search(r"AVANT_FILE_PATH:(.*)", stdout) # Add this print in AVANT.py if needed
        apres_file = re.search(r"APRES_FILE_PATH:(.*)", stdout)   # Add this print in APRES.py if needed
        comparison_file = re.search(r"COMPARISON_FILE_PATH:(.*)", stdout)

        result = {
            "stdout": stdout,
            "stderr": stderr,
            "returncode": process.returncode,
            "identifiants_file": identifiants_file.group(1).strip() if identifiants_file else None,
            "avant_file": avant_file.group(1).strip() if avant_file else None,
            "apres_file": apres_file.group(1).strip() if apres_file else None,
            "comparison_file": comparison_file.group(1).strip() if comparison_file else None,
        }
        return result
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return {
            "stdout": stdout,
            "stderr": stderr + "\nERROR: Script execution timed out.",
            "returncode": -1, # Custom timeout code
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Failed to run script {script_name}: {str(e)}",
            "returncode": -2, # Custom execution failure
        }

@app.route('/api/avant/pre-checks', methods=['POST'])
def avant_pre_checks():
    data = request.json
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')

    if not all([ip, username, password]):
        return jsonify({"error": "Missing IP, username, or password"}), 400

    args = [
        "--ip", ip,
        "--username", username,
        "--password", password,
        "--mode", "pre_checks"
    ]
    result = run_script("AVANT.py", args)

    if result["returncode"] == 0:
        return jsonify({
            "message": "AVANT.py pre-checks completed.",
            "output": result["stdout"] + "\n" + result["stderr"],
            "identifiants_file": result["identifiants_file"] # This is crucial
        }), 200
    elif result["returncode"] == 10: # Specific exit code for lock failure from AVANT.py
        return jsonify({
            "error": "Router is locked by another process.",
            "details": result["stdout"] + "\n" + result["stderr"]
        }), 409 # Conflict
    else:
        return jsonify({
            "error": "AVANT.py pre-checks failed.",
            "details": result["stdout"] + "\n" + result["stderr"]
        }), 500

@app.route('/api/avant/run-update', methods=['POST'])
def avant_run_update():
    data = request.json
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')
    image_file = data.get('image_file') # e.g., jinstall-ppc-VERSION-signed.tgz

    if not all([ip, username, password, image_file]):
        return jsonify({"error": "Missing IP, username, password, or image_file"}), 400

    args = [
        "--ip", ip,
        "--username", username,
        "--password", password,
        "--mode", "update",
        "--image-file", image_file,
        "--assume-yes" # Important for non-interactive update confirmations
    ]
    result = run_script("AVANT.py", args)

    if result["returncode"] == 0:
        # The update process itself might generate more output and potentially a new identifiants file if it re-runs that part.
        # For simplicity, we assume the initial identifiants_file is still relevant or the script handles it.
        return jsonify({
            "message": "AVANT.py update process initiated/completed.",
            "output": result["stdout"] + "\n" + result["stderr"],
            "identifiants_file": result["identifiants_file"] # If AVANT.py re-prints it
        }), 200
    elif result["returncode"] == 10:
         return jsonify({"error": "Router is locked by another process.", "details": result["stdout"] + "\n" + result["stderr"]}), 409
    else:
        return jsonify({
            "error": "AVANT.py update process failed.",
            "details": result["stdout"] + "\n" + result["stderr"]
        }), 500

@app.route('/api/apres/run-checks', methods=['POST'])
def apres_run_checks():
    data = request.json
    identifiants_file_name = data.get('identifiants_file') # This should be the FILENAME, not the full path from client
    password = data.get('password')
    auto_cleanup = data.get('auto_cleanup', False) # Default to no auto cleanup

    if not all([identifiants_file_name, password]):
        return jsonify({"error": "Missing identifiants_file name or password"}), 400

    # Construct the full path on the server
    # IMPORTANT: Sanitize identifiants_file_name to prevent path traversal if it's user-controlled
    # For now, assume it's just the basename from a trusted source (previous API call)
    identifiants_file_path = os.path.join(REPORTS_DIR, os.path.basename(identifiants_file_name))

    if not os.path.exists(identifiants_file_path):
        return jsonify({"error": f"Identifiants file not found on server: {identifiants_file_path}"}), 404

    args = [
        identifiants_file_path, # Positional argument for APRES.py
        "--password", password
    ]
    if auto_cleanup:
        args.append("--auto-cleanup")

    result = run_script("APRES.py", args)

    if result["returncode"] == 0:
        response_data = {
            "message": "APRES.py checks completed.",
            "output": result["stdout"] + "\n" + result["stderr"],
            "comparison_file": result["comparison_file"] # Path to comparison file
        }
        # Optionally, read and include comparison file content
        if result["comparison_file"] and os.path.exists(result["comparison_file"]):
            try:
                with open(result["comparison_file"], 'r', encoding='utf-8') as f_comp:
                    response_data["comparison_content"] = f_comp.read()
            except Exception as e:
                response_data["comparison_content_error"] = str(e)
        
        return jsonify(response_data), 200
    else:
        return jsonify({
            "error": "APRES.py checks failed.",
            "details": result["stdout"] + "\n" + result["stderr"]
        }), 500

@app.route('/api/files/<path:filename>', methods=['GET'])
def get_file(filename):
    # SECURITY: Ensure this only serves files from a known, safe directory.
    # os.path.basename is a weak protection. A better approach is to check
    # if os.path.abspath(os.path.join(REPORTS_DIR, filename)).startswith(os.path.abspath(REPORTS_DIR))
    safe_path = os.path.abspath(os.path.join(REPORTS_DIR, filename))
    if not safe_path.startswith(os.path.abspath(REPORTS_DIR)):
        return jsonify({"error": "Access denied"}), 403
    
    try:
        return send_from_directory(REPORTS_DIR, filename, as_attachment=False) # as_attachment=True to download
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404

if __name__ == '__main__':
    # Make sure REPORTS_DIR exists if scripts don't create it fully
    Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5001) # Port 5001 for backend