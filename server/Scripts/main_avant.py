import os
import sys
import json
import time
from pathlib import Path
from getpass import getpass
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import tempfile
import subprocess

# Import from new modules
from locking_utils import verrouiller_routeur, liberer_verrou_et_fichier
from common_utils import (
    verifier_connexion,
    nettoyer_fichiers_disque,
    confirmation_box,
    valider_ip,
    stream_log
)
import juniper_data_collector as jdc
from importlib import import_module

# Import the perform_junos_update function
# Dynamically import all public functions from juniper_data_collector
from types import FunctionType
jdc_module = import_module('juniper_data_collector')
jdc_functions = [getattr(jdc_module, name) for name in dir(jdc_module)
                if isinstance(getattr(jdc_module, name), FunctionType) and not name.startswith('_')]

# List of function names in the desired order
JDC_FUNC_ORDER = [
    'collect_routing_engine_info',
    'collect_interface_info',
    'collect_arp_info',
    'collect_route_summary',
    'collect_ospf_info',
    'collect_isis_info',
    'collect_mpls_info',
    'collect_ldp_info',
    'collect_rsvp_info',
    'collect_lldp_info',
    'collect_lsp_info',
    'collect_bgp_info',
    'collect_system_services',
    'collect_configured_protocols',
    'collect_firewall_acls',
    'collect_critical_logs',
]

def run_all_jdc_collectors(connection, file_handle, structured_output_data, logs):
    """Call all jdc data collection functions in the correct order."""
    for func_name in JDC_FUNC_ORDER:
        func = getattr(jdc, func_name, None)
        if callable(func):
            func(connection, file_handle, structured_output_data, logs)

# Fonction pour lancer APRES.py (main_apres.py)
def lancer_apres(fichier_identifiants, logs, max_tentatives=3):
    tentatives = 0
    python_exec = sys.executable
    script_apres = os.path.join(os.path.dirname(__file__), "main_apres.py")
    while tentatives < max_tentatives:
        try:
            logs.append(f"\nLancement de main_apres.py")
            result = subprocess.run(
                [python_exec, "main_apres.py", fichier_identifiants],
                check=True,
            )
            return True 
        except subprocess.CalledProcessError as e:
            tentatives += 1
            logs.append(f"Erreur lors de l'exécution (Code {e.returncode}): {e.stderr.strip()}")
            if tentatives < max_tentatives:
                logs.append("Nouvelle tentative...")
            else:
                logs.append("Échec après plusieurs tentatives.")
                return False


def run_avant_workflow(ip, username, password, avant_logs=None):
    # --- Main script logic ---
    if not valider_ip(ip):
        avant_logs.append("Adresse IP invalide.")
        return {"status": "error", "message": "Adresse IP invalide.", "logs": avant_logs, "structured_data": {}}
    lock_obj = None
    lock_file_path_main = None
    connection = None
    fichiers_crees_main = []
    AVANT_file = None
    config_file_main = None
    identifiants_file_main = None
    if avant_logs is None:
        avant_logs = []
    structured_output_data = {
        "basic_info": {}, "routing_engine": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_info": "", "isis_info": "", "mpls_info": "",
        "ldp_info": "", "rsvp_info": "", "lldp_info": "", "lsp_info": "", "bgp_summary": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": "",
    }
    # Lock and connect
    script_dir = os.path.dirname(os.path.abspath(__file__))
    GENERATED_FILES_DIR = os.path.join(script_dir, "generated_files")
    Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)
    device_config = {
        'device_type': 'juniper_junos',
        'host': ip,
        'username': username,
        'password': password,
        'timeout': 60,
        'session_log': os.path.join(GENERATED_FILES_DIR, 'netmiko_session_avant.log'),
        'session_log_file_mode': 'append'
    }

    try:
        avant_logs.append(f"--- Début run_avant_checks pour {ip} ---")
        lock_acquired, attempted_lock_path = verrouiller_routeur(ip, avant_logs=avant_logs)
        lock_file_path = attempted_lock_path
        lock_file_path_main = lock_file_path
        if not lock_acquired:
            return {"status": "error", "message": f"Impossible de verrouiller le routeur {ip}. Voir logs.",
                    "lock_file_path": lock_file_path, "logs": avant_logs, "structured_data": structured_output_data}
        avant_logs.append(f"AVANT: Tentative de connexion à {ip}...")
        connection = ConnectHandler(**device_config)
        if verifier_connexion(connection):
            avant_logs.append(f"Connecté avec succès au routeur {ip}")
        else:
            avant_logs.append("Échec de la vérification de la connexion AVANT.")
            connection.disconnect()
            return {"status": "error", "message": "SSH connection verification failed.", "logs": avant_logs}
        with tempfile.NamedTemporaryFile(
            mode='w+',
            dir=GENERATED_FILES_DIR,
            prefix='AVANT_TEMP_',
            suffix='.txt',
            delete=False,
            encoding='utf-8'
        ) as temp_file_obj:
            fichier_temporaire_avant = temp_file_obj.name
        fichiers_crees_main.append(fichier_temporaire_avant)
        router_hostname_main = "inconnu"
        with open(fichier_temporaire_avant, 'w', encoding='utf-8') as file_handle_avant:
            router_hostname_main, _, _ = jdc.collect_basic_info(connection, file_handle_avant, structured_output_data=structured_output_data, logs=avant_logs)
            for func_name in [
                'collect_routing_engine_info',
                'collect_interface_info',
                'collect_arp_info',
                'collect_route_summary',
                'collect_ospf_info',
                'collect_isis_info',
                'collect_mpls_info',
                'collect_ldp_info',
                'collect_rsvp_info',
                'collect_lldp_info',
                'collect_lsp_info',
                'collect_bgp_info',
                'collect_system_services',
                'collect_configured_protocols',
                'collect_firewall_acls',
                'collect_critical_logs',
                'collect_full_configuration',
            ]:
                func = getattr(jdc, func_name, None)
                if callable(func):
                    if func_name == 'collect_full_configuration':
                        func(connection, file_handle_avant, structured_output_data, avant_logs, username, router_hostname_main)
                    else:
                        func(connection, file_handle_avant, structured_output_data, avant_logs)
        base_avant_filename = f"AVANT_{username}_{router_hostname_main}.txt"
        AVANT_file = os.path.join(GENERATED_FILES_DIR, base_avant_filename)
        compteur = 1
        while os.path.exists(AVANT_file):
            AVANT_file = os.path.join(GENERATED_FILES_DIR, f"AVANT_{username}_{router_hostname_main}_{compteur}.txt")
            compteur += 1
        try:
            os.replace(fichier_temporaire_avant, AVANT_file)
            avant_logs.append(f"Fichier temporaire AVANT renommé en : {AVANT_file}")
            fichiers_crees_main.remove(fichier_temporaire_avant)
            fichiers_crees_main.append(AVANT_file)
        except Exception as e:
            avant_logs.append(f"Erreur lors du renommage du fichier temporaire AVANT : {e}")
            AVANT_file = fichier_temporaire_avant
        identifiants_base_name = f"identifiants_{username}_{router_hostname_main}.json"
        identifiants_file_main = os.path.join(GENERATED_FILES_DIR, identifiants_base_name)
        compteur_id = 1
        while os.path.exists(identifiants_file_main):
            identifiants_file_main = os.path.join(GENERATED_FILES_DIR, f"identifiants_{username}_{router_hostname_main}_{compteur_id}.json")
            compteur_id += 1
        try:
            identifiants_data = {
                "ip": ip,
                "username": username,
                "router_hostname": router_hostname_main,
                "lock_file_path": lock_file_path_main,
                "avant_file_path": AVANT_file,
                "config_file_path": config_file_main,
                "ident_file_path": identifiants_file_main,
                "device_details_for_update": device_config
            }
            with open(identifiants_file_main, 'w', encoding='utf-8') as f_ident:
                json.dump(identifiants_data, f_ident, indent=2)
            avant_logs.append(f"Fichier d'identifiants sauvegardé : {identifiants_file_main}")
            fichiers_crees_main.append(identifiants_file_main)
        except Exception as e:
            avant_logs.append(f"Erreur lors de la sauvegarde du fichier d'identifiants : {e}")
        return {
            "status": "success", "message": "Vérifications AVANT terminées.",
            "ident_data": identifiants_data, "ident_file_path": identifiants_file_main,
            "avant_file_path": AVANT_file,
            "config_file_path": config_file_main,
            "lock_file_path": lock_file_path_main,
            "connection_obj": connection,
            "structured_data": structured_output_data,
            "log_messages": avant_logs,
            "device_details_for_update": device_config
        }
    except Exception as e_generic:
        import traceback
        error_msg = f"AVANT Erreur majeure dans run_avant_checks: {str(e_generic)} (Type: {type(e_generic).__name__})"
        avant_logs.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        for key_data_error in structured_output_data:
            pass
        return {
            "status": "error", "message": error_msg,
            "lock_file_path": lock_file_path,
            "fichiers_crees": fichiers_crees_main,
            "structured_data": structured_output_data,
            "log_messages": avant_logs,
            "connection_obj": connection
        }
    finally:
        if connection:
            try:
                connection.disconnect()
                avant_logs.append(f"Déconnexion de la session SSH (AVANT)... Session SSH (AVANT) déconnectée.")
            except Exception as e:
                avant_logs.append(f"Erreur lors de la fermeture de la connexion SSH: {e}")
        # Always release the lock if acquired
        if lock_file_path_main:
            try:
                liberer_verrou_et_fichier(lock_file_path_main, avant_logs)
                avant_logs.append(f"Verrou sur le routeur {ip} libéré (AVANT).")
            except Exception as e:
                avant_logs.append(f"Erreur lors de la libération du verrou AVANT: {e}")

