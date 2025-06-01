import os
import sys
import json
import glob
from getpass import getpass
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import tempfile
from pathlib import Path

from common_utils import (
    verifier_connexion,
    valider_ip,
    read_file_by_line,
    extract_sections,
    compare_sections,
    display_differences,
    write_differences_to_file,
    nettoyer_fichiers_disque,
    confirmation_box,
    stream_log
)
import juniper_data_collector as jdc

def run_apres_workflow(avant_ident_file, apres_logs, password_apres):
    if apres_logs is None:
        apres_logs = []
    connection_apres = None
    fichiers_crees_apres = []
    APRES_file_path = None
    identifiants_data = {}
    structured_output_data = {
        "basic_info": {}, "routing_engine": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_info": "", "isis_info": "", "mpls_info": "",
        "ldp_info": "", "rsvp_info": "", "lldp_info": "", "lsp_info": "", "bgp_summary": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": "",
    }
    try:
        # --- File selection logic (keep APRES-specific) ---
        selected_ident_file = avant_ident_file
        if not selected_ident_file:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            GENERATED_FILES_DIR = os.path.join(script_dir, "generated_files")
            Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)
            if not os.access(GENERATED_FILES_DIR, os.W_OK):
                apres_logs.append(f"APRES CRITIQUE: Pas d'accès en écriture à GENERATED_FILES_DIR ({GENERATED_FILES_DIR})!")
                return {"status": "error", "message": "No write access to generated_files.", "logs": apres_logs}
            list_of_files = glob.glob(os.path.join(GENERATED_FILES_DIR, "identifiants_*.json"))
            if not list_of_files:
                apres_logs.append("ERREUR: Aucun fichier d'identification (identifiants_*.json) trouvé. Exécutez main_avant.py d'abord.")
                return {"status": "error", "message": "No identifiants file found.", "logs": apres_logs}
            if len(list_of_files) > 1:
                apres_logs.append("Plusieurs fichiers d'identification trouvés:")
                for i, file_path_id in enumerate(list_of_files):
                    try:
                        with open(file_path_id, "r") as f_peek:
                            data_peek = json.load(f_peek)
                        apres_logs.append(f"  {i+1}. {os.path.basename(file_path_id)} (IP: {data_peek.get('ip', 'N/A')}, User: {data_peek.get('username', 'N/A')})")
                    except Exception:
                        apres_logs.append(f"  {i+1}. {os.path.basename(file_path_id)} (Impossible de lire les détails)")
                selected_ident_file = max(list_of_files, key=os.path.getctime)
            else:
                selected_ident_file = list_of_files[0]
                print(selected_ident_file)
        apres_logs.append(f"Utilisation du fichier d'identifiants : {selected_ident_file}")
        with open(selected_ident_file, "r", encoding='utf-8') as f_id_load:
            identifiants_data = json.load(f_id_load)
        ip_apres = identifiants_data.get("ip")
        username_apres = identifiants_data.get("username")
        AVANT_file_from_id = identifiants_data.get("avant_file_path")
        config_file_from_id = identifiants_data.get("config_file_path")
        print(ip_apres, username_apres, 
        AVANT_file_from_id, config_file_from_id)
        if not all([ip_apres, username_apres, AVANT_file_from_id]):
            apres_logs.append("Fichier d'identifiants incomplet ou corrompu (IP, username, AVANT_file manquants).")
            return {"status": "error", "message": "Identifiants file incomplete.", "logs": apres_logs}
        if not valider_ip(ip_apres):
            apres_logs.append("Adresse IP invalide dans le fichier d'identifiants.")
            return {"status": "error", "message": "Invalid IP in identifiants file.", "logs": apres_logs}
        if not os.path.exists(AVANT_file_from_id):
            apres_logs.append(f"Le fichier AVANT '{AVANT_file_from_id}' spécifié dans les identifiants est introuvable.")
            return {"status": "error", "message": "AVANT file not found.", "logs": apres_logs}
        if not password_apres:
            apres_logs.append("Erreur: Aucun mot de passe fourni dans les identifiants ou la session. Impossible de continuer.")
            return {"status": "error", "message": "No password provided for APRES connection.", "logs": apres_logs}
        device_config_apres = {
            'device_type': 'juniper_junos',
            'host': ip_apres,
            'username': username_apres,
            'password': password_apres,
            'timeout': 60,
            'session_log': os.path.join(os.path.dirname(selected_ident_file), 'netmiko_session_apres.log'),
            'session_log_file_mode': 'append'
        }
        try:
            apres_logs.append(f"\nTentative de connexion à {ip_apres} pour les vérifications APRES...")
            connection_apres = ConnectHandler(**device_config_apres)
            if verifier_connexion(connection_apres):
                apres_logs.append(f"Connecté avec succès au routeur {ip_apres} pour APRES.")
            else:
                apres_logs.append("Échec de la vérification de la connexion APRES.")
                connection_apres.disconnect()
                return {"status": "error", "message": "SSH connection verification failed.", "logs": apres_logs}
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as conn_err_apres:
            apres_logs.append(f"Erreur de connexion Netmiko (APRES) : {str(conn_err_apres)}")
            return {"status": "error", "message": "SSH connection failed.", "logs": apres_logs}
        except Exception as e_conn_apres:
            apres_logs.append(f"Échec de la connexion APRES : {str(e_conn_apres)}")
            return {"status": "error", "message": "SSH connection failed.", "logs": apres_logs}
        # --- Data collection (generator/yield style) ---
        script_dir = os.path.dirname(os.path.abspath(__file__))
        GENERATED_FILES_DIR = os.path.join(script_dir, "generated_files")
        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)
        with tempfile.NamedTemporaryFile(
            mode='w+',
            dir=GENERATED_FILES_DIR,
            prefix='APRES_TEMP_',
            suffix='.txt',
            delete=False,
            encoding='utf-8'
        ) as temp_file_obj_apres:
            fichier_temporaire_apres = temp_file_obj_apres.name
        fichiers_crees_apres.append(fichier_temporaire_apres)
        router_hostname_apres = "inconnu"
        with open(fichier_temporaire_apres, 'w', encoding='utf-8') as file_handle_apres:
            router_hostname_apres, _, _ = jdc.collect_basic_info(connection_apres, file_handle_apres, structured_output_data=structured_output_data, logs=apres_logs)
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
                'collect_full_configuration', # APRES: config is in APRES file
            ]:
                func = getattr(jdc, func_name, None)
                if callable(func):
                    if func_name == 'collect_full_configuration':
                        func(connection_apres, file_handle_apres, structured_output_data, apres_logs, username_apres, router_hostname_apres)
                    else:
                        func(connection_apres, file_handle_apres, structured_output_data, apres_logs)
        # Rename APRES file
        base_apres_filename = f"APRES_{username_apres}_{router_hostname_apres}.txt"
        APRES_file_path = os.path.join(GENERATED_FILES_DIR, base_apres_filename)
        compteur_apres = 1
        while os.path.exists(APRES_file_path):
            APRES_file_path = os.path.join(GENERATED_FILES_DIR, f"APRES_{username_apres}_{router_hostname_apres}_{compteur_apres}.txt")
            compteur_apres += 1
        try:
            os.replace(fichier_temporaire_apres, APRES_file_path)
            apres_logs.append(f"Fichier temporaire APRES renommé en : {APRES_file_path}")
            fichiers_crees_apres.remove(fichier_temporaire_apres)
            fichiers_crees_apres.append(APRES_file_path)
        except Exception as e_rename_apres:
            apres_logs.append(f"Erreur lors du renommage du fichier temporaire APRES : {e_rename_apres}")
            APRES_file_path = fichier_temporaire_apres
        apres_logs.append("\n--- Lancement de la comparaison AVANT vs APRES ---")
        content_avant_gen = read_file_by_line(AVANT_file_from_id, apres_logs)
        content_apres_gen = read_file_by_line(APRES_file_path, apres_logs)
        sections_avant_data = extract_sections(content_avant_gen, apres_logs)
        sections_apres_data = extract_sections(content_apres_gen, apres_logs)
        if not sections_avant_data and os.path.exists(AVANT_file_from_id):
            apres_logs.append(f"AVERTISSEMENT: Aucune section n'a pu être extraite de {AVANT_file_from_id}. Le fichier est-il vide ou mal formaté?")
        if not sections_apres_data and os.path.exists(APRES_file_path):
            apres_logs.append(f"AVERTISSEMENT: Aucune section n'a pu être extraite de {APRES_file_path}. Le fichier est-il vide ou mal formaté?")
        if not sections_avant_data and not sections_apres_data:
            apres_logs.append("Erreur critique: Impossible d'extraire des sections des fichiers AVANT et APRES. Comparaison impossible.")
        else:
            differences_data = compare_sections(sections_avant_data, sections_apres_data, apres_logs)
            if not isinstance(differences_data, dict):
                # Exhaust the generator to log the error, then set to empty dict
                list(differences_data)
                differences_data = {}
            display_differences(differences_data, apres_logs)
            comparaison_filename_base = f"COMPARAISON_{username_apres}_{router_hostname_apres}.txt"
            comparaison_filename = os.path.join(GENERATED_FILES_DIR, comparaison_filename_base)
            compteur_comp = 1
            while os.path.exists(comparaison_filename):
                comparaison_filename = os.path.join(GENERATED_FILES_DIR, f"COMPARAISON_{username_apres}_{router_hostname_apres}_{compteur_comp}.txt")
                compteur_comp += 1
            write_differences_to_file(differences_data, comparaison_filename, apres_logs)
            fichiers_crees_apres.append(comparaison_filename)
        return {
            "status": "success",
            "message": "Vérifications APRES terminées.",
            "apres_file_path": APRES_file_path,
            "structured_data": structured_output_data,
            "logs": apres_logs,
            "fichiers_crees": fichiers_crees_apres,
            "comparison_file": comparaison_filename if 'comparaison_filename' in locals() else None,
            "comparison_result": (open(comparaison_filename, encoding='utf-8').read() if 'comparaison_filename' in locals() and os.path.exists(comparaison_filename) else None)
        }
    except Exception as e_main_apres:
        import traceback
        error_msg = f"APRES Erreur majeure dans run_apres_workflow: {str(e_main_apres)} (Type: {type(e_main_apres).__name__})"
        apres_logs.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        return {"status": "error", "message": error_msg, "logs": apres_logs, "structured_data": structured_output_data}
    finally:
        if connection_apres:
            try:
                connection_apres.disconnect()
                apres_logs.append(f"Déconnexion de la session SSH (APRES)... Session SSH (APRES) déconnectée.")
            except Exception as e:
                apres_logs.append(f"Erreur lors de la fermeture de la connexion SSH: {e}")
        # APRES-specific: Cleanup prompts for files (optional, can be handled by caller)
        # ...existing code for cleanup...