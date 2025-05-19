import os
import sys
import json
import glob
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import ipaddress
import tempfile
import chardet
import unicodedata
from collections import OrderedDict
import portalocker # CRITICAL: Ensure this import is present
from pathlib import Path

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

# --- Helper Functions (valider_ip_apres, verifier_connexion_apres etc. from last full version) ---
# Assuming parse_interfaces_structured is available (e.g., imported from AVANT_API or duplicated)
# For simplicity if running standalone, let's duplicate a simplified version or import.
# To keep APRES_API self-contained for this example, let's use a placeholder or import from AVANT_API.
# from AVANT_API import parse_interfaces_structured (This is cleaner if AVANT_API is in PYTHONPATH)
# For now, let's assume a similar function would exist or be imported. For brevity, I'll omit its full code here again.
# The `parse_interfaces_structured` from AVANT_API.py would be used.

def valider_ip_apres(ip):
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

def verifier_connexion_apres(connection, log_messages):
    try:
        output = connection.send_command("show system uptime", read_timeout=15)
        if "error" in output.lower() or not output.strip():
            log_messages.append(f"ERREUR APRES: Problème de communication (uptime): '{output if output else 'No output'}'")
            return False
        log_messages.append(f"Connexion APRES vérifiée (uptime): {output.strip().splitlines()[0] if output.strip() else 'OK'}")
        return True
    except Exception as e:
        log_messages.append(f"ERREUR APRES: Connexion (exception uptime): {str(e)}")
        return False

# normalize_text, detect_encoding, read_file_by_line, extract_sections from previous APRES_API full version
def normalize_text(text):
    try:
        if isinstance(text, list): return [normalize_text(line) for line in text]
        if not isinstance(text, str): text = str(text)
        return unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII').lower()
    except: return str(text)

def detect_encoding(file_path):
    try:
        with open(file_path, 'rb') as f: raw = f.read(1024); return chardet.detect(raw)['encoding'] or 'utf-8'
    except: return 'utf-8'

def read_file_by_line(file_path, log_messages):
    try:
        enc = detect_encoding(file_path)
        with open(file_path, 'r', encoding=enc, errors='replace') as f:
            for line in f: yield line.rstrip('\n')
    except FileNotFoundError: log_messages.append(f"Fichier {file_path} non trouvé."); yield None
    except Exception as e: log_messages.append(f"Erreur lecture {file_path}: {e}"); yield None

def extract_sections(file_gen, log_messages):
    sections = OrderedDict(); current_section = None
    try:
        for line in file_gen:
            if line is None: continue
            stripped = line.strip()
            if stripped.endswith(" :") and len(stripped) < 100: current_section = stripped; sections[current_section] = []
            elif current_section: sections[current_section].append(stripped)
    except Exception as e: log_messages.append(f"Erreur extraction sections: {e}")
    return sections

# compare_sections and format_differences_for_report modified to produce structured diffs
def compare_sections_structured(sections_avant, sections_apres, log_messages):
    structured_differences = OrderedDict()
    all_section_keys = sorted(list(set(sections_avant.keys()) | set(sections_apres.keys())))

    for section_key in all_section_keys:
        content_avant_orig = sections_avant.get(section_key, [])
        content_apres_orig = sections_apres.get(section_key, [])
        
        norm_avant = set(normalize_text(content_avant_orig))
        norm_apres = set(normalize_text(content_apres_orig))

        current_diff = {"section_title": section_key, "lines_removed": [], "lines_added": [], "status": "Identique"}

        if norm_avant != norm_apres:
            current_diff["status"] = "Modifié"
            # Lines in AVANT (normalized) not in APRES (normalized) -> considered removed
            current_diff["lines_removed"] = [line for line in content_avant_orig if normalize_text(line) not in norm_apres]
            # Lines in APRES (normalized) not in AVANT (normalized) -> considered added
            current_diff["lines_added"] = [line for line in content_apres_orig if normalize_text(line) not in norm_avant]
            
            if not current_diff["lines_removed"] and not current_diff["lines_added"]:
                 # This can happen if only whitespace or case differences existed, and norm fixed it,
                 # but the initial norm_avant != norm_apres check passed due to subtle normalization artifacts.
                 # Or if one section was present and other absent.
                 if not content_avant_orig and content_apres_orig: current_diff["status"] = "Nouveau"
                 elif content_avant_orig and not content_apres_orig: current_diff["status"] = "Supprimé"
                 else: current_diff["status"] = "Modifié (subtil)" # Or back to Identique if truly no diffs found by line comparison

        structured_differences[section_key] = current_diff
    log_messages.append(f"Comparaison structurée terminée pour {len(all_section_keys)} sections.")
    return structured_differences


def run_apres_checks_and_compare(ident_data, password, log_messages, avant_connection=None):
    # ... (Initial validation of ident_data - same as last full APRES_API version) ...
    ip = ident_data.get("ip")
    username = ident_data.get("username")
    avant_file_to_compare = ident_data.get("avant_file_path") # Actual AVANT data file
    router_hostname = ident_data.get("router_hostname", "inconnu") # From AVANT run

    if not all([ip, username, avant_file_to_compare]):
        msg = "Données d'identification APRES incomplètes."
        log_messages.append(msg)
        return {"status": "error", "message": msg, "logs": log_messages, "structured_data": {}, "comparison_results": {}}
    if not os.path.exists(avant_file_to_compare):
        msg = f"Fichier AVANT ({avant_file_to_compare}) non trouvé pour comparaison APRES."
        log_messages.append(msg)
        return {"status": "error", "message": msg, "logs": log_messages, "structured_data": {}, "comparison_results": {}}

    fichiers_crees_apres = []
    connection = avant_connection 
    apres_file_path_internal = None
    comparison_file_path = None
    
    structured_output_data_apres = { # Similar to AVANT's structure
        "basic_info": {}, "routing_engine": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_info": "", "isis_info": "", "mpls_info": "",
        "ldp_info": "", "rsvp_info": "", "lldp_info": "", "lsp_info": "", "bgp_summary": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": ""
    }

    try:
        log_messages.append(f"--- Début run_apres_checks_and_compare pour {ip} ---")
        if connection is None or not connection.is_alive():
            # ... (Connection logic same as last full APRES_API version) ...
            if connection is not None: log_messages.append("Connexion fournie pour APRES non active. Reconnexion.")
            try: connection.disconnect()
            except: pass
            device = {'device_type': 'juniper', 'host': ip, 'username': username, 'password': password, 'timeout': 30}
            log_messages.append(f"APRES: Tentative de connexion à {ip}..."); connection = ConnectHandler(**device)
            log_messages.append(f"APRES: Connecté succès à {ip}")
        else:
            log_messages.append("APRES: Utilisation de la connexion existante.")

        if not verifier_connexion_apres(connection, log_messages):
            raise Exception("APRES: Vérification de la connexion post-établissement échouée.")

        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True) # Ensure dir
        if not os.access(GENERATED_FILES_DIR, os.W_OK):
            raise PermissionError(f"APRES: Pas d'accès écriture à {GENERATED_FILES_DIR}")

        temp_apres_file_obj = tempfile.NamedTemporaryFile(
            mode='w+', prefix='APRES_', suffix='.txt', delete=False, encoding='utf-8', dir=GENERATED_FILES_DIR)
        apres_file_path_internal = temp_apres_file_obj.name
        log_messages.append(f"Fichier APRES temporaire: {apres_file_path_internal}")
        fichiers_crees_apres.append(apres_file_path_internal)

        # --- Collect APRES data (similar structure to AVANT's collection) ---
        # Section: Basic Info (APRES)
        structured_output_data_apres["basic_info"]["section_title"] = "Informations de base du routeur (APRES)"
        temp_apres_file_obj.write(f"{structured_output_data_apres['basic_info']['section_title']}:\n")
        out_ver_apres = connection.send_command('show version')
        j_ver_ap, r_model_ap = "inconnu", "inconnu"; cur_host_ap = router_hostname # Default to original hostname
        for l in out_ver_apres.splitlines():
            if l.startswith("Hostname:"): cur_host_ap = l.split("Hostname:")[1].strip()
            elif l.startswith("Model:"): r_model_ap = l.split("Model:")[1].strip()
            elif l.startswith("Junos:"): j_ver_ap = l.split("Junos:")[1].strip()
        structured_output_data_apres["basic_info"]["hostname"] = cur_host_ap
        structured_output_data_apres["basic_info"]["model"] = r_model_ap
        structured_output_data_apres["basic_info"]["junos_version"] = j_ver_ap
        temp_apres_file_obj.write(f"  Hostname: {cur_host_ap}\n  Modèle: {r_model_ap}\n  Version Junos: {j_ver_ap}\n")
        log_messages.append(f"APRES Basic Info: Host={cur_host_ap}, Model={r_model_ap}, Junos={j_ver_ap}")

        temp_apres_file_obj.flush()
        temp_apres_file_obj.close()
        if not os.path.exists(apres_file_path_internal):
            raise FileNotFoundError(f"Disparition critique fichier temporaire APRES: {apres_file_path_internal}")

        final_apres_base = f"APRES_{username}_{router_hostname}.txt" # Use original hostname for consistency
        final_apres_path = os.path.join(GENERATED_FILES_DIR, final_apres_base)
        # ... (Renaming logic for APRES file, similar to AVANT) ...
        compteur_ap = 1
        while os.path.exists(final_apres_path):
            final_apres_path = os.path.join(GENERATED_FILES_DIR, f"APRES_{username}_{router_hostname}_{compteur_ap}.txt"); compteur_ap+=1
        try:
            os.replace(apres_file_path_internal, final_apres_path)
            log_messages.append(f"Fichier APRES renommé en: {final_apres_path}")
            if apres_file_path_internal in fichiers_crees_apres: fichiers_crees_apres.remove(apres_file_path_internal)
            apres_file_path_internal = final_apres_path # Update to final path
            if apres_file_path_internal not in fichiers_crees_apres: fichiers_crees_apres.append(apres_file_path_internal)
        except OSError as e_rep_ap:
            log_messages.append(f"ERREUR renommage APRES: {e_rep_ap}. Utilisation du nom temporaire: {apres_file_path_internal}")


        with open(apres_file_path_internal, 'a', encoding='utf-8') as file_ap:
            file_ap.write("\n--- Collecte APRES étendue ---\n")
            # Use a similar fetch_and_store or direct collection for all sections as in AVANT_API
            # For brevity, I'll show a couple and assume the rest follow the pattern.
            # Ensure you import or define parse_interfaces_structured if used here.
            # from AVANT_API import parse_interfaces_structured
            
            # Example: Routing Engine
            title_re_ap = "Informations du moteur de routage (APRES)"
            cmd_re_ap = "show chassis routing-engine"
            if not verifier_connexion_apres(connection, log_messages): raise Exception(f"Connexion perdue avant: {title_re_ap}")
            log_messages.append(f"Récupération APRES: {title_re_ap}")
            file_ap.write(f"\n{title_re_ap}:\n")
            out_re_ap = connection.send_command(cmd_re_ap)
            structured_output_data_apres["routing_engine"] = out_re_ap
            file_ap.write(out_re_ap + "\n")
            log_messages.append(f"OK APRES: {title_re_ap}")

            # Example: Interfaces (APRES) - This would use parse_interfaces_structured
            title_if_ap = "Informations sur les interfaces (APRES)"
            if not verifier_connexion_apres(connection, log_messages): raise Exception(f"Connexion perdue avant: {title_if_ap}")
            log_messages.append(f"Récupération APRES: {title_if_ap}")
            file_ap.write(f"\n{title_if_ap}:\n")
            # up_list_ap, down_list_ap = parse_interfaces_structured(...) # Full call
            # structured_output_data_apres["interfaces_up"] = up_list_ap
            # structured_output_data_apres["interfaces_down"] = down_list_ap
            # ... (write to file_ap) ...
            # For now, simplified:
            terse_ap = connection.send_command("show interfaces terse | no-more")
            file_ap.write("--- TERSE (APRES) ---\n" + terse_ap + "\n")
            structured_output_data_apres["interfaces_terse_apres"] = terse_ap # Store raw for now
            log_messages.append(f"OK APRES: {title_if_ap} (terse only for brevity)")

            # ... (Collect ALL other sections for APRES into structured_output_data_apres and file_ap) ...
            # Make sure to fill all keys in structured_output_data_apres

        # --- Comparaison ---
        log_messages.append(f"\nLancement de la comparaison structurée entre AVANT et APRES...")
        # avant_data_for_comparison is the structured_data from the AVANT run.
        # This needs to be passed to this function if comparison is done here.
        # For API flow, the API endpoint would fetch AVANT file, parse it, then call this.
        # OR, this function reads the AVANT file. Let's assume reading AVANT file:
        
        avant_data_file_content_gen = read_file_by_line(avant_file_to_compare, log_messages)
        sections_from_avant_file = extract_sections(avant_data_file_content_gen, log_messages)
        # For a true structured comparison, we'd need to re-parse sections_from_avant_file
        # into the same structure as structured_output_data_apres.
        # This is complex. A simpler file-based diff is what was originally done.
        # The new `compare_sections_structured` will compare these file-extracted sections.

        apres_data_file_content_gen = read_file_by_line(apres_file_path_internal, log_messages)
        sections_from_apres_file = extract_sections(apres_data_file_content_gen, log_messages)
        
        comparison_results_structured = compare_sections_structured(sections_from_avant_file, sections_from_apres_file, log_messages)

        # Save comparison report to file (textual)
        comp_base_name = f"COMPARAISON_{username}_{router_hostname}.txt"
        comparison_file_path = os.path.join(GENERATED_FILES_DIR, comp_base_name)
        # ... (collision check for comparison_file_path) ...
        comp_counter = 1
        while os.path.exists(comparison_file_path):
            comparison_file_path = os.path.join(GENERATED_FILES_DIR, f"COMPARAISON_{username}_{router_hostname}_{comp_counter}.txt"); comp_counter+=1

        # format_differences_for_report needs to be adapted if using structured_differences
        # For now, let's write a JSON dump of the structured diff to the file for inspection.
        with open(comparison_file_path, 'w', encoding='utf-8') as f_comp:
            json.dump(comparison_results_structured, f_comp, indent=2)
        fichiers_crees_apres.append(comparison_file_path)
        log_messages.append(f"Rapport de comparaison (structuré JSON) sauvegardé dans: {comparison_file_path}")

        # Cleanup original identifiants file
        original_ident_file = ident_data.get("ident_file_path") # from AVANT step
        if original_ident_file and os.path.exists(original_ident_file):
            try: os.remove(original_ident_file); log_messages.append(f"Fichier identifiants {original_ident_file} supprimé.")
            except Exception as e_del_id: log_messages.append(f"Erreur suppression {original_ident_file}: {e_del_id}")
        
        log_messages.append(f"--- Fin run_apres_checks_and_compare pour {ip} ---")
        return {
            "status": "success", "message": "Vérifications APRES et comparaison terminées.",
            "apres_file_path": apres_file_path_internal, 
            "comparison_file_path": comparison_file_path,
            "structured_data_apres": structured_output_data_apres, # Data collected during APRES
            "comparison_results": comparison_results_structured, # Structured differences
            "log_messages": log_messages,
            "fichiers_crees_apres": fichiers_crees_apres,
            "connection_obj": connection 
        }

    except Exception as e_generic_apres:
        import traceback
        error_msg = f"APRES: Erreur majeure: {str(e_generic_apres)} (Type: {type(e_generic_apres).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        return {
            "status": "error", "message": error_msg, 
            "fichiers_crees": fichiers_crees_apres, 
            "structured_data_apres": structured_output_data_apres, # Partial data
            "comparison_results": {},
            "log_messages": log_messages, 
            "connection_obj": connection if 'connection' in locals() and connection else None
        }

if __name__ == '__main__':
    print("APRES_API.py: Script chargé.")
    # Add specific tests for run_apres_checks_and_compare if needed,
    # ensuring you mock or provide valid ident_data and an AVANT file.