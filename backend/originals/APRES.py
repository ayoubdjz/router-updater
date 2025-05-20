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
import portalocker 
from pathlib import Path

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

# --- Helper Functions ---
# Import or duplicate necessary helpers from AVANT_API.py if they are identical
# For example: verifier_connexion_apres (similar to verifier_connexion), parse_interfaces_structured

def valider_ip_apres(ip): # Specific to APRES if different logic, else use AVANT_API.valider_ip
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

def verifier_connexion_apres(connection, log_messages, context="APRES"): # Added context
    try:
        output = connection.send_command("show system uptime", read_timeout=15)
        if "error" in output.lower() or not output.strip():
            log_messages.append(f"ERREUR {context}: Problème de communication (uptime): '{output if output else 'No output'}'")
            return False
        log_messages.append(f"Connexion {context} vérifiée (uptime): {output.strip().splitlines()[0] if output.strip() else 'OK'}")
        return True
    except Exception as e:
        log_messages.append(f"ERREUR {context}: Connexion (exception uptime): {str(e)}")
        return False

# Assuming parse_interfaces_structured is needed and defined as in AVANT_API.py
# If it's in AVANT_API.py, you could do:
# from AVANT_API import parse_interfaces_structured
# For this standalone example, I'll include its signature and a note
def parse_interfaces_structured(output_terse, output_detail, log_messages):
    # Placeholder: This function should be identical to the one in AVANT_API.py
    # or imported from there. It parses terse and detail output into structured lists.
    log_messages.append("NOTE: parse_interfaces_structured called in APRES (ensure implementation is complete).")
    up_interfaces = [{"name": "dummy-up-apres/0", "status": "up", "speed": "1G", "ip_address": "1.1.1.2/24", "mac_address": "AA:BB:CC:00:11:23"}]
    down_interfaces = []
    # --- Real parsing logic from AVANT_API.py version should be here ---
    # For brevity, returning dummy data. Replace with full parsing from AVANT_API.py.
    # This is a common source of discrepancy if not identical.
    # The parsing logic MUST be the same for AVANT and APRES for valid comparison and display.
    raw_up_names = []
    raw_down_names = []
    all_interface_details = {}
    for line in output_terse.splitlines():
        columns = line.split()
        if len(columns) >= 2:
            interface_name = columns[0]; status = columns[1].lower()
            if "up" == status or ("up" in status and "admin" not in status): raw_up_names.append(interface_name)
            elif "down" == status: raw_down_names.append(interface_name)
    
    physical_interface_sections = output_detail.split("Physical interface:")
    if len(physical_interface_sections) > 1: physical_interface_sections = physical_interface_sections[1:]

    for section in physical_interface_sections:
        lines = section.split("\n"); phys_speed = "Indisponible"; phys_mac = "N/A"
        if not lines: continue
        physical_interface_name = lines[0].strip().split(",")[0].strip()
        for line_idx, line in enumerate(lines):
            if "Speed:" in line: phys_speed = line.split("Speed:")[1].split(",")[0].strip()
            if "Current address:" in line or "Hardware address:" in line:
                key = "Current address:" if "Current address:" in line else "Hardware address:"
                phys_mac = line.split(key)[1].strip().split(",")[0].split()[0]
        if physical_interface_name in raw_up_names or physical_interface_name in raw_down_names:
            all_interface_details[physical_interface_name] = {"name": physical_interface_name, "status": "", "speed": phys_speed, "ip_address": "N/A (Phys)", "mac_address": phys_mac}
        
        logical_interface_sections = section.split("Logical interface ")
        if len(logical_interface_sections) > 1: logical_interface_sections = logical_interface_sections[1:]
        for logical_section in logical_interface_sections:
            logical_lines = logical_section.split("\n"); log_ip = "N/A"
            if not logical_lines: continue
            logical_interface_name = logical_lines[0].strip().split()[0].strip()
            for log_line in logical_lines:
                if "Local:" in log_line and "inet" in logical_section.lower(): log_ip = log_line.split("Local:")[1].split(",")[0].strip()
            if logical_interface_name in raw_up_names or logical_interface_name in raw_down_names:
                 all_interface_details[logical_interface_name] = {"name": logical_interface_name, "status": "", "speed": phys_speed, "ip_address": log_ip, "mac_address": phys_mac}
    
    up_interfaces = []
    for name in raw_up_names:
        details = all_interface_details.get(name, {"name": name, "status": "up", "speed": "N/A", "ip_address": "N/A", "mac_address": "N/A"})
        details["status"] = "up"; up_interfaces.append(details)
    down_interfaces = []
    for name in raw_down_names:
        details = all_interface_details.get(name, {"name": name, "status": "down", "speed": "N/A", "ip_address": "N/A", "mac_address": "N/A"})
        details["status"] = "down"; down_interfaces.append(details)
    return up_interfaces, down_interfaces
# End of parse_interfaces_structured (ensure this is the full, correct version)

# normalize_text, detect_encoding, read_file_by_line, extract_sections (same as before)
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

def compare_sections_structured(sections_avant, sections_apres, log_messages):
    # ... (Same as previous version of this function in APRES_API.py)
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
            current_diff["lines_removed"] = [l for l in content_avant_orig if normalize_text(l) not in norm_apres]
            current_diff["lines_added"] = [l for l in content_apres_orig if normalize_text(l) not in norm_avant]
            if not current_diff["lines_removed"] and not current_diff["lines_added"]:
                 if not content_avant_orig and content_apres_orig: current_diff["status"] = "Nouveau"
                 elif content_avant_orig and not content_apres_orig: current_diff["status"] = "Supprimé"
                 else: current_diff["status"] = "Modifié (subtil)"
        structured_differences[section_key] = current_diff
    log_messages.append(f"Comparaison structurée terminée pour {len(all_section_keys)} sections.")
    return structured_differences


# --- Main Process Function for APRES ---
def run_apres_checks_and_compare(ident_data, password, log_messages, avant_connection=None):
    ip = ident_data.get("ip")
    username = ident_data.get("username")
    avant_file_to_compare_path = ident_data.get("avant_file_path") # Path to the AVANT output text file
    router_hostname = ident_data.get("router_hostname", "inconnu")

    if not all([ip, username, avant_file_to_compare_path]):
        # ... (error handling as before)
        msg = "Données d'identification APRES incomplètes."
        log_messages.append(msg)
        return {"status": "error", "message": msg, "logs": log_messages, "structured_data_apres": {}, "comparison_results": {}}
    if not os.path.exists(avant_file_to_compare_path):
        # ... (error handling as before)
        msg = f"Fichier AVANT ({avant_file_to_compare_path}) non trouvé pour comparaison APRES."
        log_messages.append(msg)
        return {"status": "error", "message": msg, "logs": log_messages, "structured_data_apres": {}, "comparison_results": {}}


    fichiers_crees_apres = []
    connection = avant_connection 
    apres_file_path_internal = None # For temp then final APRES text file
    comparison_file_path = None
    
    # Initialize structured data dictionary for APRES results
    structured_output_data_apres = {
        "basic_info": {}, "routing_engine": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_info": "", "isis_info": "", "mpls_info": "",
        "ldp_info": "", "rsvp_info": "", "lldp_info": "", "lsp_info": "", "bgp_summary": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": ""
    }

    try:
        log_messages.append(f"--- Début run_apres_checks_and_compare pour {ip} ---")
        if connection is None or not connection.is_alive():
            if connection is not None: log_messages.append("Connexion fournie pour APRES non active. Reconnexion.")
            try: connection.disconnect()
            except: pass
            device = {'device_type': 'juniper', 'host': ip, 'username': username, 'password': password, 'timeout': 30}
            log_messages.append(f"APRES: Tentative de connexion à {ip}..."); connection = ConnectHandler(**device)
            log_messages.append(f"APRES: Connecté succès à {ip}")
        else:
            log_messages.append("APRES: Utilisation de la connexion existante.")

        if not verifier_connexion_apres(connection, log_messages, context="APRES"): # Pass context
            raise Exception("APRES: Vérification de la connexion post-établissement échouée.")

        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)
        if not os.access(GENERATED_FILES_DIR, os.W_OK):
            raise PermissionError(f"APRES: Pas d'accès écriture à {GENERATED_FILES_DIR}")

        temp_apres_file_obj = tempfile.NamedTemporaryFile(
            mode='w+', prefix='APRES_', suffix='.txt', delete=False, encoding='utf-8', dir=GENERATED_FILES_DIR)
        apres_file_path_internal = temp_apres_file_obj.name
        log_messages.append(f"Fichier APRES temporaire: {apres_file_path_internal}")
        fichiers_crees_apres.append(apres_file_path_internal)

        # Section: Basic Info (APRES)
        structured_output_data_apres["basic_info"]["section_title"] = "Informations de base du routeur (APRES)"
        temp_apres_file_obj.write(f"{structured_output_data_apres['basic_info']['section_title']}:\n")
        out_ver_apres = connection.send_command('show version')
        j_ver_ap, r_model_ap = "inconnu", "inconnu"; cur_host_ap = router_hostname
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

        final_apres_base = f"APRES_{username}_{router_hostname}.txt"
        final_apres_path = os.path.join(GENERATED_FILES_DIR, final_apres_base)
        compteur_ap = 1
        while os.path.exists(final_apres_path):
            final_apres_path = os.path.join(GENERATED_FILES_DIR, f"APRES_{username}_{router_hostname}_{compteur_ap}.txt"); compteur_ap+=1
        try:
            os.replace(apres_file_path_internal, final_apres_path)
            log_messages.append(f"Fichier APRES renommé en: {final_apres_path}")
            if apres_file_path_internal in fichiers_crees_apres: fichiers_crees_apres.remove(apres_file_path_internal)
            apres_file_path_internal = final_apres_path
            if apres_file_path_internal not in fichiers_crees_apres: fichiers_crees_apres.append(apres_file_path_internal)
        except OSError as e_rep_ap:
            log_messages.append(f"ERREUR renommage APRES: {e_rep_ap}. Utilisation du nom temporaire: {apres_file_path_internal}")
        
        # --- Collect other data for APRES ---
        with open(apres_file_path_internal, 'a', encoding='utf-8') as file_ap:
            file_ap.write("\n--- Collecte APRES étendue ---\n")
            
            def fetch_and_store_apres(key, title, cmd, is_raw=True, special_parser=None):
                # Simplified version of AVANT's fetch_and_store, adapt as needed
                if not verifier_connexion_apres(connection, log_messages, "APRES"):
                    raise Exception(f"Connexion APRES perdue avant: {title}")
                log_messages.append(f"Récupération APRES: {title}")
                file_ap.write(f"\n{title}:\n")
                output = connection.send_command(cmd, read_timeout=60)
                
                if special_parser:
                    parsed_data = special_parser(output)
                    structured_output_data_apres[key] = parsed_data
                    if isinstance(parsed_data, list) and parsed_data and isinstance(parsed_data[0], dict):
                         for item_dict in parsed_data:
                            for k,v in item_dict.items(): file_ap.write(f"  {k}: {v}\n")
                            file_ap.write("\n")
                    elif isinstance(parsed_data, list):
                        for item_str in parsed_data: file_ap.write(f"  {item_str}\n")
                    else: file_ap.write(str(parsed_data) + "\n")
                elif is_raw:
                    structured_output_data_apres[key] = output
                    file_ap.write(output + "\n")
                else:
                    lines = [l.strip() for l in output.splitlines() if l.strip() and not l.strip().startswith("---(more")]
                    structured_output_data_apres[key] = lines
                    for line_item in lines: file_ap.write(f"  {line_item}\n")
                log_messages.append(f"OK APRES: {title}")

            fetch_and_store_apres("routing_engine", "Informations du moteur de routage (APRES)", "show chassis routing-engine")

            # Interfaces (APRES)
            if not verifier_connexion_apres(connection, log_messages, "APRES"): raise Exception("Connexion APRES perdue avant interfaces")
            log_messages.append("Récupération APRES: Informations sur les interfaces")
            file_ap.write("\nInformations sur les interfaces (APRES):\n")
            cmd_terse_ap = "show interfaces terse | no-more"
            cmd_detail_ap = "show interfaces detail | no-more"
            out_terse_ap = connection.send_command(cmd_terse_ap, read_timeout=60)
            out_detail_ap = connection.send_command(cmd_detail_ap, read_timeout=120)
            up_list_ap, down_list_ap = parse_interfaces_structured(out_terse_ap, out_detail_ap, log_messages)
            structured_output_data_apres["interfaces_up"] = up_list_ap
            structured_output_data_apres["interfaces_down"] = down_list_ap
            file_ap.write("Interfaces UP (APRES):\n")
            if up_list_ap:
                for iface in up_list_ap: file_ap.write(f"  Name: {iface['name']}, Speed: {iface['speed']}, IP: {iface['ip_address']}, MAC: {iface['mac_address']}\n")
            else: file_ap.write("  Aucune interface UP (APRES).\n")
            file_ap.write("Interfaces DOWN (APRES):\n")
            if down_list_ap:
                for iface in down_list_ap: file_ap.write(f"  Name: {iface['name']}, Speed: {iface['speed']}, IP: {iface['ip_address']}, MAC: {iface['mac_address']}\n")
            else: file_ap.write("  Aucune interface DOWN (APRES).\n")
            log_messages.append("OK APRES: Informations sur les interfaces")

            fetch_and_store_apres("arp_table", "Informations ARP (APRES)", "show arp")
            fetch_and_store_apres("route_summary", "Informations sur les routes (APRES)", "show route summary")
            fetch_and_store_apres("ospf_info", "Protocole OSPF (APRES)", "show ospf interface brief")
            # ... Add all other fetch_and_store_apres calls similar to AVANT_API.py ...
            fetch_and_store_apres("isis_info", "Protocole IS-IS (APRES)", "show isis adjacency")
            fetch_and_store_apres("mpls_info", "Protocole MPLS (APRES)", "show mpls interface")
            fetch_and_store_apres("ldp_info", "Protocole LDP (APRES)", "show ldp session")
            fetch_and_store_apres("rsvp_info", "Protocole RSVP (APRES)", "show rsvp interface")
            fetch_and_store_apres("lldp_info", "Protocole LLDP (APRES)", "show lldp neighbor")
            fetch_and_store_apres("lsp_info", "Protocole LSP (APRES)", "show mpls lsp")
            fetch_and_store_apres("bgp_summary", "Protocole BGP (APRES)", "show bgp summary")
            
            def parse_services_apres(output): return sorted(list(set(l.strip().rstrip(";") for l in output.splitlines() if l.strip().endswith(";"))))
            fetch_and_store_apres("system_services", "Services configurés (APRES)", "show configuration system services", is_raw=False, special_parser=parse_services_apres)
            
            def parse_protocols_apres(output): return sorted(list(set(l.split("{")[0].strip() for l in output.splitlines() if "{" in l and not l.strip().startswith("}"))))
            fetch_and_store_apres("configured_protocols", "Protocoles configurés (APRES)", "show configuration protocols", is_raw=False, special_parser=parse_protocols_apres)

            fetch_and_store_apres("firewall_config", "Listes de Contrôle d'Accès (ACL) (APRES)", "show configuration firewall")
            fetch_and_store_apres("critical_logs_messages", "Logs erreurs critiques 'messages' (APRES)", 'show log messages | match "error|warning|critical" | last 10')
            fetch_and_store_apres("critical_logs_chassisd", "Logs erreurs critiques 'chassisd' (APRES)", 'show log chassisd | match "error|warning|critical" | last 10')

            if not verifier_connexion_apres(connection, log_messages, "APRES"): raise Exception("Connexion APRES perdue avant config totale.")
            title_cfg_ap = "La configuration totale (set format) (APRES)"
            cmd_cfg_ap = "show configuration | display set"
            log_messages.append(f"Récupération APRES: {title_cfg_ap}")
            file_ap.write(f"\n{title_cfg_ap}:\n")
            out_cfg_ap = connection.send_command(cmd_cfg_ap, read_timeout=180)
            structured_output_data_apres["full_config_set"] = out_cfg_ap
            file_ap.write(out_cfg_ap + "\n")
            log_messages.append(f"OK APRES: {title_cfg_ap}")


        # --- Comparaison ---
        log_messages.append(f"\nLancement de la comparaison structurée entre AVANT et APRES...")
        avant_data_file_content_gen = read_file_by_line(avant_file_to_compare_path, log_messages)
        sections_from_avant_file = extract_sections(avant_data_file_content_gen, log_messages)

        apres_data_file_content_gen = read_file_by_line(apres_file_path_internal, log_messages) # Use the actual APRES text file
        sections_from_apres_file = extract_sections(apres_data_file_content_gen, log_messages)
        
        if not sections_from_avant_file and os.path.exists(avant_file_to_compare_path):
            log_messages.append(f"AVERTISSEMENT: Aucune section extraite de {avant_file_to_compare_path} (AVANT). Comparaison affectée.")
        if not sections_from_apres_file and os.path.exists(apres_file_path_internal):
            log_messages.append(f"AVERTISSEMENT: Aucune section extraite de {apres_file_path_internal} (APRES). Comparaison affectée.")

        comparison_results_structured = compare_sections_structured(sections_from_avant_file, sections_from_apres_file, log_messages)

        comp_base_name = f"COMPARAISON_{username}_{router_hostname}.txt" # Text file for JSON dump of diff
        comparison_file_path = os.path.join(GENERATED_FILES_DIR, comp_base_name)
        comp_counter = 1
        while os.path.exists(comparison_file_path):
            comparison_file_path = os.path.join(GENERATED_FILES_DIR, f"COMPARAISON_{username}_{router_hostname}_{comp_counter}.txt"); comp_counter+=1
        with open(comparison_file_path, 'w', encoding='utf-8') as f_comp:
            json.dump(comparison_results_structured, f_comp, indent=2) # Store structured diff as JSON
        fichiers_crees_apres.append(comparison_file_path)
        log_messages.append(f"Rapport de comparaison (structuré JSON) sauvegardé dans: {comparison_file_path}")

        original_ident_file = ident_data.get("ident_file_path")
        if original_ident_file and os.path.exists(original_ident_file):
            try: os.remove(original_ident_file); log_messages.append(f"Fichier identifiants {original_ident_file} supprimé.")
            except Exception as e_del_id: log_messages.append(f"Erreur suppression {original_ident_file}: {e_del_id}")
        
        log_messages.append(f"--- Fin run_apres_checks_and_compare pour {ip} ---")
        return {
            "status": "success", "message": "Vérifications APRES et comparaison terminées.",
            "apres_file_path": apres_file_path_internal, 
            "comparison_file_path": comparison_file_path,
            "structured_data_apres": structured_output_data_apres, 
            "comparison_results": comparison_results_structured, 
            "log_messages": log_messages,
            "fichiers_crees_apres": fichiers_crees_apres,
            "connection_obj": connection 
        }

    except Exception as e_generic_apres:
        # ... (error handling same as before) ...
        import traceback
        error_msg = f"APRES: Erreur majeure: {str(e_generic_apres)} (Type: {type(e_generic_apres).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        return {
            "status": "error", "message": error_msg, 
            "fichiers_crees": fichiers_crees_apres, 
            "structured_data_apres": structured_output_data_apres, 
            "comparison_results": {}, # Empty on major error
            "log_messages": log_messages, 
            "connection_obj": connection if 'connection' in locals() and connection else None
        }

if __name__ == '__main__':
    print("APRES_API.py: Script chargé.")