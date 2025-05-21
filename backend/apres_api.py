import os
import sys
import json
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException 
from pathlib import Path
import tempfile
import chardet
import unicodedata
from collections import OrderedDict
import portalocker 
import ipaddress
import difflib # For generating diffs

# --- Configuration & Basic Helpers (Assume they are correct from previous full versions) ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

def verifier_connexion_apres(connection, log_messages, context="APRES"): # Same
    try:
        output = connection.send_command("show system uptime", read_timeout=15)
        if "error" in output.lower() or not output.strip():
            log_messages.append(f"ERREUR {context}: Comm (uptime): '{output if output else 'No output'}'"); return False
        log_messages.append(f"Connexion {context} vérifiée (uptime): {output.strip().splitlines()[0] if output.strip() else 'OK'}"); return True
    except Exception as e: log_messages.append(f"ERREUR {context}: Connexion (exception uptime): {str(e)}"); return False

def parse_interfaces_structured_for_table_apres(output_terse, output_detail, log_messages): # Same
    # THIS MUST BE IDENTICAL TO AVANT_API.py's parse_interfaces_structured_for_table
    up_interfaces_obj_list = []; down_interfaces_obj_list = []
    interface_status_map = {}; all_details_map = {}
    for line in output_terse.splitlines():
        cols = line.split();
        if len(cols) >= 2:
            name, status_val = cols[0], cols[1].lower()
            if "up" == status_val or ("up" in status_val and "admin" not in status_val): interface_status_map[name] = "up"
            elif "down" == status_val: interface_status_map[name] = "down"
            current_ip = "Aucune IP"
            if "inet" in cols:
                try: ip_idx = cols.index("inet") + 1; current_ip = cols[ip_idx] if ip_idx < len(cols) else "Aucune IP"
                except ValueError: pass
            all_details_map[name] = {"speed": "N/A", "ip_address": current_ip, "mac_address": "N/A", "name": name, "status": ""}
    phys_sections = output_detail.split("Physical interface:")[1:]
    for sect in phys_sections:
        lines = sect.split("\n"); phys_name = lines[0].strip().split(",")[0].strip()
        c_phys_speed = "Unspecified"; c_phys_mac = "Unspecified"
        for l_det in lines:
            if "Speed:" in l_det: c_phys_speed = l_det.split("Speed:")[1].split(",")[0].strip()
            if "Current address:" in l_det or "Hardware address:" in l_det:
                k = "Current address:" if "Current address:" in l_det else "Hardware address:"
                c_phys_mac = l_det.split(k)[1].strip().split(",")[0].split()[0]
        if phys_name in all_details_map: all_details_map[phys_name]["speed"] = c_phys_speed; all_details_map[phys_name]["mac_address"] = c_phys_mac
        elif phys_name in interface_status_map: all_details_map[phys_name] = {"speed": c_phys_speed, "ip_address": "Aucune IP", "mac_address": c_phys_mac, "name": phys_name, "status": ""}
        log_sects = sect.split("Logical interface ")
        if len(log_sects) > 1:
            for log_blk in log_sects[1:]:
                log_ls = log_blk.split("\n"); log_name = log_ls[0].strip().split()[0].strip()
                current_log_ip = "Aucune IP"
                if log_name in all_details_map: current_log_ip = all_details_map[log_name]["ip_address"]
                if current_log_ip == "Aucune IP":
                    for l_l_det in log_ls:
                        if "Local:" in l_l_det and "inet" in log_blk.lower():
                            try: ip_a = l_l_det.split("Local:")[1].split(",")[0].strip(); current_log_ip = ip_a if ip_a else "Aucune IP"
                            except IndexError: pass
                if log_name in all_details_map: all_details_map[log_name]["speed"] = c_phys_speed; all_details_map[log_name]["ip_address"] = current_log_ip; all_details_map[log_name]["mac_address"] = "N/A" if phys_name != log_name else c_phys_mac 
                elif log_name in interface_status_map: all_details_map[log_name] = {"speed": c_phys_speed, "ip_address": current_log_ip, "mac_address": "N/A", "name": log_name, "status": ""}
    for name, status in interface_status_map.items():
        detail = all_details_map.get(name, {"name": name, "speed": "N/A", "ip_address": "Aucune IP", "mac_address": "N/A"})
        obj = {"name": name, "status": status, "speed": detail["speed"], "ip_address": detail["ip_address"], "mac_address": detail["mac_address"]}
        if status == "up": up_interfaces_obj_list.append(obj)
        else: down_interfaces_obj_list.append(obj)
    return up_interfaces_obj_list, down_interfaces_obj_list

def parse_interfaces_for_file_display_apres(up_obj_list, down_obj_list): # Same
    up_display_lines = []
    for iface in up_obj_list:
        mac_suffix = "," if iface["ip_address"] == "Aucune IP" and iface["mac_address"] not in ["Unspecified", "N/A"] else ""
        line_str = f"{iface['name']} - Vitesse: {iface['speed']} - IP: {iface['ip_address']}"
        if iface["mac_address"] != "N/A": line_str += f" - MAC: {iface['mac_address']}{mac_suffix}"
        up_display_lines.append(line_str)
    if not down_obj_list: down_display_str = "Aucune interface inactive trouvée."
    else:
        down_lines_temp = []
        for iface in down_obj_list:
            mac_suffix = "," if iface["ip_address"] == "Aucune IP" and iface["mac_address"] not in ["Unspecified", "N/A"] else ""
            line_str = f"{iface['name']} - Vitesse: {iface['speed']} - IP: {iface['ip_address']}"
            if iface["mac_address"] != "N/A": line_str += f" - MAC: {iface['mac_address']}{mac_suffix}"
            down_lines_temp.append(line_str)
        down_display_str = "\n".join(down_lines_temp)
    return up_display_lines, down_display_str

def normalize_text(text): # Same
    try:
        if isinstance(text, list): return [normalize_text(line) for line in text]
        if not isinstance(text, str): text = str(text)
        return unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII').lower()
    except: return str(text)
def detect_encoding(file_path): # Same
    try:
        with open(file_path, 'rb') as f: raw = f.read(1024); return chardet.detect(raw)['encoding'] or 'utf-8'
    except: return 'utf-8'
def read_file_by_line(file_path, log_messages): # Same
    try:
        enc = detect_encoding(file_path)
        with open(file_path, 'r', encoding=enc, errors='replace') as f:
            for line in f: yield line.rstrip('\n')
    except FileNotFoundError: log_messages.append(f"Fichier {file_path} non trouvé."); yield None
    except Exception as e: log_messages.append(f"Erreur lecture {file_path}: {e}"); yield None
def extract_sections(file_gen, log_messages): # Same
    sections = OrderedDict(); current_section = None
    try:
        for line in file_gen:
            if line is None: continue
            stripped = line.strip()
            if stripped.endswith(" :") and len(stripped) < 100: current_section = stripped; sections[current_section] = []
            elif current_section: sections[current_section].append(stripped)
    except Exception as e: log_messages.append(f"Erreur extraction sections: {e}")
    return sections

# --- MODIFIED COMPARISON FUNCTION ---
def generate_side_by_side_comparison_text(sections_avant_content, sections_apres_content, log_messages):
    """
    Generates a side-by-side textual comparison for a single section's content.
    Returns a list of formatted strings.
    """
    comparison_lines = []
    # Use difflib to find differences.
    # The `ndiff` function produces lines with prefixes like '  ', '- ', '+ ', '? '.
    # We need to process these to create the side-by-side view.
    
    # Normalize for effective diffing, but display original lines.
    # This is tricky. A simpler approach for now is to diff original lines.
    # For more advanced diff, one might diff normalized then map back to original.
    
    diff = list(difflib.ndiff(sections_avant_content, sections_apres_content))
    
    # Max width for each side (approximate, adjust as needed)
    # This should ideally match your example's column width
    avant_width = 45 
    apres_width = 45
    separator = " | "

    # Header for the diff output
    header_line = f"{'AVANT'.center(avant_width)}{separator}{'APRÈS'.center(apres_width)}"
    comparison_lines.append(header_line)
    comparison_lines.append("-" * (avant_width + len(separator) + apres_width))

    # Pointers for iterating through AVANT and APRÈS specific lines from diff
    # This logic needs to be careful to align lines correctly.
    # A simple line-by-line alignment based on difflib.ndiff output:
    
    # This is a simplified diff reconstruction for side-by-side.
    # For perfect alignment like your example, it might require more complex logic
    # or a library specifically for creating unified/side-by-side text diffs.
    
    # Let's try a different approach using SequenceMatcher for block alignment
    # then format those blocks.
    
    matcher = difflib.SequenceMatcher(None, sections_avant_content, sections_apres_content)
    
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        avant_chunk = sections_avant_content[i1:i2]
        apres_chunk = sections_apres_content[j1:j2]
        
        max_len = max(len(avant_chunk), len(apres_chunk))
        
        for i in range(max_len):
            line_avant = avant_chunk[i] if i < len(avant_chunk) else ""
            line_apres = apres_chunk[i] if i < len(apres_chunk) else ""
            
            # Simple status for the line pair
            line_status = "  " # Identical or aligned
            if tag == 'replace': line_status = "<>" # Replaced
            elif tag == 'delete': line_status = "- " # Deleted from AVANT
            elif tag == 'insert': line_status = "+ " # Inserted into APRÈS
            
            # Truncate/pad lines to fit width (simple approach)
            # A more robust solution would handle word wrapping or character limits better.
            avant_display = line_avant.ljust(avant_width)[:avant_width]
            apres_display = line_apres.ljust(apres_width)[:apres_width]
            
            # For the text file, we just put them side by side.
            # The React component will handle the visual diff display.
            # The 'status' here is more for the text file's context.
            if tag == 'equal':
                comparison_lines.append(f"{avant_display}{separator}{apres_display}")
            elif tag == 'replace':
                # Show both lines if they are different
                for k in range(max(len(avant_chunk), len(apres_chunk))):
                    l_av = avant_chunk[k] if k < len(avant_chunk) else ""
                    l_ap = apres_chunk[k] if k < len(apres_chunk) else ""
                    comparison_lines.append(f"{l_av.ljust(avant_width)[:avant_width]}{separator}{l_ap.ljust(apres_width)[:apres_width]}")
                break # Break from inner loop as chunks are processed by opcode
            elif tag == 'delete':
                comparison_lines.append(f"{avant_display}{separator}{''.ljust(apres_width)}")
            elif tag == 'insert':
                comparison_lines.append(f"{''.ljust(avant_width)}{separator}{apres_display}")

    if not comparison_lines[2:]: # If only header and separator line, means no content or no diff
        comparison_lines.append(f"{'(No content or identical)'.center(avant_width)}{separator}{'(No content or identical)'.center(apres_width)}")

    return "\n".join(comparison_lines)


def compare_sections_for_api(sections_avant, sections_apres, log_messages):
    """
    Compares sections and returns a dictionary where each differing section
    contains a pre-formatted side-by-side textual diff string.
    """
    comparison_output_for_api = OrderedDict()
    all_section_keys = sorted(list(set(sections_avant.keys()) | set(sections_apres.keys())))

    for section_key in all_section_keys:
        content_avant = sections_avant.get(section_key, []) # List of strings
        content_apres = sections_apres.get(section_key, []) # List of strings

        # Normalize for determining if there *is* a difference
        norm_avant = set(normalize_text(content_avant))
        norm_apres = set(normalize_text(content_apres))

        if norm_avant != norm_apres:
            # Generate the side-by-side textual diff for this section
            # using the *original* (non-normalized) content lines
            side_by_side_text = generate_side_by_side_comparison_text(content_avant, content_apres, log_messages)
            comparison_output_for_api[section_key] = {
                "section_title": section_key,
                "status": "Modifié", # Or determine more specific status if needed
                "diff_text": side_by_side_text
            }
        else:
            comparison_output_for_api[section_key] = {
                "section_title": section_key,
                "status": "Identique",
                "diff_text": f"{'AVANT'.center(45)} | {'APRÈS'.center(45)}\n" + \
                             f"{'-'*45} | {'-'*45}\n" + \
                             "(Contenu identique)"
            }
    log_messages.append(f"Comparaison textuelle générée pour {len(all_section_keys)} sections.")
    return comparison_output_for_api


def run_apres_checks_and_compare(ident_data, password, log_messages, avant_connection=None):
    # ... (Initial validation for ip, username, avant_file_to_compare_path - same as before) ...
    ip = ident_data.get("ip"); username = ident_data.get("username")
    avant_file_to_compare_path = ident_data.get("avant_file_path")
    router_hostname = ident_data.get("router_hostname", "inconnu")
    if not all([ip, username, avant_file_to_compare_path]):
        return {"status": "error", "message":"APRES ident data incomplete", "logs": log_messages, "structured_data_apres": {}, "comparison_results": {}}
    if not os.path.exists(avant_file_to_compare_path):
        return {"status": "error", "message":f"AVANT file {avant_file_to_compare_path} not found for APRES", "logs": log_messages, "structured_data_apres": {}, "comparison_results": {}}

    fichiers_crees_apres = []; connection = avant_connection
    apres_file_path_internal = None; comparison_file_path_for_archive = None # For the JSON archive of diffs
    
    structured_output_data_apres = { # For UI display of APRES state
        "basic_info": {}, "routing_engine_status": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_status": "", "isis_status": "", "mpls_status": "",
        "ldp_status": "", "rsvp_status": "", "lldp_status": "", "lsp_status": "", "bgp_status": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": ""
    }
    text_display_output_apres = {} 

    try:
        # ... (Connection logic, temp file creation for APRES data, rename - same as before) ...
        log_messages.append(f"--- Début run_apres_checks_and_compare pour {ip} ---")
        if connection is None or not connection.is_alive(): 
            if connection is not None: log_messages.append("Connexion APRES non active. Reconnexion.")
            try: connection.disconnect()
            except: pass
            device = {'device_type':'juniper','host':ip,'username':username,'password':password,'timeout':30}
            log_messages.append(f"APRES: Connexion à {ip}..."); connection = ConnectHandler(**device)
            # Disable paging for the session
            try:
                connection.send_command('set cli screen-length 0')
            except Exception as e:
                log_messages.append(f"Warning: Could not set screen-length 0: {e}")
            log_messages.append(f"APRES: Connecté succès à {ip}")
        else: log_messages.append("APRES: Utilisation connexion existante.")
        if not verifier_connexion_apres(connection, log_messages, "APRES"): raise Exception("APRES: Vérification connexion échouée.")
        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True) 
        if not os.access(GENERATED_FILES_DIR, os.W_OK): raise PermissionError(f"APRES: Pas accès écriture à {GENERATED_FILES_DIR}")
        temp_apres_file_obj = tempfile.NamedTemporaryFile(mode='w+', prefix='APRES_', suffix='.txt', delete=False, encoding='utf-8', dir=GENERATED_FILES_DIR)
        apres_file_path_internal = temp_apres_file_obj.name; fichiers_crees_apres.append(apres_file_path_internal)

        # --- Collect APRES data (mirroring AVANT's collection logic) ---
        file_title_basic_ap = "Informations de base du routeur (APRES)"
        out_ver_ap = connection.send_command('show version')
        j_ver_ap, r_model_ap, cur_host_ap = "inconnu", "inconnu", router_hostname
        for l in out_ver_ap.splitlines():
            if l.startswith("Hostname:"): cur_host_ap = l.split("Hostname:")[1].strip()
            elif l.startswith("Model:"): r_model_ap = l.split("Model:")[1].strip()
            elif l.startswith("Junos:"): j_ver_ap = l.split("Junos:")[1].strip()
        structured_output_data_apres["basic_info"] = {"hostname":cur_host_ap, "model":r_model_ap, "junos_version":j_ver_ap, "section_title":file_title_basic_ap}
        apres_basic_lines = []
        if cur_host_ap!="inconnu": apres_basic_lines.append(f"Le hostname du routeur est : {cur_host_ap}")
        apres_basic_lines.extend([f"Le modèle du routeur est : {r_model_ap}", f"La version du système Junos est : {j_ver_ap}"])
        text_display_output_apres["basic_info_display"] = "\n".join(apres_basic_lines)
        temp_apres_file_obj.write(f"{file_title_basic_ap} :\n{text_display_output_apres['basic_info_display']}\n")
        log_messages.append(f"APRES Basic Info: Host={cur_host_ap}, Model={r_model_ap}, Junos={j_ver_ap}")
        
        temp_apres_file_obj.flush(); temp_apres_file_obj.close()
        if not os.path.exists(apres_file_path_internal): raise FileNotFoundError(f"Disparition APRES temp file: {apres_file_path_internal}")
        final_apres_base = f"APRES_{username}_{router_hostname}.txt"
        final_apres_path = os.path.join(GENERATED_FILES_DIR, final_apres_base)
        compteur_ap = 1
        while os.path.exists(final_apres_path):
            final_apres_path = os.path.join(GENERATED_FILES_DIR, f"APRES_{username}_{router_hostname}_{compteur_ap}.txt")
            compteur_ap += 1
        try:
            os.replace(apres_file_path_internal, final_apres_path); log_messages.append(f"APRES renommé: {final_apres_path}")
            if apres_file_path_internal in fichiers_crees_apres: fichiers_crees_apres.remove(apres_file_path_internal)
            apres_file_path_internal = final_apres_path
            if apres_file_path_internal not in fichiers_crees_apres: fichiers_crees_apres.append(apres_file_path_internal)
        except OSError as e_rep_ap: log_messages.append(f"ERREUR renommage APRES: {e_rep_ap}. Utilisation temp: {apres_file_path_internal}")

        with open(apres_file_path_internal, 'a', encoding='utf-8') as file_ap:
            # (Use the same collect_data_apres helper from previous full APRES_API.py version)
            # (Ensure all sections are collected for structured_output_data_apres and file_ap)
            def collect_data_apres(data_key_structured, file_title, cmd, data_key_text_display=None, parser_func=None):
                if not verifier_connexion_apres(connection, log_messages, "APRES"): raise Exception(f"Connexion APRES perdue avant: {file_title}")
                log_messages.append(f"Récupération APRES: {file_title}"); file_ap.write(f"\n{file_title} :\n") # Note colon
                output = connection.send_command(cmd, read_timeout=60)
                if parser_func: structured_output_data_apres[data_key_structured] = parser_func(output) # Use generic output for parser
                else: structured_output_data_apres[data_key_structured] = output.strip()
                text_to_write = output.strip()
                if data_key_text_display and data_key_text_display in text_display_output_apres: text_to_write = text_display_output_apres[data_key_text_display]
                elif isinstance(structured_output_data_apres[data_key_structured], list): text_to_write = "\n".join(structured_output_data_apres[data_key_structured])
                file_ap.write(text_to_write + "\n"); log_messages.append(f"OK APRES: {file_title}")

            collect_data_apres("routing_engine_status", "Informations du moteur de routage (APRES)", "show chassis routing-engine")
            
            log_messages.append("Récupération APRES: Interfaces"); file_ap.write("\nInformations sur les interfaces (APRES) :\n")
            out_terse_ap = connection.send_command("show interfaces terse | no-more", read_timeout=60)
            out_detail_ap = connection.send_command("show interfaces detail | no-more", read_timeout=120)
            up_obj_list_ap, down_obj_list_ap = parse_interfaces_structured_for_table_apres(out_terse_ap, out_detail_ap, log_messages)
            structured_output_data_apres["interfaces_up"] = up_obj_list_ap
            structured_output_data_apres["interfaces_down"] = down_obj_list_ap
            up_file_lines_ap, down_file_str_ap = parse_interfaces_for_file_display_apres(up_obj_list_ap, down_obj_list_ap)
            text_display_output_apres["interfaces_up_display"] = up_file_lines_ap
            text_display_output_apres["interfaces_down_display"] = down_file_str_ap # This is already a formatted string
            file_ap.write("Les Interfaces up :\n"); 
            if up_file_lines_ap: [file_ap.write(lstr + "\n") for lstr in up_file_lines_ap]
            else: file_ap.write("Aucune interface active trouvée.\n")
            file_ap.write("Les Interfaces down :\n"); file_ap.write(down_file_str_ap + "\n")
            log_messages.append("OK APRES: Interfaces")

            collect_data_apres("arp_table", "Informations ARP (APRES)", "show arp")
            log_messages.append("Récupération APRES: Routes"); file_ap.write("\nInformations sur les routes (APRES) :\nRésumé des routes :\n")
            route_sum_out_ap = connection.send_command("show route summary"); structured_output_data_apres["route_summary"] = route_sum_out_ap.strip()
            file_ap.write(route_sum_out_ap + "\n"); log_messages.append("OK APRES: Routes")
            
            collect_data_apres("ospf_status", "Protocole OSPF (APRES)", "show ospf interface brief")
            collect_data_apres("isis_status", "Protocole IS-IS (APRES)", "show isis adjacency")
            collect_data_apres("mpls_status", "Protocole MPLS (APRES)", "show mpls interface")
            collect_data_apres("ldp_status", "Protcole LDP (APRES)", "show ldp session")
            collect_data_apres("rsvp_status", "Protocole RSVP (APRES)", "show rsvp interface")
            collect_data_apres("lldp_status", "Protocole LLDP (APRES)", "show lldp neighbor")
            collect_data_apres("lsp_status", "Protocole LSP (APRES)", "show mpls lsp")
            collect_data_apres("bgp_status", "Protocole BGP (APRES)", "show bgp summary")

            def parse_svcs_ap(output): return sorted(list(set(l.strip().rstrip(";") for l in output.splitlines() if l.strip().endswith(";"))))
            collect_data_apres("system_services", "Services configurés (APRES)", "show configuration system services", parser_func=parse_svcs_ap)
            def parse_protos_ap(output): return sorted(list(set(l.split("{")[0].strip() for l in output.splitlines() if "{" in l and not l.strip().startswith("}"))))
            collect_data_apres("configured_protocols", "Protocoles configurés (APRES)", "show configuration protocols", parser_func=parse_protos_ap)
            
            acl_out_ap = connection.send_command("show configuration firewall")
            acl_disp_ap = acl_out_ap.strip() if acl_out_ap.strip() else "Aucune ACL configurée trouvée."
            structured_output_data_apres["firewall_config"] = acl_disp_ap
            file_ap.write("\nListes de Contrôle d'Accès (ACL) (APRES) :\n" + acl_disp_ap + "\n"); log_messages.append("OK APRES: ACLs")

            log_messages.append("Récupération APRES: Logs critiques"); file_ap.write("\nLogs des erreurs critiques (APRES) :\n")
            msg_logs_out_ap = connection.send_command('show log messages | match "error|warning|critical" | last 10 | no-more')
            structured_output_data_apres["critical_logs_messages"] = msg_logs_out_ap.strip()
            file_ap.write("Logs des erreurs critiques dans 'messages' :\n" + msg_logs_out_ap + "\n")
            chassisd_logs_out_ap = connection.send_command('show log chassisd | match "error|warning|critical" | last 10 | no-more')
            structured_output_data_apres["critical_logs_chassisd"] = chassisd_logs_out_ap.strip()
            file_ap.write("Logs des erreurs critiques dans 'chassisd' :\n" + chassisd_logs_out_ap + "\n"); log_messages.append("OK APRES: Logs critiques")
            title_cfg_ap = "La configuration totale (APRES)"; cmd_cfg_ap = "show configuration | display set | no-more"
            log_messages.append(f"Récupération APRES: {title_cfg_ap}"); file_ap.write(f"\n{title_cfg_ap} :\n")
            out_cfg_ap_set = connection.send_command(cmd_cfg_ap, read_timeout=180)
            structured_output_data_apres["full_config_set"] = out_cfg_ap_set
            file_ap.write(out_cfg_ap_set + "\n"); log_messages.append(f"OK APRES: {title_cfg_ap}")


        # --- Comparison ---
        log_messages.append(f"\nLancement comparaison (file-based) AVANT/APRES...")
        avant_data_gen = read_file_by_line(avant_file_to_compare_path, log_messages)
        sections_from_avant_file = extract_sections(avant_data_gen, log_messages)
        apres_data_gen = read_file_by_line(apres_file_path_internal, log_messages)
        sections_from_apres_file = extract_sections(apres_data_gen, log_messages)
        
        # MODIFIED: Use compare_sections_for_api to get pre-formatted text diffs
        comparison_results_for_api = compare_sections_for_api(sections_from_avant_file, sections_from_apres_file, log_messages)

        # Save this text-based comparison to the COMPARAISON file
        comp_base_name = f"COMPARAISON_{username}_{router_hostname}.txt"
        comparison_file_path_for_archive = os.path.join(GENERATED_FILES_DIR, comp_base_name)
        comp_counter = 1
        while os.path.exists(comparison_file_path_for_archive):
            comparison_file_path_for_archive = os.path.join(GENERATED_FILES_DIR, f"COMPARAISON_{username}_{router_hostname}_{comp_counter}.txt"); comp_counter+=1
        
        with open(comparison_file_path_for_archive, 'w', encoding='utf-8') as f_comp:
            f_comp.write("RAPPORT DE COMPARAISON AVANT/APRÈS\n")
            f_comp.write("="*80 + "\n")
            for section_title, diff_data in comparison_results_for_api.items():
                f_comp.write(f"\nSECTION: {section_title} (Status: {diff_data['status']})\n")
                f_comp.write(diff_data['diff_text'] + "\n")
                f_comp.write("-" * 80 + "\n")
        fichiers_crees_apres.append(comparison_file_path_for_archive)
        log_messages.append(f"Rapport de comparaison textuel sauvegardé : {comparison_file_path_for_archive}")
        
        # ... (Cleanup original identifiants file - same as before) ...
        original_ident_file = ident_data.get("ident_file_path")
        if original_ident_file and os.path.exists(original_ident_file):
            try: os.remove(original_ident_file); log_messages.append(f"Fichier ident {original_ident_file} supprimé.")
            except Exception as e_del_id: log_messages.append(f"Erreur suppression {original_ident_file}: {e_del_id}")

        log_messages.append(f"--- Fin run_apres_checks_and_compare pour {ip} ---")
        return {
            "status": "success", "message": "Vérifications APRES et comparaison terminées.",
            "apres_file_path": apres_file_path_internal, 
            "comparison_file_path": comparison_file_path_for_archive, # Path to the text diff file
            "structured_data_apres": structured_output_data_apres, 
            "comparison_results": comparison_results_for_api, # This now contains pre-formatted text diffs
            "log_messages": log_messages,
            "fichiers_crees_apres": fichiers_crees_apres,
            "connection_obj": connection 
        }

    except Exception as e_generic_apres:
        # ... (Error handling - same as before)
        import traceback
        error_msg = f"APRES: Erreur majeure: {str(e_generic_apres)} (Type: {type(e_generic_apres).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        return {"status": "error", "message": error_msg, "fichiers_crees": fichiers_crees_apres, 
                "structured_data_apres": structured_output_data_apres, "comparison_results": {},
                "log_messages": log_messages, 
                "connection_obj": connection if 'connection' in locals() and connection else None}

if __name__ == '__main__':
    print("APRES_API.py: Script chargé.")