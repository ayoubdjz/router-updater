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
import difflib # Keep difflib for line comparison

# --- Configuration & Basic Helpers (Assume same as before) ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

# --- Helper Functions (verifier_connexion_apres, parse_interfaces_*, normalize_text, etc. ---
# --- These should be IDENTICAL to the ones in AVANT_API.py for consistency. ---
# --- For brevity, I'm not re-pasting all of them. Assume they are correct. ---
def verifier_connexion_apres(connection, log_messages, context="APRES"): # Same
    try:
        output = connection.send_command("show system uptime", read_timeout=15)
        if "error" in output.lower() or not output.strip():
            log_messages.append(f"ERREUR {context}: Comm (uptime): '{output if output else 'No output'}'"); return False
        log_messages.append(f"Connexion {context} vérifiée (uptime): {output.strip().splitlines()[0] if output.strip() else 'OK'}"); return True
    except Exception as e: log_messages.append(f"ERREUR {context}: Connexion (exception uptime): {str(e)}"); return False

def parse_interfaces_structured_for_table_apres(output_terse, output_detail, log_messages): # Same as AVANT_API's
    # ... (Full logic from previous correct version) ...
    up_interfaces_obj_list = []; down_interfaces_obj_list = [] # Ensure this returns list of objects
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


# --- REVISED TEXTUAL DIFF GENERATION ---
def generate_textual_side_by_side_diff(content_avant, content_apres, avant_col_width=45, apres_col_width=45):
    """
    Generates a side-by-side textual diff for a section's content lines.
    content_avant and content_apres are lists of strings.
    """
    diff_lines_for_section = []
    separator = " | "
    
    # Use difflib.unified_diff to get a list of diff lines with context
    # Or, for simpler side-by-side, we can iterate based on SequenceMatcher opcodes.
    # This is a more complex alignment challenge to exactly match your example for *all* cases.
    # Let's try to replicate the example's spirit: show differing lines aligned.

    # For simplicity and to match the provided example, we'll focus on aligning differing lines.
    # This simplified version won't do context lines like a full `diff -U` or complex alignment
    # but will try to show lines that are different.
    
    # A more direct approach to get something like your example for differing lines:
    # Find lines in AVANT not in APRÈS (normalized), and vice-versa.
    # Then try to pair them up or show them. This is still not a true "diff".

    # Let's use difflib.SequenceMatcher to find differing blocks.
    s = difflib.SequenceMatcher(None, content_avant, content_apres)
    
    has_diff = False
    for tag, i1, i2, j1, j2 in s.get_opcodes():
        if tag != 'equal':
            has_diff = True
            # For non-equal blocks, just list AVANT lines then APRÈS lines for this block
            if content_avant[i1:i2]: # If there's anything in AVANT for this differing block
                for line_av in content_avant[i1:i2]:
                    diff_lines_for_section.append(f"{line_av:<{avant_col_width}}{separator}{''}")
            if content_apres[j1:j2]: # If there's anything in APRÈS for this differing block
                for line_ap in content_apres[j1:j2]:
                    # If avant block was shorter, we need to align these by prepending empty avant side
                    if len(content_avant[i1:i2]) < len(content_apres[j1:j2]) and \
                       diff_lines_for_section and \
                       diff_lines_for_section[-1].strip().startswith(content_avant[i2-1] if i2 > i1 else ""): # if last line was from avant
                        diff_lines_for_section.append(f"{'' :<{avant_col_width}}{separator}{line_ap}")
                    else: # Default case or if no corresponding avant line was just printed
                         diff_lines_for_section.append(f"{'' :<{avant_col_width}}{separator}{line_ap}")

    if not has_diff:
        return "(Contenu identique)" # Or return empty list if modal handles this

    if not diff_lines_for_section: # If has_diff was true but no lines collected (edge case)
        return "(Différences détectées mais formatage simple a échoué)"

    # Add header to the generated diff text for this section
    header = [
        f"{'AVANT'.center(avant_col_width)}{separator}{'APRÈS'.center(apres_width)}",
        f"{'-' * avant_col_width}{separator}{'-' * apres_col_width}"
    ]
    return "\n".join(header + diff_lines_for_section)


def create_comparison_payload(sections_avant, sections_apres, log_messages):
    """
    Prepares the comparison data for the API response.
    For differing sections, it includes a pre-formatted textual diff.
    """
    comparison_payload = OrderedDict()
    all_section_keys = sorted(list(set(sections_avant.keys()) | set(sections_apres.keys())))

    for section_key in all_section_keys:
        content_avant = sections_avant.get(section_key, []) # List of strings from file
        content_apres = sections_apres.get(section_key, []) # List of strings from file

        norm_avant_set = set(normalize_text(content_avant))
        norm_apres_set = set(normalize_text(content_apres))

        status = "Identique"
        diff_text_for_section = "(Contenu identique)"

        if not content_avant and content_apres:
            status = "Nouveau"
            # For "Nouveau", show all APRÈS content under APRÈS column
            header = [f"{'AVANT'.center(45)} | {'APRÈS'.center(45)}", f"{'-'*45} | {'-'*45}"]
            apres_lines = [f"{'' :<45} | {line_ap}" for line_ap in content_apres]
            diff_text_for_section = "\n".join(header + apres_lines)
        elif content_avant and not content_apres:
            status = "Supprimé"
            # For "Supprimé", show all AVANT content under AVANT column
            header = [f"{'AVANT'.center(45)} | {'APRÈS'.center(45)}", f"{'-'*45} | {'-'*45}"]
            avant_lines = [f"{line_av:<45} | {''}" for line_av in content_avant]
            diff_text_for_section = "\n".join(header + avant_lines)
        elif norm_avant_set != norm_apres_set:
            status = "Modifié"
            # Generate the side-by-side textual diff for this section
            diff_text_for_section = generate_textual_side_by_side_diff(content_avant, content_apres)
        
        comparison_payload[section_key] = {
            "section_title": section_key,
            "status": status,
            "diff_text": diff_text_for_section 
            # No longer sending full avant_content_lines/apres_content_lines here
            # as diff_text is now the primary display for comparison.
            # If frontend needs raw lines for other purposes, they can be added back.
        }
    log_messages.append(f"Payload de comparaison généré pour {len(all_section_keys)} sections.")
    return comparison_payload


def run_apres_checks_and_compare(ident_data, password, log_messages, avant_connection=None):
    # ... (Initial validation, setup, APRES data collection - same as previous full version) ...
    # Ensure structured_output_data_apres is populated correctly.
    ip = ident_data.get("ip"); username = ident_data.get("username")
    avant_file_to_compare_path = ident_data.get("avant_file_path")
    router_hostname = ident_data.get("router_hostname", "inconnu")
    if not all([ip, username, avant_file_to_compare_path]):
        return {"status": "error", "message":"APRES ident data incomplete", "logs": log_messages, "structured_data_apres": {}, "comparison_results": {}}
    if not os.path.exists(avant_file_to_compare_path):
        return {"status": "error", "message":f"AVANT file {avant_file_to_compare_path} not found for APRES", "logs": log_messages, "structured_data_apres": {}, "comparison_results": {}}

    fichiers_crees_apres = []; connection = avant_connection
    apres_file_path_internal = None; comparison_archive_file_path = None
    structured_output_data_apres = {
        "basic_info": {}, "routing_engine_status": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_status": "", "isis_status": "", "mpls_status": "",
        "ldp_status": "", "rsvp_status": "", "lldp_status": "", "lsp_status": "", "bgp_status": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": ""
    }
    text_display_output_apres = {} 

    try:
        log_messages.append(f"--- Début run_apres_checks_and_compare pour {ip} ---")
        if connection is None or not connection.is_alive(): 
            if connection is not None: log_messages.append("Connexion APRES non active. Reconnexion.")
            try: connection.disconnect()
            except: pass
            device = {'device_type':'juniper','host':ip,'username':username,'password':password,'timeout':30}
            log_messages.append(f"APRES: Connexion à {ip}..."); connection = ConnectHandler(**device)
            log_messages.append(f"APRES: Connecté succès à {ip}")
        else: log_messages.append("APRES: Utilisation connexion existante.")
        if not verifier_connexion_apres(connection, log_messages, "APRES"): raise Exception("APRES: Vérification connexion échouée.")
        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True) 
        if not os.access(GENERATED_FILES_DIR, os.W_OK): raise PermissionError(f"APRES: Pas accès écriture à {GENERATED_FILES_DIR}")
        temp_apres_file_obj = tempfile.NamedTemporaryFile(mode='w+', prefix='APRES_', suffix='.txt', delete=False, encoding='utf-8', dir=GENERATED_FILES_DIR)
        apres_file_path_internal = temp_apres_file_obj.name; fichiers_crees_apres.append(apres_file_path_internal)
        
        file_title_basic_ap = "Informations de base du routeur (APRES)"
        out_ver_ap = connection.send_command('show version')
        j_ver_ap,r_model_ap,cur_host_ap = "inconnu","inconnu",router_hostname
        for l in out_ver_ap.splitlines():
            if l.startswith("Hostname:"):cur_host_ap=l.split("Hostname:")[1].strip()
            elif l.startswith("Model:"):r_model_ap=l.split("Model:")[1].strip()
            elif l.startswith("Junos:"):j_ver_ap=l.split("Junos:")[1].strip()
        structured_output_data_apres["basic_info"] = {"hostname":cur_host_ap,"model":r_model_ap,"junos_version":j_ver_ap,"section_title":file_title_basic_ap}
        apres_basic_lines = []
        if cur_host_ap!="inconnu":apres_basic_lines.append(f"Le hostname du routeur est : {cur_host_ap}")
        apres_basic_lines.extend([f"Le modèle du routeur est : {r_model_ap}",f"La version du système Junos est : {j_ver_ap}"])
        text_display_output_apres["basic_info_display"] = "\n".join(apres_basic_lines)
        temp_apres_file_obj.write(f"{file_title_basic_ap} :\n{text_display_output_apres['basic_info_display']}\n")
        log_messages.append(f"APRES Basic Info: Host={cur_host_ap}, Model={r_model_ap}, Junos={j_ver_ap}")
        temp_apres_file_obj.flush();temp_apres_file_obj.close()
        if not os.path.exists(apres_file_path_internal):raise FileNotFoundError(f"Disparition APRES temp file: {apres_file_path_internal}")
        final_apres_base = f"APRES_{username}_{router_hostname}.txt"
        final_apres_path = os.path.join(GENERATED_FILES_DIR,final_apres_base)
        compteur_ap = 1
        while os.path.exists(final_apres_path):
            final_apres_path = os.path.join(GENERATED_FILES_DIR, f"APRES_{username}_{router_hostname}_{compteur_ap}.txt")
            compteur_ap += 1
        try:
            os.replace(apres_file_path_internal,final_apres_path);log_messages.append(f"APRES renommé: {final_apres_path}")
            if apres_file_path_internal in fichiers_crees_apres:fichiers_crees_apres.remove(apres_file_path_internal)
            apres_file_path_internal=final_apres_path
            if apres_file_path_internal not in fichiers_crees_apres:fichiers_crees_apres.append(apres_file_path_internal)
        except OSError as e_rep_ap:log_messages.append(f"ERREUR renommage APRES: {e_rep_ap}. Utilisation temp: {apres_file_path_internal}")

        with open(apres_file_path_internal,'a',encoding='utf-8') as file_ap:
            file_ap.write("\n--- Collecte APRES étendue ---\n")
            def collect_data_apres(data_key_structured, file_title, cmd, data_key_text_display=None, parser_func=None):
                if not verifier_connexion_apres(connection,log_messages,"APRES"):raise Exception(f"Connexion APRES perdue avant: {file_title}")
                log_messages.append(f"Récupération APRES: {file_title}");file_ap.write(f"\n{file_title} :\n")
                output=connection.send_command(cmd,read_timeout=60)
                if parser_func:structured_output_data_apres[data_key_structured]=parser_func(output)
                else:structured_output_data_apres[data_key_structured]=output.strip()
                text_to_write=output.strip()
                if data_key_text_display and data_key_text_display in text_display_output_apres:text_to_write=text_display_output_apres[data_key_text_display]
                elif isinstance(structured_output_data_apres[data_key_structured],list):text_to_write="\n".join(structured_output_data_apres[data_key_structured])
                file_ap.write(text_to_write+"\n");log_messages.append(f"OK APRES: {file_title}")
            collect_data_apres("routing_engine_status","Informations du moteur de routage (APRES)","show chassis routing-engine")
            log_messages.append("Récupération APRES: Interfaces");file_ap.write("\nInformations sur les interfaces (APRES) :\n")
            out_terse_ap=connection.send_command("show interfaces terse | no-more",read_timeout=60)
            out_detail_ap=connection.send_command("show interfaces detail | no-more",read_timeout=120)
            up_obj_list_ap,down_obj_list_ap=parse_interfaces_structured_for_table_apres(out_terse_ap,out_detail_ap,log_messages)
            structured_output_data_apres["interfaces_up"]=up_obj_list_ap;structured_output_data_apres["interfaces_down"]=down_obj_list_ap
            up_file_lines_ap,down_file_str_ap=parse_interfaces_for_file_display_apres(up_obj_list_ap,down_obj_list_ap)
            text_display_output_apres["interfaces_up_display"]=up_file_lines_ap;text_display_output_apres["interfaces_down_display"]=down_file_str_ap
            file_ap.write("Les Interfaces up :\n");
            if up_file_lines_ap:[file_ap.write(lstr+"\n")for lstr in up_file_lines_ap]
            else:file_ap.write("Aucune interface active trouvée.\n")
            file_ap.write("Les Interfaces down :\n");file_ap.write(down_file_str_ap+"\n");log_messages.append("OK APRES: Interfaces")
            collect_data_apres("arp_table","Informations ARP (APRES)","show arp")
            log_messages.append("Récupération APRES: Routes");file_ap.write("\nInformations sur les routes (APRES) :\nRésumé des routes :\n")
            route_sum_out_ap=connection.send_command("show route summary");structured_output_data_apres["route_summary"]=route_sum_out_ap.strip()
            file_ap.write(route_sum_out_ap+"\n");log_messages.append("OK APRES: Routes")
            collect_data_apres("ospf_status","Protocole OSPF (APRES)","show ospf interface brief")
            collect_data_apres("isis_status","Protocole IS-IS (APRES)","show isis adjacency")
            collect_data_apres("mpls_status","Protocole MPLS (APRES)","show mpls interface")
            collect_data_apres("ldp_status","Protcole LDP (APRES)","show ldp session")
            collect_data_apres("rsvp_status","Protocole RSVP (APRES)","show rsvp interface")
            collect_data_apres("lldp_status","Protocole LLDP (APRES)","show lldp neighbor")
            collect_data_apres("lsp_status","Protocole LSP (APRES)","show mpls lsp")
            collect_data_apres("bgp_status","Protocole BGP (APRES)","show bgp summary")
            def parse_svcs_ap(output):return sorted(list(set(l.strip().rstrip(";")for l in output.splitlines()if l.strip().endswith(";"))))
            collect_data_apres("system_services","Services configurés (APRES)","show configuration system services",parser_func=parse_svcs_ap)
            def parse_protos_ap(output):return sorted(list(set(l.split("{")[0].strip()for l in output.splitlines()if"{"in l and not l.strip().startswith("}"))))
            collect_data_apres("configured_protocols","Protocoles configurés (APRES)","show configuration protocols",parser_func=parse_protos_ap)
            acl_out_ap=connection.send_command("show configuration firewall")
            acl_disp_ap=acl_out_ap.strip()if acl_out_ap.strip()else"Aucune ACL configurée trouvée."
            structured_output_data_apres["firewall_config"]=acl_disp_ap
            file_ap.write("\nListes de Contrôle d'Accès (ACL) (APRES) :\n"+acl_disp_ap+"\n");log_messages.append("OK APRES: ACLs")
            log_messages.append("Récupération APRES: Logs critiques");file_ap.write("\nLogs des erreurs critiques (APRES) :\n")
            msg_logs_out_ap=connection.send_command('show log messages | match "error|warning|critical" | last 10')
            structured_output_data_apres["critical_logs_messages"]=msg_logs_out_ap.strip()
            file_ap.write("Logs des erreurs critiques dans 'messages' :\n"+msg_logs_out_ap+"\n")
            chassisd_logs_out_ap=connection.send_command('show log chassisd | match "error|warning|critical" | last 10')
            structured_output_data_apres["critical_logs_chassisd"]=chassisd_logs_out_ap.strip()
            file_ap.write("Logs des erreurs critiques dans 'chassisd' :\n"+chassisd_logs_out_ap+"\n");log_messages.append("OK APRES: Logs critiques")
            title_cfg_ap="La configuration totale (APRES)";cmd_cfg_ap="show configuration | display set"
            log_messages.append(f"Récupération APRES: {title_cfg_ap}");file_ap.write(f"\n{title_cfg_ap} :\n")
            out_cfg_ap_set=connection.send_command(cmd_cfg_ap,read_timeout=180)
            structured_output_data_apres["full_config_set"]=out_cfg_ap_set
            file_ap.write(out_cfg_ap_set+"\n");log_messages.append(f"OK APRES: {title_cfg_ap}")

        # --- Comparison ---
        log_messages.append(f"\nPréparation des données pour la comparaison AVANT/APRÈS...")
        avant_data_gen = read_file_by_line(avant_file_to_compare_path, log_messages)
        sections_from_avant_file = extract_sections(avant_data_gen, log_messages)
        apres_data_gen = read_file_by_line(apres_file_path_internal, log_messages)
        sections_from_apres_file = extract_sections(apres_data_gen, log_messages)
        
        # Use the new comparison function
        comparison_payload_for_api = create_comparison_payload(sections_from_avant_file, sections_from_apres_file, log_messages)

        comp_base_name = f"COMPARAISON_{username}_{router_hostname}.txt" # Text file for the generated diffs
        comparison_archive_file_path = os.path.join(GENERATED_FILES_DIR, comp_base_name)
        comp_counter = 1
        while os.path.exists(comparison_archive_file_path):
            comparison_archive_file_path = os.path.join(GENERATED_FILES_DIR, f"COMPARAISON_{username}_{router_hostname}_{comp_counter}.txt"); comp_counter+=1
        
        with open(comparison_archive_file_path, 'w', encoding='utf-8') as f_comp_txt:
            f_comp_txt.write("RAPPORT DE COMPARAISON AVANT/APRÈS (Format Texte Brut)\n")
            f_comp_txt.write("="*80 + "\n")
            for section_title, diff_data in comparison_payload_for_api.items():
                f_comp_txt.write(f"\nSECTION: {section_title} (Status: {diff_data['status']})\n")
                f_comp_txt.write(diff_data.get('diff_text', '(Erreur: diff_text non généré)') + "\n") # Use .get for safety
                f_comp_txt.write("-" * 80 + "\n")
        fichiers_crees_apres.append(comparison_archive_file_path)
        log_messages.append(f"Rapport de comparaison textuel sauvegardé : {comparison_archive_file_path}")
        
        original_ident_file = ident_data.get("ident_file_path")
        if original_ident_file and os.path.exists(original_ident_file):
            try: os.remove(original_ident_file); log_messages.append(f"Fichier ident {original_ident_file} supprimé.")
            except Exception as e_del_id: log_messages.append(f"Erreur suppression {original_ident_file}: {e_del_id}")
        
        log_messages.append(f"--- Fin run_apres_checks_and_compare pour {ip} ---")
        return {
            "status": "success", "message": "Vérifications APRES et comparaison terminées.",
            "apres_file_path": apres_file_path_internal, 
            "comparison_file_path": comparison_archive_file_path, 
            "structured_data_apres": structured_output_data_apres, 
            "comparison_results": comparison_payload_for_api, # This now contains pre-formatted text diffs
            "log_messages": log_messages,
            "fichiers_crees_apres": fichiers_crees_apres,
            "connection_obj": connection 
        }

    except Exception as e_generic_apres:
        import traceback
        error_msg = f"APRES: Erreur majeure: {str(e_generic_apres)} (Type: {type(e_generic_apres).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        return {"status": "error", "message": error_msg, "fichiers_crees": fichiers_crees_apres, 
                "structured_data_apres": structured_output_data_apres, "comparison_results": {},
                "log_messages": log_messages, 
                "connection_obj": connection if 'connection' in locals() and connection else None}

if __name__ == '__main__':
    print("APRES_API.py: Script chargé.")