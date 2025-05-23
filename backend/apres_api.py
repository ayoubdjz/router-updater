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
# import difflib # No longer needed for the simplified comparison

# --- Configuration & Basic Helpers ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

def verifier_connexion_apres(connection, log_messages, context="APRES"): 
    try:
        output = connection.send_command("show system uptime", read_timeout=15)
        if "error" in output.lower() or not output.strip():
            log_messages.append(f"ERREUR {context}: Comm (uptime): '{output if output else 'No output'}'"); return False
        log_messages.append(f"{context}: Connexion vérifiée (uptime): {output.strip().splitlines()[0] if output.strip() else 'OK'}"); return True
    except Exception as e: log_messages.append(f"ERREUR {context}: Connexion (exception uptime): {str(e)}"); return False

def parse_interfaces_structured_for_table_apres(output_terse, output_detail, log_messages):
    up_interfaces = []
    down_interfaces = []
    interface_status_map = {} 
    interface_ip_map = {}  

    for line in output_terse.splitlines():
        columns = line.split()
        if len(columns) >= 2:
            interface_name = columns[0]
            status = columns[1].lower()
            if "up" == status or ("up" in status and "admin" not in status):
                interface_status_map[interface_name] = "up"
            elif "down" == status:
                interface_status_map[interface_name] = "down"
            if "inet" in columns:
                try:
                    ip_index = columns.index("inet") + 1
                    if ip_index < len(columns): interface_ip_map[interface_name] = columns[ip_index]
                except ValueError: pass
    
    all_interface_details = {} 
    physical_interface_sections = output_detail.split("Physical interface:")
    if len(physical_interface_sections) > 1: physical_interface_sections = physical_interface_sections[1:] 

    for section in physical_interface_sections:
        lines = section.split("\n")
        if not lines: continue
        physical_interface_name = lines[0].strip().split(",")[0].strip()
        phys_speed = "Indisponible"; phys_mac = "N/A"
        for line in lines:
            if "Speed:" in line: phys_speed = line.split("Speed:")[1].split(",")[0].strip()
            if "Current address:" in line or "Hardware address:" in line:
                key = "Current address:" if "Current address:" in line else "Hardware address:"
                phys_mac = line.split(key)[1].strip().split(",")[0].split()[0]
        all_interface_details[physical_interface_name] = {"name": physical_interface_name, "speed": phys_speed, "mac_address": phys_mac, "ip_address": interface_ip_map.get(physical_interface_name, "N/A (Physical)")}
        logical_interface_sections = section.split("Logical interface ")
        if len(logical_interface_sections) > 1: logical_interface_sections = logical_interface_sections[1:] 
        for logical_section in logical_interface_sections:
            logical_lines = logical_section.split("\n")
            if not logical_lines: continue
            logical_interface_name = logical_lines[0].strip().split()[0].strip()
            log_ip = interface_ip_map.get(logical_interface_name, "N/A")
            if log_ip == "N/A":
                for log_line in logical_lines:
                    if "Local:" in log_line and "inet" in logical_section.lower():
                        try: 
                            parsed_log_ip = log_line.split("Local:")[1].split(",")[0].strip()
                            if parsed_log_ip: log_ip = parsed_log_ip; break
                        except IndexError: pass
            all_interface_details[logical_interface_name] = {"name": logical_interface_name, "speed": phys_speed, "ip_address": log_ip, "mac_address": phys_mac}

    for name, status_val in interface_status_map.items():
        details = all_interface_details.get(name, {"name": name, "speed": "N/A", "ip_address": interface_ip_map.get(name, "N/A"), "mac_address": "N/A"})
        details["status"] = status_val
        if status_val == "up": up_interfaces.append(details)
        else: down_interfaces.append(details)
    return up_interfaces, down_interfaces


def parse_interfaces_for_file_display_apres(up_obj_list, down_obj_list): 
    up_display_lines = []
    for iface in up_obj_list:
        line_str = f"{iface['name']} - Vitesse: {iface['speed']} - IP: {iface['ip_address']} - MAC: {iface['mac_address']}"
        up_display_lines.append(line_str)
    
    down_display_lines = []
    for iface in down_obj_list:
        line_str = f"{iface['name']} - Vitesse: {iface['speed']} - IP: {iface['ip_address']} - MAC: {iface['mac_address']}"
        down_display_lines.append(line_str)
    
    return up_display_lines, "\n".join(down_display_lines) if down_display_lines else "Aucune interface inactive trouvée."


def normalize_text(text_input): 
    try:
        if isinstance(text_input, list): return [normalize_text(line) for line in text_input]
        if not isinstance(text_input, str): text_input = str(text_input) 
        normalized = unicodedata.normalize('NFKC', text_input)
        normalized = ' '.join(normalized.split()).lower() 
        return normalized
    except Exception as e:
        return str(text_input).strip().lower() 

def detect_encoding(file_path): 
    try:
        with open(file_path, 'rb') as f: raw = f.read(1024); return chardet.detect(raw)['encoding'] or 'utf-8'
    except: return 'utf-8'

def read_file_by_line(file_path, log_messages): 
    try:
        enc = detect_encoding(file_path)
        with open(file_path, 'r', encoding=enc, errors='replace') as f:
            for line in f: yield line.rstrip('\n')
    except FileNotFoundError: log_messages.append(f"APRES Fichier {file_path} non trouvé."); yield None 
    except Exception as e: log_messages.append(f"APRES Erreur lecture {file_path}: {e}"); yield None 

def extract_sections(file_gen, log_messages): 
    sections = OrderedDict(); current_section = None
    try:
        for line_num, line_content in enumerate(file_gen): 
            if line_content is None: continue 
            stripped = line_content.strip()
            if stripped.endswith(" :") and len(stripped) < 100 and not stripped.startswith(" "): 
                current_section = stripped
                sections[current_section] = []
            elif current_section:
                if stripped: 
                    sections[current_section].append(line_content) 
    except Exception as e: log_messages.append(f"APRES Erreur extraction sections: {e}")
    return sections

def compare_sections_for_api(sections_avant, sections_apres, log_messages):
    comparison_output_for_api = OrderedDict()
    all_section_keys = sorted(list(set(sections_avant.keys()) | set(sections_apres.keys())))
    log_messages.append(f"APRES Comparaison: Clés AVANT: {list(sections_avant.keys())}")
    log_messages.append(f"APRES Comparaison: Clés APRÈS: {list(sections_apres.keys())}")
    log_messages.append(f"APRES Comparaison: Clés combinées pour comparaison: {all_section_keys}")

    for section_key in all_section_keys:
        content_avant = sections_avant.get(section_key, []) 
        content_apres = sections_apres.get(section_key, []) 

        status = ""
        if section_key in sections_avant and section_key not in sections_apres:
            status = "Seulement dans AVANT"
        elif section_key not in sections_avant and section_key in sections_apres:
            status = "Seulement dans APRÈS"
        else: 
            norm_avant_set = set(normalize_text(line) for line in content_avant if normalize_text(line))
            norm_apres_set = set(normalize_text(line) for line in content_apres if normalize_text(line))

            if norm_avant_set == norm_apres_set:
                status = "Identique"
            else:
                status = "Modifié"
        
        comparison_output_for_api[section_key] = {
            "section_title": section_key,
            "status": status,
            "avant_content": content_avant,
            "apres_content": content_apres
        }
    log_messages.append(f"APRES Comparaison terminée pour {len(all_section_keys)} sections.")
    return comparison_output_for_api

def _parse_configured_protocols_output(output, log_messages, context="APRES"):
    protocols = set()
    for line in output.splitlines():
        line_stripped = line.strip()
        if "{" in line_stripped and not line_stripped.startswith("}") and not line_stripped.startswith("#"):
            protocol_name = line_stripped.split("{")[0].strip()
            if protocol_name and not ' ' in protocol_name and len(protocol_name) > 0:
                protocols.add(protocol_name)
    if protocols:
        return sorted(list(protocols))
    else:
        msg = "Aucun protocole configuré trouvé dans la sortie."
        return {"message": msg, "protocols": []}

def _parse_firewall_acls_output(output, log_messages, context="APRES"):
    output_stripped = output.strip()
    if output_stripped:
        return output_stripped
    else:
        msg = "Aucune ACL configurée trouvée dans la sortie."
        return msg

def run_apres_checks_and_compare(ident_data, password, log_messages, avant_connection=None): 
    ip = ident_data.get("ip"); username = ident_data.get("username")
    avant_file_to_compare_path = ident_data.get("avant_file_path")
    router_hostname = ident_data.get("router_hostname", "inconnu") 
    original_ident_file_path = ident_data.get("ident_file_path") 

    if not all([ip, username, avant_file_to_compare_path]):
        msg = "APRES: ident_data (ip, username, avant_file_path) incomplet."
        log_messages.append(msg)
        return {"status": "error", "message": msg, "logs": log_messages, "structured_data_apres": {}, "comparison_results": {}}
    if not os.path.exists(avant_file_to_compare_path):
        msg = f"APRES: Fichier AVANT {avant_file_to_compare_path} non trouvé pour comparaison."
        log_messages.append(msg)
        return {"status": "error", "message": msg, "logs": log_messages, "structured_data_apres": {}, "comparison_results": {}}

    fichiers_crees_apres = []; connection = None 
    apres_file_path_internal = None; comparison_file_path_for_archive = None 
    
    structured_output_data_apres = { 
        "basic_info": {}, "routing_engine_status": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_status": "", "isis_status": "", "mpls_status": "",
        "ldp_status": "", "rsvp_status": "", "lldp_status": "", "lsp_status": "", "bgp_summary": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": "",
        
    }
    
    try:
        log_messages.append(f"--- Début run_apres_checks_and_compare pour {ip} ---")
        device = {'device_type':'juniper','host':ip,'username':username,'password':password,
                  'timeout':30, 'auth_timeout': 45, 'banner_timeout': 45, 'global_delay_factor': 2}
        log_messages.append(f"APRES: Connexion à {ip}..."); connection = ConnectHandler(**device)
        log_messages.append(f"APRES: Connecté succès à {ip}")
        try:
            connection.send_command('set cli screen-length 0', expect_string=r'[\#>]')
            log_messages.append("APRES: Pagination CLI désactivée (set cli screen-length 0).")
        except Exception as e_pagination:
            log_messages.append(f"APRES Warning: Impossible de désactiver la pagination CLI: {str(e_pagination)}")

        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True) 
        if not os.access(GENERATED_FILES_DIR, os.W_OK): 
            raise PermissionError(f"APRES: Pas accès écriture à {GENERATED_FILES_DIR}")
        temp_apres_file_obj = tempfile.NamedTemporaryFile(mode='w+', prefix='APRES_', suffix='.txt', delete=False, encoding='utf-8', dir=GENERATED_FILES_DIR)
        apres_file_path_internal = temp_apres_file_obj.name; fichiers_crees_apres.append(apres_file_path_internal)

        section_title_basic_ap = "Informations de base du routeur" 
        structured_output_data_apres["basic_info"]["section_title_display"] = f"{section_title_basic_ap} (APRES)"
        temp_apres_file_obj.write(f"{section_title_basic_ap} :\n") 

        out_ver_ap = connection.send_command('show version | no-more')
        if isinstance(out_ver_ap, str): # Apply pagination filtering
            out_ver_lines = out_ver_ap.splitlines()
            cleaned_ver_lines = [line for line in out_ver_lines if not line.strip().startswith("---(more")]
            out_ver_ap = "\n".join(cleaned_ver_lines)

        j_ver_ap, r_model_ap, cur_host_ap = "inconnu", "inconnu", router_hostname 
        for l in out_ver_ap.splitlines():
            if l.startswith("Hostname:"): cur_host_ap = l.split("Hostname:")[1].strip()
            elif l.startswith("Model:"): r_model_ap = l.split("Model:")[1].strip()
            elif l.startswith("Junos:"): j_ver_ap = l.split("Junos:")[1].strip()
        
        if cur_host_ap != "inconnu" and cur_host_ap != router_hostname:
            log_messages.append(f"APRES: Hostname a changé de {router_hostname} à {cur_host_ap}.")
            router_hostname = cur_host_ap 

        structured_output_data_apres["basic_info"]["hostname"] = cur_host_ap
        structured_output_data_apres["basic_info"]["model"] = r_model_ap
        structured_output_data_apres["basic_info"]["junos_version"] = j_ver_ap
        temp_apres_file_obj.write(f"Le hostname du routeur est : {cur_host_ap}\n")
        temp_apres_file_obj.write(f"Le modele du routeur est : {r_model_ap}\n")
        temp_apres_file_obj.write(f"La version du systeme Junos est : {j_ver_ap}\n")
        log_messages.append(f"APRES Basic Info: Host={cur_host_ap}, Model={r_model_ap}, Junos={j_ver_ap}")
        
        temp_apres_file_obj.flush(); temp_apres_file_obj.close()
        if not os.path.exists(apres_file_path_internal): 
            raise FileNotFoundError(f"APRES: Disparition temp file: {apres_file_path_internal}")
        
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
        except OSError as e_rep_ap: 
            log_messages.append(f"APRES ERREUR renommage: {e_rep_ap}. Utilisation temp: {apres_file_path_internal}")

        with open(apres_file_path_internal, 'a', encoding='utf-8') as file_ap:
            
            def fetch_and_store_apres(data_key_structured, title_for_file_key, cmd, 
                                      parser_func=None, is_raw=True, read_timeout=90,
                                      not_configured_check=None): 
                if not verifier_connexion_apres(connection, log_messages, "APRES Collect"): 
                    log_messages.append(f"ERREUR APRES: Connexion perdue avant collecte de: {title_for_file_key}")
                    structured_output_data_apres[data_key_structured] = f"ERREUR: Connexion perdue avant collecte de {title_for_file_key}"
                    file_ap.write(f"\n{title_for_file_key} :\n")
                    file_ap.write(f"ERREUR: Connexion perdue.\n")
                    raise Exception(f"APRES: Connexion perdue avant collecte de: {title_for_file_key}")

                log_messages.append(f"APRES Récupération: {title_for_file_key} (Cmd: {cmd[:70]}{'...' if len(cmd)>70 else ''})")
                file_ap.write(f"\n{title_for_file_key} :\n")
                
                output = ""
                try:
                    cmd_to_send = cmd
                    if not cmd.strip().endswith("| no-more") and not cmd.strip().endswith("no-more"):
                         cmd_to_send = f"{cmd.strip()} | no-more"
                    
                    output = connection.send_command(cmd_to_send, read_timeout=read_timeout)

                    # --- Pagination Filtering ---
                    if isinstance(output, str):
                        output_lines = output.splitlines()
                        cleaned_lines = [line for line in output_lines if not line.strip().startswith("---(more")]
                        output = "\n".join(cleaned_lines)
                    # --- End Pagination Filtering ---

                except Exception as e_cmd:
                    err_msg = f"ERREUR APRES: Echec commande '{cmd_to_send[:70]}{'...' if len(cmd_to_send)>70 else ''}' pour '{title_for_file_key}': {e_cmd}"
                    log_messages.append(err_msg)
                    structured_output_data_apres[data_key_structured] = err_msg
                    file_ap.write(err_msg + "\n")
                    log_messages.append(f"APRES ECHEC: {title_for_file_key}")
                    return 

                if not_configured_check:
                    keywords, message_if_found = not_configured_check
                    output_lower_for_check = output.lower() 
                    if any(keyword.lower() in output_lower_for_check for keyword in keywords):
                        structured_output_data_apres[data_key_structured] = message_if_found
                        file_ap.write(message_if_found + "\n")
                        log_messages.append(f"APRES INFO ({title_for_file_key}): {message_if_found}")
                        log_messages.append(f"APRES OK (Not Configured): {title_for_file_key}")
                        return

                if parser_func:
                    try:
                        parsed_data = parser_func(output, log_messages, "APRES Parse") 
                        structured_output_data_apres[data_key_structured] = parsed_data
                        if isinstance(parsed_data, list) and parsed_data and isinstance(parsed_data[0], dict):
                            for item_dict in parsed_data:
                                for k_item,v_item in item_dict.items(): file_ap.write(f"  {k_item}: {v_item}\n")
                                file_ap.write("\n")
                        elif isinstance(parsed_data, list):
                            for item_str in parsed_data: file_ap.write(f"{item_str}\n")
                        elif isinstance(parsed_data, dict) and "message" in parsed_data:
                             file_ap.write(str(parsed_data["message"]) + "\n")
                        else: 
                            file_ap.write(str(parsed_data) + "\n")
                    except Exception as e_parse:
                        parse_err_msg = f"ERREUR APRES: Echec parsing pour '{title_for_file_key}': {e_parse}. Output:\n{output[:200]}..."
                        log_messages.append(parse_err_msg)
                        structured_output_data_apres[data_key_structured] = {"error": parse_err_msg, "raw_output": output.strip()}
                        file_ap.write(output.strip() + f"\n# PARSE_ERROR: {parse_err_msg}\n")
                elif is_raw:
                    data_to_store = output.strip()
                    structured_output_data_apres[data_key_structured] = data_to_store
                    file_ap.write(data_to_store + "\n")
                else: 
                    lines = [l.strip() for l in output.splitlines() if l.strip()]
                    structured_output_data_apres[data_key_structured] = lines
                    for line_item in lines: file_ap.write(f"{line_item}\n")
                
                log_messages.append(f"APRES OK: {title_for_file_key}")

            fetch_and_store_apres("routing_engine_status", "Informations du moteur de routage", "show chassis routing-engine", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            
            section_title_interfaces_ap = "Informations sur les interfaces" 
            log_messages.append(f"APRES Récupération: {section_title_interfaces_ap}"); 
            file_ap.write(f"\n{section_title_interfaces_ap} :\n")
            out_terse_ap = connection.send_command("show interfaces terse | no-more", read_timeout=90)
            if isinstance(out_terse_ap, str): # Apply pagination filtering
                out_terse_lines = out_terse_ap.splitlines()
                cleaned_terse_lines = [line for line in out_terse_lines if not line.strip().startswith("---(more")]
                out_terse_ap = "\n".join(cleaned_terse_lines)
            out_detail_ap = connection.send_command("show interfaces detail | no-more", read_timeout=180)
            if isinstance(out_detail_ap, str): # Apply pagination filtering
                out_detail_lines = out_detail_ap.splitlines()
                cleaned_detail_lines = [line for line in out_detail_lines if not line.strip().startswith("---(more")]
                out_detail_ap = "\n".join(cleaned_detail_lines)

            up_obj_list_ap, down_obj_list_ap = parse_interfaces_structured_for_table_apres(out_terse_ap, out_detail_ap, log_messages)
            structured_output_data_apres["interfaces_up"] = up_obj_list_ap
            structured_output_data_apres["interfaces_down"] = down_obj_list_ap
            up_file_lines_ap, down_file_str_ap = parse_interfaces_for_file_display_apres(up_obj_list_ap, down_obj_list_ap)
            file_ap.write("Les Interfaces up :\n"); 
            if up_file_lines_ap: [file_ap.write(lstr + "\n") for lstr in up_file_lines_ap]
            else: file_ap.write("Aucune interface active trouvée.\n")
            file_ap.write("Les Interfaces down :\n"); file_ap.write(down_file_str_ap + "\n")
            log_messages.append(f"APRES OK: {section_title_interfaces_ap}")

            fetch_and_store_apres("arp_table", "Informations ARP", "show arp", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)

            section_title_routes_ap = "Informations sur les routes" 
            file_ap.write(f"\n{section_title_routes_ap} :\n") 
            log_messages.append(f"APRES Récupération: {section_title_routes_ap} - Résumé")
            file_ap.write("Resume des routes :\n") 
            try:
                route_sum_out_ap = connection.send_command("show route summary | no-more", read_timeout=90)
                if isinstance(route_sum_out_ap, str): # Apply pagination filtering
                    rs_lines = route_sum_out_ap.splitlines()
                    cleaned_rs_lines = [line for line in rs_lines if not line.strip().startswith("---(more")]
                    route_sum_out_ap = "\n".join(cleaned_rs_lines)
                structured_output_data_apres["route_summary"] = route_sum_out_ap.strip()
                file_ap.write(route_sum_out_ap.strip() + "\n")
                log_messages.append(f"APRES OK: {section_title_routes_ap} - Résumé")
            except Exception as e_route_sum:
                err_msg = f"ERREUR APRES: Echec commande 'show route summary' pour '{section_title_routes_ap}': {e_route_sum}"
                log_messages.append(err_msg)
                structured_output_data_apres["route_summary"] = err_msg
                file_ap.write(err_msg + "\n")
                log_messages.append(f"APRES ECHEC: {section_title_routes_ap} - Résumé")
            
            fetch_and_store_apres("ospf_status", "Protocole OSPF", "show ospf interface brief", parser_func=None, is_raw=True, read_timeout=90, 
                not_configured_check=(["OSPF instance is not running", "not running", "not configured"], "OSPF n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("isis_status", "Protocole IS-IS", "show isis adjacency", parser_func=None, is_raw=True, read_timeout=90,
                not_configured_check=(["ISIS is not running", "not running", "not configured"], "IS-IS n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("mpls_status", "Protocole MPLS", "show mpls interface", parser_func=None, is_raw=True, read_timeout=90,
                not_configured_check=(["MPLS is not enabled", "not enabled", "not configured"], "MPLS n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("ldp_status", "Protocole LDP", "show ldp session", parser_func=None, is_raw=True, read_timeout=90,
                not_configured_check=(["LDP is not running", "not running", "not configured"], "LDP n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("rsvp_status", "Protocole RSVP", "show rsvp interface", parser_func=None, is_raw=True, read_timeout=90,
                not_configured_check=(["RSVP is not enabled", "not enabled", "not configured"], "RSVP n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("lldp_status", "Protocole LLDP", "show lldp neighbor", parser_func=None, is_raw=True, read_timeout=90,
                not_configured_check=(["LLDP is not running", "not running", "not configured"], "LLDP n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("lsp_status", "Protocole LSP", "show mpls lsp", parser_func=None, is_raw=True, read_timeout=90,
                not_configured_check=(["No LSPs found", "not configured"], "Aucun LSP configuré sur ce routeur."))
            fetch_and_store_apres("bgp_summary", "Protocole BGP", "show bgp summary", parser_func=None, is_raw=True, read_timeout=90,
                not_configured_check=(["BGP is not running", "not running", "not configured"], "BGP n'est pas configuré sur ce routeur."))
            
            def parse_svcs_ap(output, log_msgs_ignore, context_ignore): 
                return sorted(list(set(l.strip().rstrip(";") for l in output.splitlines() if l.strip().endswith(";"))))
            fetch_and_store_apres("system_services", "Services configurés", "show configuration system services", 
                parser_func=parse_svcs_ap, is_raw=False, read_timeout=90, not_configured_check=None)
            
            fetch_and_store_apres("configured_protocols", "Protocoles configurés", "show configuration protocols", 
                parser_func=_parse_configured_protocols_output, is_raw=False, read_timeout=90, not_configured_check=None)

            fetch_and_store_apres("firewall_config", "Listes de Controle d'Acces (ACL)", "show configuration firewall",
                parser_func=_parse_firewall_acls_output, is_raw=False, read_timeout=90, not_configured_check=None)

            # --- Critical Logs using fetch_and_store_apres ---
            log_msg_cmd_ap = 'show log messages | match "error|warning|critical" | last 10'
            fetch_and_store_apres(
                data_key_structured="critical_logs_messages",
                title_for_file_key="Logs des erreurs critiques - messages", # Consistent title for comparison
                cmd=log_msg_cmd_ap,
                is_raw=True,
                read_timeout=60
            )

            chassisd_log_cmd_ap = 'show log chassisd | match "error|warning|critical" | last 10'
            fetch_and_store_apres(
                data_key_structured="critical_logs_chassisd",
                title_for_file_key="Logs des erreurs critiques - chassisd", # Consistent title for comparison
                cmd=chassisd_log_cmd_ap,
                is_raw=True,
                read_timeout=60
            )
            # --- End Critical Logs ---
            
            fetch_and_store_apres("full_config_set", "La configuration totale", "show configuration | display set", 
                parser_func=None, is_raw=True, read_timeout=300, not_configured_check=None)

        log_messages.append(f"\nAPRES Lancement comparaison (file-based) AVANT/APRES...")
        avant_data_gen = read_file_by_line(avant_file_to_compare_path, log_messages)
        sections_from_avant_file = extract_sections(avant_data_gen, log_messages)
        
        apres_data_gen = read_file_by_line(apres_file_path_internal, log_messages)
        sections_from_apres_file = extract_sections(apres_data_gen, log_messages)
        
        if not sections_from_avant_file and avant_data_gen is None: 
            log_messages.append("APRES ERREUR: sections_from_avant_file est vide car le fichier AVANT n'a pas pu être lu.")
        if not sections_from_apres_file and apres_data_gen is None:
            log_messages.append("APRES ERREUR: sections_from_apres_file est vide car le fichier APRES n'a pas pu être lu.")

        comparison_results_for_api = compare_sections_for_api(sections_from_avant_file, sections_from_apres_file, log_messages)

        comp_base_name = f"COMPARAISON_{username}_{router_hostname}.txt"
        comparison_file_path_for_archive = os.path.join(GENERATED_FILES_DIR, comp_base_name)
        comp_counter = 1
        while os.path.exists(comparison_file_path_for_archive):
            comparison_file_path_for_archive = os.path.join(GENERATED_FILES_DIR, f"COMPARAISON_{username}_{router_hostname}_{comp_counter}.txt"); comp_counter+=1
        
        with open(comparison_file_path_for_archive, 'w', encoding='utf-8') as f_comp:
            f_comp.write("RAPPORT DE COMPARAISON AVANT/APRÈS\n" + "="*80 + "\n")
            for section_key, data in comparison_results_for_api.items():
                f_comp.write(f"\nSECTION: {data['section_title']} (Status: {data['status']})\n")
                
                content_avant = data['avant_content']
                content_apres = data['apres_content']
                max_lines = max(len(content_avant), len(content_apres))
                
                apres_col_width = 100
                avant_col_width = 100  
                
                f_comp.write(f"{'AVANT'.center(avant_col_width)} | {'APRÈS'.center(apres_col_width)}\n")
                f_comp.write(f"{'-'*avant_col_width} | {'-'*apres_col_width}\n")
                
                for i in range(max_lines):
                    line_av = content_avant[i] if i < len(content_avant) else ""
                    line_ap = content_apres[i] if i < len(content_apres) else ""
                    f_comp.write(f"{line_av.ljust(avant_col_width)[:avant_col_width]} | {line_ap.ljust(apres_col_width)[:apres_col_width]}\n")
                f_comp.write("-" * (avant_col_width + apres_col_width + 3) + "\n") 
        fichiers_crees_apres.append(comparison_file_path_for_archive)
        log_messages.append(f"APRES: Rapport de comparaison textuel sauvegardé : {comparison_file_path_for_archive}")
        
        if original_ident_file_path and os.path.exists(original_ident_file_path):
            try: 
                os.remove(original_ident_file_path); 
                log_messages.append(f"APRES: Fichier identifiant {original_ident_file_path} de l'étape AVANT supprimé.")
            except Exception as e_del_id: 
                log_messages.append(f"APRES Erreur suppression ancien fichier identifiant {original_ident_file_path}: {e_del_id}")
        else:
            log_messages.append(f"APRES: Ancien fichier identifiant ({original_ident_file_path}) non trouvé ou non spécifié pour suppression.")

        for key, value in list(structured_output_data_apres.items()): 
            if isinstance(value, str) and not value.strip() and not key.startswith("critical_logs"): 
                structured_output_data_apres[key] = {"message": f"Aucune donnée trouvée pour {key}."}
            elif isinstance(value, list) and not value:
                if key not in ["interfaces_up", "interfaces_down"]: # Allow these to be empty lists
                    structured_output_data_apres[key] = {"message": f"Aucune donnée trouvée pour {key}."}
        log_messages.append(f"--- Fin run_apres_checks_and_compare pour {ip} ---")
        return {
            "status": "success", "message": "Vérifications APRES et comparaison terminées.",
            "apres_file_path": apres_file_path_internal, 
            "comparison_file_path": comparison_file_path_for_archive, 
            "structured_data_apres": structured_output_data_apres, 
            "comparison_results": comparison_results_for_api, 
            "log_messages": log_messages,
            "fichiers_crees_apres": fichiers_crees_apres, 
            "connection_obj": connection 
        }

    except Exception as e_generic_apres:
        import traceback
        error_msg = f"APRES: Erreur majeure: {str(e_generic_apres)} (Type: {type(e_generic_apres).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        for key_data in structured_output_data_apres:
            if not structured_output_data_apres[key_data] or \
               (isinstance(structured_output_data_apres[key_data], dict) and not structured_output_data_apres[key_data]):
                structured_output_data_apres[key_data] = {"message": f"Collecte interrompue par erreur: {error_msg}"}

        return {"status": "error", "message": error_msg, 
                "fichiers_crees_apres": fichiers_crees_apres, 
                "structured_data_apres": structured_output_data_apres, "comparison_results": {},
                "log_messages": log_messages, 
                "connection_obj": connection if 'connection' in locals() and connection else None}

if __name__ == '__main__':
    print("APRES_API.py: Script chargé.")