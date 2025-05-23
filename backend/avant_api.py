import os
import sys
import json
import time
import warnings
from pathlib import Path
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import ipaddress
import tempfile
import portalocker
import subprocess # Kept for potential (though not ideal) direct APRES call
from netmiko import NetmikoTimeoutException, ReadTimeout
import re

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCK_DIR = os.path.join(SCRIPT_DIR, "router_locks")
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
Path(LOCK_DIR).mkdir(exist_ok=True, parents=True)
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

# --- Helper Functions (verrouiller_routeur, liberer_verrou, etc. remain the same as the last "whole file content" version) ---
def verrouiller_routeur(ip, log_messages):
    warnings.filterwarnings("ignore", category=UserWarning, module="portalocker.utils")
    Path(LOCK_DIR).mkdir(exist_ok=True, parents=True)
    ip_normalisee = ip.replace('.', '_')
    lock_file_path = os.path.join(LOCK_DIR, f"{ip_normalisee}.lock")
    try:
        lock = portalocker.Lock(lock_file_path, mode='w', flags=portalocker.LOCK_EX | portalocker.LOCK_NB)
        lock.acquire(timeout=0.1)
        log_messages.append(f"Routeur {ip} verrouillé (fichier créé/acquis: {lock_file_path}).")
        lock.release()
        log_messages.append(f"Verrou objet Python libéré pour {lock_file_path}, le fichier persiste comme sémaphore.")
        return True, lock_file_path
    except (portalocker.LockException, BlockingIOError) as e_lock_portal:
        if os.path.exists(lock_file_path):
            msg = (f"Impossible de verrouiller le routeur {ip}. Verrou ({lock_file_path}) "
                   f"activement détenu par un autre processus ou inaccessible. Erreur: {e_lock_portal}")
        else:
            msg = (f"Impossible de créer/verrouiller le fichier de verrou pour {ip} à {lock_file_path}. "
                   f"Vérifiez les permissions ou si le chemin est valide. Erreur: {e_lock_portal}")
        log_messages.append(msg)
        return False, lock_file_path
    except Exception as e:
        msg = f"Erreur inattendue lors de la tentative de verrouillage de {ip} ({lock_file_path}): {e}"
        log_messages.append(msg)
        return False, lock_file_path

def liberer_verrou(lock_file_path, log_messages):
    if lock_file_path and os.path.exists(lock_file_path):
        try:
            os.remove(lock_file_path)
            log_messages.append(f"Fichier de verrou {lock_file_path} supprimé (libéré).")
            return True
        except Exception as e:
            log_messages.append(f"Erreur lors de la suppression du fichier de verrou {lock_file_path}: {e}")
            return False
    elif lock_file_path:
        log_messages.append(f"Fichier de verrou {lock_file_path} non trouvé pour suppression (déjà libéré ou jamais créé).")
        return True
    else:
        log_messages.append("Aucun chemin de fichier de verrou fourni pour la libération.")
        return False

def verifier_connexion(connection, log_messages, context="AVANT"):
    try:
        output = connection.send_command("show system uptime", read_timeout=15)
        if "error" in output.lower() or not output.strip():
            log_messages.append(f"ERREUR {context}: Problème de communication détecté (show system uptime): '{output if output else 'No output'}'")
            return False
        log_messages.append(f"{context}: Connexion vérifiée (uptime): {output.strip().splitlines()[0] if output.strip() else 'OK'}")
        return True
    except Exception as e:
        log_messages.append(f"ERREUR {context}: Problème de connexion (exception pendant show system uptime): {str(e)}")
        return False

def valider_ip(ip):
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

def parse_interfaces_structured(output_terse, output_detail, log_messages):
    """ Parses interface data and returns structured lists for up/down interfaces. """
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
                    if ip_index < len(columns):
                        interface_ip_map[interface_name] = columns[ip_index]
                except ValueError:
                    pass 
    
    all_interface_details = {} 

    physical_interface_sections = output_detail.split("Physical interface:")
    if len(physical_interface_sections) > 1:
        physical_interface_sections = physical_interface_sections[1:] 

    for section in physical_interface_sections:
        lines = section.split("\n")
        if not lines: continue
        
        physical_name_line = lines[0].strip()
        physical_interface_name = physical_name_line.split(",")[0].strip()
        
        phys_speed = "Indisponible"
        phys_mac = "N/A"
        
        for line_idx, line in enumerate(lines):
            if "Speed:" in line:
                try: phys_speed = line.split("Speed:")[1].split(",")[0].strip()
                except IndexError: pass
            if "Current address:" in line or "Hardware address:" in line: 
                try:
                    key = "Current address:" if "Current address:" in line else "Hardware address:"
                    phys_mac = line.split(key)[1].strip().split(",")[0].split()[0] 
                except IndexError: pass

        all_interface_details[physical_interface_name] = {
            "name": physical_interface_name,
            "speed": phys_speed, 
            "mac_address": phys_mac,
            "ip_address": interface_ip_map.get(physical_interface_name, "N/A (Physical)")
        }

        logical_interface_sections = section.split("Logical interface ")
        if len(logical_interface_sections) > 1:
            logical_interface_sections = logical_interface_sections[1:] 

        for logical_section in logical_interface_sections:
            logical_lines = logical_section.split("\n")
            if not logical_lines: continue
            
            logical_name_line = logical_lines[0].strip()
            logical_interface_name = logical_name_line.split()[0].strip() 
            
            log_ip = interface_ip_map.get(logical_interface_name, "N/A")
            
            if log_ip == "N/A":
                for log_line in logical_lines:
                    if "Local:" in log_line and "inet" in logical_section.lower(): 
                        try: 
                            parsed_log_ip = log_line.split("Local:")[1].split(",")[0].strip()
                            if parsed_log_ip: 
                                log_ip = parsed_log_ip
                                break 
                        except IndexError: pass
            
            all_interface_details[logical_interface_name] = {
                "name": logical_interface_name,
                "speed": phys_speed, 
                "ip_address": log_ip, 
                "mac_address": phys_mac 
            }

    for name, status_val in interface_status_map.items():
        details = all_interface_details.get(name, 
            {"name": name, "speed": "N/A", "ip_address": interface_ip_map.get(name, "N/A"), "mac_address": "N/A"}
        )
        details["status"] = status_val 
        if status_val == "up":
            up_interfaces.append(details)
        else: 
            down_interfaces.append(details)
            
    return up_interfaces, down_interfaces

# --- New Parser Helper Functions for AVANT ---
def _parse_services_avant(output, log_messages, context="AVANT Parse"):
    return sorted(list(set(l.strip().rstrip(";") for l in output.splitlines() if l.strip().endswith(";"))))

def _parse_configured_protocols_output_avant(output, log_messages, context="AVANT Parse"):
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

def _parse_firewall_acls_output_avant(output, log_messages, context="AVANT Parse"):
    output_stripped = output.strip()
    if output_stripped:
        return output_stripped
    else:
        msg = "Aucune ACL configurée trouvée dans la sortie."
        return msg
# --- End New Parser Helper Functions ---


# --- Main Process Function for AVANT ---
def run_avant_checks(ip, username, password, log_messages):
    if not valider_ip(ip):
        log_messages.append("Adresse IP invalide.")
        return {"status": "error", "message": "Adresse IP invalide.", "logs": log_messages, "structured_data": {}}

    fichiers_crees_avant = []
    connection = None
    lock_file_path = None
    avant_file_path_internal = None
    config_file_path = None
    identifiants_file_path = None
    router_hostname = "inconnu"
    
    structured_output_data = {
        "basic_info": {}, "routing_engine": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_info": "", "isis_info": "", "mpls_info": "",
        "ldp_info": "", "rsvp_info": "", "lldp_info": "", "lsp_info": "", "bgp_summary": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": "",
        "var": "var"
    }

    try:
        log_messages.append(f"--- Début run_avant_checks pour {ip} ---")
        lock_acquired, attempted_lock_path = verrouiller_routeur(ip, log_messages)
        lock_file_path = attempted_lock_path
        if not lock_acquired:
            return {"status": "error", "message": f"Impossible de verrouiller le routeur {ip}. Voir logs.", 
                    "lock_file_path": lock_file_path, "logs": log_messages, "structured_data": structured_output_data}

        device = {'device_type': 'juniper', 'host': ip, 'username': username, 'password': password,
                  'timeout': 30, 'auth_timeout': 45, 'banner_timeout': 45, 'global_delay_factor': 2}
        log_messages.append(f"AVANT: Tentative de connexion à {ip}...")
        connection = ConnectHandler(**device)
        log_messages.append(f"AVANT: Connecté avec succès au routeur {ip}")
        
        try:
            pagination_off_command = 'set cli screen-length 0'
            log_messages.append(f"AVANT: Tentative de désactivation de la pagination CLI: {pagination_off_command}")
            connection.send_command_timing(
                pagination_off_command, read_timeout=15, delay_factor=1, max_loops=50, expect_string=r'[\#>]' 
            )
            log_messages.append("AVANT: Commande 'set cli screen-length 0' envoyée.")
        except Exception as e_pagination:
            log_messages.append(f"AVANT WARNING: Echec désactivation pagination CLI: {str(e_pagination)}. Utilisation de '| no-more'.")


        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True) 
        if not os.access(GENERATED_FILES_DIR, os.W_OK):
            raise PermissionError(f"AVANT CRITICAL: Pas d'accès en écriture à GENERATED_FILES_DIR ({GENERATED_FILES_DIR})!")
        
        temp_avant_file_obj = tempfile.NamedTemporaryFile(
            mode='w+', prefix='AVANT_', suffix='.txt', delete=False, encoding='utf-8', dir=GENERATED_FILES_DIR)
        avant_file_path_internal = temp_avant_file_obj.name
        log_messages.append(f"AVANT: Fichier temporaire ouvert: {avant_file_path_internal}")
        fichiers_crees_avant.append(avant_file_path_internal) 

        section_title_basic = "Informations de base du routeur"
        structured_output_data["basic_info"]["section_title"] = section_title_basic
        temp_avant_file_obj.write(f"{section_title_basic} :\n")
        
        try:
            output_version = connection.send_command("show version | no-more", read_timeout=30)
            if isinstance(output_version, str): # Apply pagination filtering
                output_lines = output_version.splitlines()
                cleaned_lines = [line for line in output_lines if not line.strip().startswith("---(more")]
                output_version = "\n".join(cleaned_lines)
        except Exception as e_ver:
            log_messages.append(f"AVANT ERREUR: Echec 'show version': {e_ver}")
            output_version = f"ERREUR: Echec 'show version': {e_ver}"
            structured_output_data["basic_info"].update({
                "hostname": "Erreur", "model": "Erreur", "junos_version": "Erreur",
                "error_message": str(e_ver)
            })

        junos_version, router_model = "inconnu", "inconnu"
        for line in output_version.splitlines():
            if line.startswith("Hostname:"): router_hostname = line.split("Hostname:")[1].strip()
            elif line.startswith("Model:"): router_model = line.split("Model:")[1].strip()
            elif line.startswith("Junos:"): junos_version = line.split("Junos:")[1].strip()
        
        if "error_message" not in structured_output_data["basic_info"]:
            structured_output_data["basic_info"]["hostname"] = router_hostname
            structured_output_data["basic_info"]["model"] = router_model
            structured_output_data["basic_info"]["junos_version"] = junos_version
        
        temp_avant_file_obj.write(f"Le hostname du routeur est : {router_hostname}\n")
        temp_avant_file_obj.write(f"Le modele du routeur est : {router_model}\n")
        temp_avant_file_obj.write(f"La version du systeme Junos est : {junos_version}\n")
        log_messages.append(f"AVANT Basic Info: Host={router_hostname}, Model={router_model}, Junos={junos_version}")

        temp_avant_file_obj.flush(); temp_avant_file_obj.close() 
        if not os.path.exists(avant_file_path_internal): 
            raise FileNotFoundError(f"AVANT: Disparition critique du fichier temporaire: {avant_file_path_internal}")

        final_avant_base = f"AVANT_{username}_{router_hostname}.txt"
        final_avant_path = os.path.join(GENERATED_FILES_DIR, final_avant_base)
        compteur = 1
        while os.path.exists(final_avant_path):
            final_avant_path = os.path.join(GENERATED_FILES_DIR, f"AVANT_{username}_{router_hostname}_{compteur}.txt")
            compteur += 1
        try:
            os.replace(avant_file_path_internal, final_avant_path)
            log_messages.append(f"AVANT: Fichier renommé en: {final_avant_path}")
            if avant_file_path_internal in fichiers_crees_avant: fichiers_crees_avant.remove(avant_file_path_internal)
            avant_file_path_internal = final_avant_path
            if avant_file_path_internal not in fichiers_crees_avant: fichiers_crees_avant.append(avant_file_path_internal)
        except OSError as e_replace:
            log_messages.append(f"AVANT ERREUR renommage: {e_replace}. Utilisation du nom temporaire: {avant_file_path_internal}")
        
        with open(avant_file_path_internal, 'a', encoding='utf-8') as file: 
            
            def fetch_and_store_avant(data_key_structured, title_for_file_key, cmd, 
                                      parser_func=None, is_raw=True, read_timeout=90,
                                      not_configured_check=None):
                if not verifier_connexion(connection, log_messages, "AVANT Collect"): 
                    log_messages.append(f"ERREUR AVANT: Connexion perdue avant collecte de: {title_for_file_key}")
                    structured_output_data[data_key_structured] = f"ERREUR: Connexion perdue avant collecte de {title_for_file_key}"
                    file.write(f"\n{title_for_file_key} :\n") 
                    file.write(f"ERREUR: Connexion perdue.\n")
                    raise Exception(f"AVANT: Connexion perdue avant collecte de: {title_for_file_key}")

                log_messages.append(f"AVANT Récupération: {title_for_file_key} (Cmd: {cmd[:70]}{'...' if len(cmd)>70 else ''})")
                file.write(f"\n{title_for_file_key} :\n") 
                
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
                    err_msg = f"ERREUR AVANT: Echec commande '{cmd_to_send[:70]}{'...' if len(cmd_to_send)>70 else ''}' pour '{title_for_file_key}': {e_cmd}"
                    log_messages.append(err_msg)
                    structured_output_data[data_key_structured] = err_msg
                    file.write(err_msg + "\n")
                    log_messages.append(f"AVANT ECHEC: {title_for_file_key}")
                    return

                if not_configured_check: 
                    keywords, message_if_found = not_configured_check
                    output_lower_for_check = output.lower()
                    if any(keyword.lower() in output_lower_for_check for keyword in keywords):
                        structured_output_data[data_key_structured] = message_if_found
                        file.write(message_if_found + "\n")
                        log_messages.append(f"AVANT INFO ({title_for_file_key}): {message_if_found}")
                        log_messages.append(f"AVANT OK (Not Configured/Found): {title_for_file_key}")
                        return

                if parser_func:
                    try:
                        parsed_data = parser_func(output, log_messages, "AVANT Parse") 
                        structured_output_data[data_key_structured] = parsed_data
                        if isinstance(parsed_data, list) and parsed_data and isinstance(parsed_data[0], dict):
                            for item_dict in parsed_data: 
                                for k_item,v_item in item_dict.items(): file.write(f"  {k_item}: {v_item}\n")
                                file.write("\n")
                        elif isinstance(parsed_data, list): 
                            for item_str in parsed_data: file.write(f"{item_str}\n")
                        elif isinstance(parsed_data, dict) and "message" in parsed_data: 
                             file.write(str(parsed_data["message"]) + "\n")
                        else: 
                             file.write(str(parsed_data) + "\n")
                    except Exception as e_parse:
                        parse_err_msg = f"ERREUR AVANT: Echec parsing pour '{title_for_file_key}': {e_parse}. Output:\n{output[:200]}..."
                        log_messages.append(parse_err_msg)
                        structured_output_data[data_key_structured] = {"error": parse_err_msg, "raw_output": output.strip()}
                        file.write(output.strip() + f"\n# PARSE_ERROR: {parse_err_msg}\n")
                elif is_raw:
                    data_to_store = output.strip()
                    structured_output_data[data_key_structured] = data_to_store
                    file.write(data_to_store + "\n")
                else: 
                    lines = [l.strip() for l in output.splitlines() if l.strip()]
                    structured_output_data[data_key_structured] = lines
                    for line_item in lines: file.write(f"{line_item}\n")
                
                log_messages.append(f"AVANT OK: {title_for_file_key}")

            fetch_and_store_avant("routing_engine", "Informations du moteur de routage", "show chassis routing-engine", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)

            if not verifier_connexion(connection, log_messages, "AVANT"): raise Exception("AVANT: Connexion perdue avant interfaces")
            section_title_interfaces = "Informations sur les interfaces"
            log_messages.append(f"AVANT Récupération: {section_title_interfaces}")
            file.write(f"\n{section_title_interfaces} :\n")
            cmd_terse = "show interfaces terse"
            cmd_detail = "show interfaces detail"
            out_terse = connection.send_command(cmd_terse + " | no-more", read_timeout=90)
            if isinstance(out_terse, str): # Apply pagination filtering
                out_terse_lines = out_terse.splitlines()
                cleaned_terse_lines = [line for line in out_terse_lines if not line.strip().startswith("---(more")]
                out_terse = "\n".join(cleaned_terse_lines)
            out_detail = connection.send_command(cmd_detail + " | no-more", read_timeout=180) 
            if isinstance(out_detail, str): # Apply pagination filtering
                out_detail_lines = out_detail.splitlines()
                cleaned_detail_lines = [line for line in out_detail_lines if not line.strip().startswith("---(more")]
                out_detail = "\n".join(cleaned_detail_lines)

            up_list, down_list = parse_interfaces_structured(out_terse, out_detail, log_messages)
            structured_output_data["interfaces_up"] = up_list
            structured_output_data["interfaces_down"] = down_list
            file.write("Les Interfaces up :\n")
            if up_list:
                for iface in up_list: file.write(f"{iface['name']} - Vitesse: {iface['speed']} - IP: {iface['ip_address']} - MAC: {iface['mac_address']}\n")
            else: file.write("Aucune interface active trouvée.\n")
            file.write("Les Interfaces down :\n")
            if down_list:
                for iface in down_list: file.write(f"{iface['name']} - Vitesse: {iface['speed']} - IP: {iface['ip_address']} - MAC: {iface['mac_address']}\n")
            else: file.write("Aucune interface inactive trouvée.\n")
            log_messages.append(f"AVANT OK: {section_title_interfaces}")

            fetch_and_store_avant("arp_table", "Informations ARP", "show arp", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            
            section_title_routes = "Informations sur les routes"
            file.write(f"\n{section_title_routes} :\n")
            log_messages.append(f"AVANT Récupération: {section_title_routes} - Résumé")
            file.write("Resume des routes :\n") 
            try:
                route_summary_out = connection.send_command("show route summary | no-more", read_timeout=90)
                if isinstance(route_summary_out, str): # Apply pagination filtering
                    rs_lines = route_summary_out.splitlines()
                    cleaned_rs_lines = [line for line in rs_lines if not line.strip().startswith("---(more")]
                    route_summary_out = "\n".join(cleaned_rs_lines)
                structured_output_data["route_summary"] = route_summary_out.strip()
                file.write(route_summary_out.strip() + "\n")
                log_messages.append(f"AVANT OK: {section_title_routes} - Résumé")
            except Exception as e_route_sum_av:
                err_msg_route = f"ERREUR AVANT: Echec commande 'show route summary' pour '{section_title_routes}': {e_route_sum_av}"
                log_messages.append(err_msg_route)
                structured_output_data["route_summary"] = err_msg_route
                file.write(err_msg_route + "\n")
                log_messages.append(f"AVANT ECHEC: {section_title_routes} - Résumé")
            
            fetch_and_store_avant("ospf_info", "Protocole OSPF", "show ospf interface brief", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            fetch_and_store_avant("isis_info", "Protocole IS-IS", "show isis adjacency", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            fetch_and_store_avant("mpls_info", "Protocole MPLS", "show mpls interface", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            fetch_and_store_avant("ldp_info", "Protocole LDP", "show ldp session", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            fetch_and_store_avant("rsvp_info", "Protocole RSVP", "show rsvp interface", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            fetch_and_store_avant("lldp_info", "Protocole LLDP", "show lldp neighbor", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            fetch_and_store_avant("lsp_info", "Protocole LSP", "show mpls lsp", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            fetch_and_store_avant("bgp_summary", "Protocole BGP", "show bgp summary", parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None)
            
            fetch_and_store_avant("firewall_config", "Listes de Controle d'Acces (ACL)", "show configuration firewall", parser_func=_parse_firewall_acls_output_avant, is_raw=False, read_timeout=90, not_configured_check=None)
            
            fetch_and_store_avant("system_services", "Services configurés", "show configuration system services", parser_func=_parse_services_avant, is_raw=False, read_timeout=90, not_configured_check=None)

            fetch_and_store_avant("configured_protocols", "Protocoles configurés", "show configuration protocols", parser_func=_parse_configured_protocols_output_avant, is_raw=False, read_timeout=90, not_configured_check=None)
            
            # --- Critical Logs using fetch_and_store_avant ---
            log_msg_cmd = 'show log messages | match "error|warning|critical" | last 10' # | no-more will be added by fetch
            fetch_and_store_avant(
                data_key_structured="critical_logs_messages",
                title_for_file_key="Logs des erreurs critiques - messages",
                cmd=log_msg_cmd,
                is_raw=True, 
                read_timeout=60
            )
            
            chassisd_log_cmd = 'show log chassisd | match "error|warning|critical" | last 10' # | no-more will be added by fetch
            fetch_and_store_avant(
                data_key_structured="critical_logs_chassisd",
                title_for_file_key="Logs des erreurs critiques - chassisd",
                cmd=chassisd_log_cmd,
                is_raw=True,
                read_timeout=60
            )
            # --- End Critical Logs ---
            
            fetch_and_store_avant("full_config_set", "La configuration totale", "show configuration | display set", parser_func=None, is_raw=True, read_timeout=300, not_configured_check=None)

            base_config_filename = f"CONFIGURATION_{username}_{router_hostname}.txt"
            config_file_path = os.path.join(GENERATED_FILES_DIR, base_config_filename)
            compteur_cfg = 1
            while os.path.exists(config_file_path):
                config_file_path = os.path.join(GENERATED_FILES_DIR, f"CONFIGURATION_{username}_{router_hostname}_{compteur_cfg}.txt")
                compteur_cfg += 1
            config_content_to_save = structured_output_data.get("full_config_set", "Erreur: Contenu de configuration non récupéré.")
            if isinstance(config_content_to_save, dict) and "error" in config_content_to_save: 
                 config_content_to_save = f"Erreur lors de la récupération de la configuration:\n{config_content_to_save.get('error', '')}\nRaw output (if any):\n{config_content_to_save.get('raw_output','')}"

            with open(config_file_path, 'w', encoding='utf-8') as cf_file: cf_file.write(config_content_to_save)
            fichiers_crees_avant.append(config_file_path)
            log_messages.append(f"AVANT: Config sauvegardée séparément: {config_file_path}")

        ident_base_name = f"identifiants_{username}_{router_hostname}.json"
        identifiants_file_path = os.path.join(GENERATED_FILES_DIR, ident_base_name)
        compteur_ident = 1
        while os.path.exists(identifiants_file_path): 
            identifiants_file_path = os.path.join(GENERATED_FILES_DIR, f"identifiants_{username}_{router_hostname}_{compteur_ident}.json")
            compteur_ident += 1
        ident_data = {
            "ip": ip, "username": username, "router_hostname": router_hostname,
            "lock_file_path": lock_file_path, 
            "avant_file_path": avant_file_path_internal, 
            "config_file_path": config_file_path,
            "ident_file_path": identifiants_file_path 
        }
        with open(identifiants_file_path, "w") as f_ident: json.dump(ident_data, f_ident, indent=2)
        fichiers_crees_avant.append(identifiants_file_path)
        log_messages.append(f"AVANT: Données d'identification sauvegardées dans: {identifiants_file_path}")
        log_messages.append(f"--- Fin run_avant_checks pour {ip} ---")

        for key, value in list(structured_output_data.items()): 
            if isinstance(value, str) and not value.strip() and not key.startswith("critical_logs"): # Allow empty critical logs to be just empty strings if they are
                structured_output_data[key] = {"message": f"Aucune donnée trouvée pour {key}."}
            elif isinstance(value, list) and not value: 
                if key not in ["interfaces_up", "interfaces_down"]:
                    structured_output_data[key] = {"message": f"Aucune donnée trouvée pour {key}."}
        return {
            "status": "success", "message": "Vérifications AVANT terminées.",
            "ident_data": ident_data, "ident_file_path": identifiants_file_path,
            "avant_file_path": avant_file_path_internal, 
            "config_file_path": config_file_path,
            "lock_file_path": lock_file_path, 
            "connection_obj": connection, 
            "structured_data": structured_output_data, 
            "log_messages": log_messages
        }

    except Exception as e_generic: 
        import traceback
        error_msg = f"AVANT Erreur majeure dans run_avant_checks: {str(e_generic)} (Type: {type(e_generic).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        for key_data in structured_output_data:
            if not structured_output_data[key_data] or \
               (isinstance(structured_output_data[key_data], dict) and not structured_output_data[key_data]):
                structured_output_data[key_data] = {"message": f"Collecte interrompue par erreur: {error_msg}"}

        return {
            "status": "error", "message": error_msg, 
            "lock_file_path": lock_file_path, 
            "fichiers_crees": fichiers_crees_avant, 
            "structured_data": structured_output_data, 
            "log_messages": log_messages,
            "connection_obj": connection if 'connection' in locals() and connection else None
        }

def run_update_procedure(connection, device_details, image_file, log_messages):
    log_messages.append(f"--- UPDATE: run_update_procedure avec image: {image_file} ---")

    try:
        log_messages.append(f"UPDATE: Vérification de la présence du package {image_file} sur le routeur...")
        if image_file == "simulate_not_found.tgz":
            log_messages.append(f"UPDATE ERREUR: Package {image_file} non trouvé (simulation).")
            return {"status": "error", "message": f"Package {image_file} non trouvé (simulation)."} 
        log_messages.append(f"UPDATE: Package {image_file} trouvé (simulation).")

        log_messages.append("UPDATE: Désactivation des fonctionnalités HA (simulation)...")
        time.sleep(1) 

        log_messages.append("UPDATE: Mise à jour RE backup (simulation)...")
        time.sleep(2) 
        
        expected_version_from_image = image_file.split("jinstall-ppc-")[-1].split("-signed.tgz")[0] if "jinstall-ppc-" in image_file else "unknown_format"
        log_messages.append(f"UPDATE: Vérification version sur RE backup (cible: {expected_version_from_image}) (simulation)...")
        current_backup_re_version = expected_version_from_image 
        if current_backup_re_version != expected_version_from_image:
            msg = f"UPDATE ERREUR: Version RE backup ({current_backup_re_version}) ne correspond pas à {expected_version_from_image} (simulation)."
            log_messages.append(msg)
            return {"status": "error", "message": msg}
        log_messages.append("UPDATE: Version RE backup OK (simulation).")

        log_messages.append("UPDATE: Basculement vers RE mis à jour (simulation)...")
        log_messages.append("UPDATE: ATTENTION - La connexion va probablement tomber ici et nécessiter une reconnexion externe.")
        time.sleep(1) 

        log_messages.append("UPDATE: (Après basculement simulé, en supposant une nouvelle connexion établie par l'appelant)")
        log_messages.append("UPDATE: Mise à jour nouveau RE backup (ancien master) (simulation)...")
        time.sleep(2)

        log_messages.append(f"UPDATE: Vérification version sur nouveau RE backup (cible: {expected_version_from_image}) (simulation)...")
        current_new_backup_re_version = expected_version_from_image 
        if current_new_backup_re_version != expected_version_from_image:
            msg = f"UPDATE ERREUR: Version nouveau RE backup ({current_new_backup_re_version}) ne correspond pas à {expected_version_from_image} (simulation)."
            log_messages.append(msg)
            return {"status": "error", "message": msg}
        log_messages.append("UPDATE: Version nouveau RE backup OK (simulation).")
        
        log_messages.append("UPDATE: Réactivation HA (simulation)...")
        time.sleep(1)

        log_messages.append("UPDATE: ✓ Procédure (simulée) terminée avec succès.")
        updated_junos_info = {"new_junos_version": expected_version_from_image}
        return {"status": "success", "message": "Mise à jour (simulée) terminée.", 
                "updated_junos_info": updated_junos_info}
    except Exception as e_update:
        log_messages.append(f"UPDATE ERREUR: Erreur majeure dans run_update_procedure: {str(e_update)}")
        return {"status": "error", "message": f"Erreur durant la mise à jour (simulée): {str(e_update)}"}


if __name__ == '__main__':
    test_logs = []
    print(f"AVANT_API.py: Script chargé.")
    print(f"Répertoire des fichiers générés: {os.path.abspath(GENERATED_FILES_DIR)}")
    print(f"Répertoire des verrous: {os.path.abspath(LOCK_DIR)}")