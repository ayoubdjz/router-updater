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
from netmiko import NetmikoTimeoutException, ReadTimeout # Explicitly import ReadTimeout
import re

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCK_DIR = os.path.join(SCRIPT_DIR, "router_locks")
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
Path(LOCK_DIR).mkdir(exist_ok=True, parents=True)
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

# --- Constants for Update Procedure ---
JUNOS_IMG_RE_PREFIX = "jinstall-ppc-"
JUNOS_IMG_RE_SUFFIX = "-signed.tgz" # Typically .tgz, original script used -signed.tgz
SOFTWARE_INSTALL_TIMEOUT = 3600  # 1 hour for "request system software add"
REBOOT_VERIFY_TIMEOUT = 900    # 15 minutes to wait for RE to come up
RE_STATE_CHECK_INTERVAL = 30   # 30 seconds interval for checking RE state
SWITCHOVER_TIMEOUT = 300       # 5 minutes for master switchover to complete
RECONNECT_ATTEMPTS = 5
RECONNECT_DELAY = 60           # 1 minute between reconnect attempts
COMMAND_TIMEOUT_SHORT = 30
COMMAND_TIMEOUT_MEDIUM = 120
COMMAND_TIMEOUT_LONG = 300


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
        msg = "No configured protocols found on the output"
        return {"message": msg, "protocols": []}

def _parse_firewall_acls_output_avant(output, log_messages, context="AVANT Parse"):
    output_stripped = output.strip()
    if output_stripped:
        return output_stripped
    else:
        msg = "No ACL configured on the output"
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
    }
    
    # Device details for potential reuse in update procedure
    device_details_for_update = {
        'device_type': 'juniper', 'host': ip, 'username': username, 'password': password,
        'timeout': 60, 'auth_timeout': 90, 'banner_timeout': 90, 'global_delay_factor': 2
    }

    try:
        log_messages.append(f"--- Début run_avant_checks pour {ip} ---")
        lock_acquired, attempted_lock_path = verrouiller_routeur(ip, log_messages)
        lock_file_path = attempted_lock_path
        if not lock_acquired:
            return {"status": "error", "message": f"Impossible de verrouiller le routeur {ip}. Voir logs.", 
                    "lock_file_path": lock_file_path, "logs": log_messages, "structured_data": structured_output_data}

        log_messages.append(f"AVANT: Tentative de connexion à {ip}...")
        connection = ConnectHandler(**device_details_for_update)
        log_messages.append(f"AVANT: Connecté avec succès au routeur {ip}")
        
        try:
            pagination_off_command = 'set cli screen-length 0'
            log_messages.append(f"AVANT: Tentative de désactivation de la pagination CLI: {pagination_off_command}")
            connection.send_command_timing(
                pagination_off_command, read_timeout=15, delay_factor=1, max_loops=50, expect_string=r'[\#>]' 
            ) # Use expect_string for robustness
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
            elif "Junos: " in line: # More robust parsing for Junos version
                try: junos_version = line.split("Junos: ")[1].split()[0].strip() # Takes the first part after "Junos: "
                except IndexError: junos_version = "inconnu (parse error)"
            elif line.startswith("JUNOS Base OS boot [") : # Fallback for some version outputs
                try: junos_version = line.split('[')[1].split(']')[0].strip()
                except IndexError: pass


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
            else: file.write("No interfaces down found\n")
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

            fetch_and_store_avant("configured_protocols", "Protocoles configures", "show configuration protocols", parser_func=_parse_configured_protocols_output_avant, is_raw=False, read_timeout=90, not_configured_check=None)
            
            log_msg_cmd = 'show log messages | match "error|warning|critical" | last 10'
            fetch_and_store_avant(
                data_key_structured="critical_logs_messages",
                title_for_file_key="Logs des erreurs critiques - messages",
                cmd=log_msg_cmd,
                is_raw=True, 
                read_timeout=60
            )
            
            chassisd_log_cmd = 'show log chassisd | match "error|warning|critical" | last 10'
            fetch_and_store_avant(
                data_key_structured="critical_logs_chassisd",
                title_for_file_key="Logs des erreurs critiques - chassisd",
                cmd=chassisd_log_cmd,
                is_raw=True,
                read_timeout=60
            )
            
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
            "ident_file_path": identifiants_file_path,
            "device_details_for_update": device_details_for_update # Add device details for update
        }
        with open(identifiants_file_path, "w") as f_ident: json.dump(ident_data, f_ident, indent=2)
        fichiers_crees_avant.append(identifiants_file_path)
        log_messages.append(f"AVANT: Données d'identification sauvegardées dans: {identifiants_file_path}")
        log_messages.append(f"--- Fin run_avant_checks pour {ip} ---")

        for key, value in list(structured_output_data.items()): 
            if isinstance(value, str) and not value.strip() and not key.startswith("critical_logs"):
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
            "log_messages": log_messages,
            "device_details_for_update": device_details_for_update # Pass this out for update
        }

    except Exception as e_generic: 
        import traceback
        error_msg = f"AVANT Erreur majeure dans run_avant_checks: {str(e_generic)} (Type: {type(e_generic).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        for key_data in structured_output_data:
            if not structured_output_data[key_data] or \
               (isinstance(structured_output_data[key_data], dict) and not structured_output_data[key_data]):
                structured_output_data[key_data] = {"message": f"Collecte interrompue par erreur: {error_msg}"}

        if connection:
            try:
                connection.disconnect()
            except Exception as e_disconnect:
                log_messages.append(f"AVANT Erreur à la déconnexion suite à une erreur majeure: {e_disconnect}")

        return {
            "status": "error", "message": error_msg, 
            "lock_file_path": lock_file_path, 
            "fichiers_crees": fichiers_crees_avant, 
            "structured_data": structured_output_data, 
            "log_messages": log_messages,
            "connection_obj": None # Connection is likely invalid or closed
        }

# --- Update Procedure Helper Functions ---

def _validate_image_filename(image_file, log_messages):
    if not image_file:
        log_messages.append("UPDATE ERREUR: Nom du package non spécifié.")
        return False, None
    if not image_file.endswith('.tgz'): # Original script checks for -signed.tgz, but .tgz is more generic
        log_messages.append(f"UPDATE ATTENTION: Package {image_file} ne finit pas par .tgz.")
        # This is a warning, not a hard fail, user might know what they are doing.
    if JUNOS_IMG_RE_PREFIX not in image_file: # or JUNOS_IMG_RE_SUFFIX not in image_file:
        log_messages.append(f"UPDATE ERREUR: Format de nom de fichier {image_file} potentiellement incorrect. Attendu: {JUNOS_IMG_RE_PREFIX}<VERSION>{JUNOS_IMG_RE_SUFFIX}")
        return False, None
    try:
        expected_version = image_file.split(JUNOS_IMG_RE_PREFIX)[-1].split("-signed.tgz")[0] # Match original extraction
        if not expected_version :
             expected_version = image_file.split(JUNOS_IMG_RE_PREFIX)[-1].split(".tgz")[0] # More generic fallback
        if not expected_version:
            log_messages.append(f"UPDATE ERREUR: Impossible d'extraire la version de {image_file}.")
            return False, None
        return True, expected_version
    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Exception lors de l'extraction de la version de {image_file}: {e}")
        return False, None


def _check_package_on_router(connection, image_file, log_messages):
    pkg_path_re0 = f"/var/tmp/{image_file}"
    pkg_path_re1 = f"/var/tmp/re1/{image_file}" # Path if copied to re1's /var/tmp from re0
    
    try:
        # Check on current RE's /var/tmp (could be re0 or re1 if switched)
        output_current_re = connection.send_command(f"file list {pkg_path_re0}", read_timeout=COMMAND_TIMEOUT_SHORT)
        found_on_current_re = "No such file or directory" not in output_current_re and image_file in output_current_re
        
        if found_on_current_re:
            log_messages.append(f"UPDATE: Package {image_file} trouvé sur {pkg_path_re0} (RE courant).")
            return True

        # If dual RE, check on the other RE's /var/tmp location if accessible.
        # This check from AVANT.py implies user might have copied it to /var/tmp/re1 specifically.
        # A more robust check might be needed if the file is expected on *both* REs' local /var/tmp.
        # For now, let's assume one of them is sufficient as per original script's apparent logic.
        # The original script checks both file list /var/tmp/image and file list /var/tmp/re1/image.
        # This suggests that from re0, you can see /var/tmp/re1. This is not standard.
        # Let's assume the check means "on /var/tmp of RE0" and "on /var/tmp of RE1".
        # The install command will run on the target RE, so it needs the file in its own /var/tmp.
        # So the critical part is that the RE being upgraded has the file in its /var/tmp.

        log_messages.append(f"UPDATE ERREUR: Package {image_file} non trouvé sur {pkg_path_re0} (RE courant). "
                            f"L'utilisateur doit s'assurer que le package est dans /var/tmp/ du RE à mettre à jour AVANT de lancer la mise à jour de ce RE.")
        return False
        
    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Exception lors de la vérification du package {image_file}: {e}")
        return False

def _get_routing_engine_status(connection, log_messages):
    """Gets status of RE0 and RE1. Returns dict {slot: {state, ...}} or None on error/single RE."""
    try:
        output = connection.send_command("show chassis routing-engine", read_timeout=COMMAND_TIMEOUT_MEDIUM)
        re_status = {}
        current_slot = -1
        for line in output.splitlines():
            line_stripped = line.strip()
            if line_stripped.startswith("Slot 0:"):
                current_slot = 0
                re_status[current_slot] = {"slot": 0}
            elif line_stripped.startswith("Slot 1:"):
                current_slot = 1
                re_status[current_slot] = {"slot": 1}
            
            if current_slot != -1:
                if "Current state" in line_stripped:
                    re_status[current_slot]["state"] = line_stripped.split("Current state")[-1].strip()
                elif "Junos version" in line_stripped: # For version check helper
                    re_status[current_slot]["version"] = line_stripped.split("Junos version")[-1].strip()
        
        if 0 not in re_status: # Should always have RE0
            log_messages.append("UPDATE ERREUR: Impossible de déterminer l'état de RE0.")
            return None
        if 1 not in re_status:
            log_messages.append("UPDATE INFO: Seul RE0 détecté. Procédure dual-RE non applicable telle quelle.")
            # For now, dual-RE specific script. Could be adapted for single RE later.
            return {"single_re": True, 0: re_status[0]} 
        
        return re_status

    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Impossible d'obtenir l'état des REs: {e}")
        return None

def _wait_for_re_to_reach_state(connection, re_slot_to_monitor, target_state, log_messages,
                                re_status_getter_func, # func that calls _get_routing_engine_status
                                timeout=REBOOT_VERIFY_TIMEOUT, check_interval=RE_STATE_CHECK_INTERVAL):
    start_time = time.time()
    log_messages.append(f"UPDATE: Attente que RE{re_slot_to_monitor} atteigne l'état '{target_state}' (max {timeout}s)...")
    while time.time() - start_time < timeout:
        all_re_status = re_status_getter_func(connection, log_messages)
        if all_re_status and re_slot_to_monitor in all_re_status:
            current_re_info = all_re_status[re_slot_to_monitor]
            current_state = current_re_info.get("state")
            log_messages.append(f"UPDATE: RE{re_slot_to_monitor} état actuel: {current_state if current_state else 'Inconnu'}")
            if current_state and target_state.lower() in current_state.lower():
                log_messages.append(f"UPDATE: ✓ RE{re_slot_to_monitor} a atteint l'état '{target_state}'.")
                return True
        else:
            log_messages.append(f"UPDATE: Impossible d'obtenir l'état de RE{re_slot_to_monitor}, nouvelle tentative dans {check_interval}s.")
        time.sleep(check_interval)
    
    log_messages.append(f"UPDATE ERREUR: Timeout ({timeout}s) atteint. RE{re_slot_to_monitor} n'a pas atteint l'état '{target_state}'.")
    return False

def _verify_re_version(connection, re_slot_to_check, expected_version, log_messages):
    try:
        command = "show version"
        # To get version of a specific RE, especially if it's the 'other' RE
        # We need to know if re_slot_to_check is the 'current' or 'other'
        # This is simpler if we get all_re_status first.
        all_re_status = _get_routing_engine_status(connection, log_messages)
        if not all_re_status or re_slot_to_check not in all_re_status:
            log_messages.append(f"UPDATE ERREUR: Impossible de récupérer les informations de version pour RE{re_slot_to_check}.")
            return False

        # The version might already be in all_re_status if parsed by _get_routing_engine_status
        # 'show version invoke-on other-routing-engine' is more direct if checking the other RE
        # For now, let's assume we need to issue a command.
        # Determine if we need 'invoke-on other-routing-engine'
        # This logic is tricky because 'other' depends on which RE we are *currently* connected to.
        # The AVANT.py script uses "show version invoke-on other-routing-engine" after RE1 update (when on RE0)
        # and again after RE0 update (when on RE1). This targets the RE that was just updated.

        # Let's assume for now the connection is to the master, and re_slot_to_check is the backup that was updated.
        cmd_version = f"show version invoke-on other-routing-engine | match Junos:" # This assumes re_slot_to_check is the 'other' one
        
        # A slightly more robust way:
        current_master_slot = -1
        for slot, info in all_re_status.items():
            if "master" in info.get("state", "").lower() and isinstance(slot, int):
                current_master_slot = slot
                break
        
        if current_master_slot == -1:
            log_messages.append("UPDATE ERREUR: Impossible de déterminer le RE master actuel pour la vérification de version.")
            return False

        if re_slot_to_check == current_master_slot: # Checking version of current master
            cmd_version = "show version | match Junos:"
        else: # Checking version of backup/other RE
            cmd_version = "show version invoke-on other-routing-engine | match Junos:"

        log_messages.append(f"UPDATE: Vérification de la version sur RE{re_slot_to_check} (Commande: {cmd_version})")
        version_output = connection.send_command(cmd_version, read_timeout=COMMAND_TIMEOUT_MEDIUM)
        
        current_version_found = None
        for line in version_output.splitlines():
            if "Junos: " in line:
                current_version_found = line.split("Junos:")[1].strip().split()[0] # Get the version part
                break
            elif line.startswith("JUNOS Base OS boot [") : # Fallback for some version outputs
                try: current_version_found = line.split('[')[1].split(']')[0].strip()
                except IndexError: pass
                break
        
        if not current_version_found:
            log_messages.append(f"UPDATE ERREUR: Impossible d'extraire la version actuelle de RE{re_slot_to_check} depuis la sortie: {version_output}")
            return False

        log_messages.append(f"UPDATE: Version actuelle sur RE{re_slot_to_check}: {current_version_found}, Version attendue: {expected_version}")
        if current_version_found == expected_version:
            log_messages.append(f"UPDATE: ✓ La version sur RE{re_slot_to_check} correspond à la version attendue.")
            return True
        else:
            log_messages.append(f"UPDATE ERREUR: La version sur RE{re_slot_to_check} ({current_version_found}) ne correspond pas à la version attendue ({expected_version}).")
            return False
            
    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Exception lors de la vérification de version sur RE{re_slot_to_check}: {e}")
        return False

def _perform_re_upgrade(connection, image_file, log_messages, target_is_other_re=True):
    """Installs software and reboots the target RE."""
    try:
        login_cmd = "request routing-engine login other-routing-engine"
        # The prompt might change after this. Netmiko should handle it.
        # Send subsequent commands on this "sub-session"
        
        original_prompt = connection.base_prompt
        
        if target_is_other_re:
            log_messages.append(f"UPDATE: Connexion à l'autre RE via '{login_cmd}'...")
            # output_login = connection.send_command_timing(login_cmd, read_timeout=COMMAND_TIMEOUT_MEDIUM) # Simpler send_command may work
            output_login = connection.send_command(login_cmd, expect_string=r'(%|\#)', read_timeout=COMMAND_TIMEOUT_MEDIUM, strip_command=False, strip_prompt=False)

            if "error" in output_login.lower() or "failed" in output_login.lower():
                 log_messages.append(f"UPDATE ERREUR: Échec de la connexion à l'autre RE: {output_login}")
                 return False
            log_messages.append(f"UPDATE: Connecté à l'autre RE. Nouveau prompt approximatif: {connection.find_prompt(delay_factor=2)}")


        install_cmd = f"request system software add /var/tmp/{image_file} no-validate"
        log_messages.append(f"UPDATE: Installation du logiciel sur le RE {'autre' if target_is_other_re else 'courant'} (Cmd: {install_cmd}). Timeout: {SOFTWARE_INSTALL_TIMEOUT}s")
        
        # Using delay_factor from original script for 'request system software add'
        install_output = connection.send_command(install_cmd, read_timeout=SOFTWARE_INSTALL_TIMEOUT, delay_factor=4) 

        if "error" in install_output.lower() or "fail" in install_output.lower():
            log_messages.append(f"UPDATE ERREUR: Échec de l'installation du logiciel: {install_output}")
            if target_is_other_re: connection.send_command("exit", expect_string=original_prompt) # Try to exit sub-session
            return False
        log_messages.append("UPDATE: ✓ Installation du logiciel terminée.")

        reboot_cmd = "request system reboot"
        log_messages.append(f"UPDATE: Lancement du redémarrage du RE {'autre' if target_is_other_re else 'courant'} (Cmd: {reboot_cmd})")
        
        # Handle [yes/no] confirmation for reboot
        # Based on AVANT.py:
        # connection.send_command("request system reboot", expect_string=r"Reboot the system", strip_prompt=False)
        # connection.send_command("yes", expect_string=r"Shutdown NOW!")
        
        # Using send_command with expect_string for the question part
        output_reboot_q = connection.send_command(reboot_cmd, expect_string=r"Reboot the system.*\[yes,no\]", read_timeout=COMMAND_TIMEOUT_SHORT, strip_prompt=False, strip_command=False)
        log_messages.append(f"UPDATE: Réponse à la demande de redémarrage: {output_reboot_q}")

        if "Reboot the system" in output_reboot_q:
            output_reboot_y = connection.send_command("yes", expect_string=r"Shutdown NOW!|CLI session terminated", read_timeout=COMMAND_TIMEOUT_SHORT, strip_prompt=False, strip_command=False) # Expect string might vary
            log_messages.append(f"UPDATE: Confirmation de redémarrage envoyée. Réponse: {output_reboot_y}")
            if "Shutdown NOW!".lower() not in output_reboot_y.lower() and "CLI session terminated".lower() not in output_reboot_y.lower() :
                 log_messages.append(f"UPDATE WARNING: Réponse inattendue à la confirmation de redémarrage: {output_reboot_y}")
        else:
            log_messages.append(f"UPDATE ERREUR: Question de confirmation de redémarrage non reçue. Sortie: {output_reboot_q}")
            if target_is_other_re: connection.send_command("exit", expect_string=original_prompt)
            return False
            
        log_messages.append(f"UPDATE: ✓ Commande de redémarrage pour RE {'autre' if target_is_other_re else 'courant'} envoyée.")
        
        # If we logged into other RE, its connection is now gone due to reboot.
        # The main connection to the original master RE should still be active.
        # We need to restore the prompt for the original Netmiko connection object if it was changed by 'login other RE'.
        if target_is_other_re:
            connection.set_base_prompt(original_prompt) # Restore original prompt context for the connection object
            log_messages.append(f"UPDATE: Prompt Netmiko restauré à: {original_prompt} pour la connexion principale.")

        return True

    except ReadTimeout:
        log_messages.append(f"UPDATE ERREUR: ReadTimeout pendant la mise à jour/redémarrage du RE. L'opération a peut-être réussi mais la confirmation a été perdue.")
        # This can happen if reboot is too fast or install takes exactly the timeout.
        # For reboot, this is often expected as connection drops.
        if "reboot" in locals() and reboot_cmd in locals(): # If it was during reboot cmd
             log_messages.append("UPDATE INFO: ReadTimeout pendant la commande de redémarrage est souvent normal car la session est coupée.")
             if target_is_other_re: connection.set_base_prompt(original_prompt)
             return True # Assume reboot initiated
        if target_is_other_re: connection.set_base_prompt(original_prompt)
        return False # For install timeout
    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Exception pendant la mise à jour/redémarrage du RE: {e}")
        if target_is_other_re and 'original_prompt' in locals(): 
            try:
                connection.send_command("exit", expect_string=original_prompt, read_timeout=10)
                connection.set_base_prompt(original_prompt)
            except: pass # best effort
        return False


def _switch_mastership_and_reconnect(current_connection, device_config_for_reconnect, log_messages,
                                     expected_new_master_slot,
                                     switch_timeout=SWITCHOVER_TIMEOUT, 
                                     reconnect_attempts=RECONNECT_ATTEMPTS, 
                                     reconnect_delay=RECONNECT_DELAY):
    try:
        log_messages.append(f"UPDATE: Tentative de basculement de mastership. Nouveau master attendu: RE{expected_new_master_slot}.")
        # current_connection.send_command("request chassis routing-engine master switch", expect_string=r"Toggle mastership.*\[yes,no\]", strip_prompt=False, strip_command=False, read_timeout=COMMAND_TIMEOUT_SHORT)
        # current_connection.send_command("yes", expect_string=r"Mastership switch has been initiated", strip_prompt=False, strip_command=False, read_timeout=COMMAND_TIMEOUT_SHORT)
        
        # Simplified from AVANT.py:
        switch_q_out = current_connection.send_command("request chassis routing-engine master switch", expect_string=r"Toggle mastership between routing engines.*\[yes,no\]", strip_prompt=False, strip_command=False, read_timeout=COMMAND_TIMEOUT_SHORT)
        log_messages.append(f"UPDATE: Demande de basculement: {switch_q_out}")
        if "Toggle mastership".lower() not in switch_q_out.lower():
            log_messages.append(f"UPDATE ERREUR: Message de confirmation de basculement inattendu: {switch_q_out}")
            return None # Return None for connection

        switch_y_out = current_connection.send_command("yes", expect_string=r"Mastership switch has been initiated|Connection to .* closed by remote host.", strip_prompt=False, strip_command=False, read_timeout=COMMAND_TIMEOUT_SHORT) # Expect switch or disconnect
        log_messages.append(f"UPDATE: Confirmation de basculement: {switch_y_out}")
        
        # Mastership switch initiated, connection will drop.
        log_messages.append("UPDATE: Basculement initié. Déconnexion de la session actuelle...")
        current_connection.disconnect()
    except Exception as e:
        log_messages.append(f"UPDATE WARNING: Erreur pendant la commande de basculement ou la déconnexion: {e}. Poursuite avec la tentative de reconnexion.")
        # If current_connection is already bad, disconnect might fail.

    log_messages.append(f"UPDATE: Attente de {switch_timeout}s pour la fin du basculement...")
    time.sleep(switch_timeout)

    log_messages.append("UPDATE: Tentative de reconnexion après basculement...")
    new_connection = None
    for attempt in range(1, reconnect_attempts + 1):
        log_messages.append(f"UPDATE: Tentative de reconnexion {attempt}/{reconnect_attempts}...")
        try:
            new_connection = ConnectHandler(**device_config_for_reconnect)
            log_messages.append("UPDATE: ✓ Reconnecté physiquement.")
            
            # Verify new master
            re_statuses = _get_routing_engine_status(new_connection, log_messages)
            if re_statuses and expected_new_master_slot in re_statuses and \
               "master" in re_statuses[expected_new_master_slot].get("state", "").lower():
                log_messages.append(f"UPDATE: ✓ Basculement vers RE{expected_new_master_slot} réussi et vérifié.")
                return new_connection
            else:
                state_found = re_statuses.get(expected_new_master_slot, {}).get('state', 'N/A') if re_statuses else 'N/A'
                log_messages.append(f"UPDATE ERREUR: RE{expected_new_master_slot} n'est pas Master après reconnexion (état trouvé: {state_found}).")
                new_connection.disconnect()
                new_connection = None
        except (NetmikoTimeoutException, NetmikoAuthenticationException, ReadTimeout, ConnectionRefusedError, Exception) as e_reconnect:
            log_messages.append(f"UPDATE ERREUR: Tentative de reconnexion {attempt} échouée: {e_reconnect}")
            if new_connection:
                try: new_connection.disconnect()
                except: pass
                new_connection = None
        
        if attempt < reconnect_attempts:
            log_messages.append(f"UPDATE: Nouvelle tentative dans {reconnect_delay}s...")
            time.sleep(reconnect_delay)

    log_messages.append("UPDATE ERREUR: Échec de toutes les tentatives de reconnexion après basculement.")
    return None


def _set_ha_features(connection, activate, log_messages):
    action = "activate" if activate else "deactivate"
    log_messages.append(f"UPDATE: {'Activation' if activate else 'Désactivation'} des fonctionnalités HA...")
    
    config_commands = [
        f"{action} chassis redundancy",
        f"{action} routing-options nonstop-routing",
        f"{action} system commit synchronize"
    ]
    if not activate: # Specific deactivation command from AVANT.py
        config_commands.append("set system processes clksyncd-service disable")
    else: # To re-enable if it was disabled this way
        config_commands.append("delete system processes clksyncd-service disable")


    try:
        connection.config_mode()
        for cmd in config_commands:
            log_messages.append(f"UPDATE: Envoi commande HA: {cmd}")
            output = connection.send_command(cmd, read_timeout=COMMAND_TIMEOUT_SHORT)
            if "error" in output.lower() or "unknown command" in output.lower():
                log_messages.append(f"UPDATE ERREUR: Commande HA '{cmd}' échouée: {output}")
                # Try to exit config mode gracefully
                try: connection.exit_config_mode()
                except: pass
                return False
        
        log_messages.append("UPDATE: Application de la configuration HA avec 'commit synchronize'...")
        # commit_output = connection.send_command("commit synchronize", read_timeout=COMMAND_TIMEOUT_LONG)
        # Netmiko's commit method might be more robust if it handles "commit synchronize" well
        commit_output = connection.commit(comment="HA features update via API", read_timeout=COMMAND_TIMEOUT_LONG, and_quit=False) # and_quit=False leaves in config mode if needed
        # The original AVANT.py used write_channel("commit synchronize\n").
        # If connection.commit() doesn't do 'synchronize', use send_command.
        # Let's use send_command for 'commit synchronize' as per original script's intent.
        # connection.exit_config_mode() # Exit first if commit() was used.
        # Then:
        # commit_output = connection.send_command("commit synchronize", read_timeout=COMMAND_TIMEOUT_LONG)
        
        # The method in AVANT.py:
        # connection.write_channel("commit synchronize\n")
        # connection.exit_config_mode()
        # This can be tricky with Netmiko's prompt detection.
        # Safer:
        commit_output = connection.send_command("commit synchronize", read_timeout=COMMAND_TIMEOUT_LONG)

        if "commit complete" not in commit_output.lower() and "commit successful" not in commit_output.lower() : # check for success patterns
            log_messages.append(f"UPDATE ERREUR: 'commit synchronize' pour HA a échoué ou a eu une réponse inattendue: {commit_output}")
            try: connection.exit_config_mode() # Still try to exit
            except: pass
            return False

        connection.exit_config_mode()
        log_messages.append(f"UPDATE: ✓ Configuration HA {'activée' if activate else 'désactivée'}.")
        return True
    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Exception pendant la configuration HA: {e}")
        try: 
            if connection.check_config_mode(): connection.exit_config_mode()
        except: pass
        return False

# --- Main Update Procedure ---
def run_update_procedure(connection, device_config_for_reconnect, image_file, log_messages, skip_re0_final_switchback=False):
    """
    Exécute la procédure de mise à jour Junos pour un système dual-RE.
    Args:
        connection: Objet de connexion Netmiko actif.
        device_config_for_reconnect (dict): Détails pour la reconnexion (host, user, pass, timeouts, etc.).
        image_file (str): Nom du fichier image Junos.
        log_messages (list): Liste pour logger les messages.
        skip_re0_final_switchback (bool): Si True, ne pas re-basculer vers RE0 à la fin.
    Returns:
        dict: {status, message, log_messages, connection_obj (peut être nouveau après switchover)}
    """
    log_messages.append(f"--- UPDATE: Début de run_update_procedure avec image: {image_file} ---")
    
    current_connection = connection # Keep track of the current valid connection object

    # 1. Validations initiales
    valid_format, expected_junos_version = _validate_image_filename(image_file, log_messages)
    if not valid_format:
        return {"status": "error", "message": "Format du nom de fichier image invalide.", "log_messages": log_messages, "connection_obj": current_connection}
    log_messages.append(f"UPDATE: Version Junos attendue après MAJ: {expected_junos_version}")

    if not _check_package_on_router(current_connection, image_file, log_messages):
        return {"status": "error", "message": f"Package {image_file} non trouvé ou inaccessible.", "log_messages": log_messages, "connection_obj": current_connection}

    # 2. Déterminer l'état actuel des REs
    initial_re_status = _get_routing_engine_status(current_connection, log_messages)
    if not initial_re_status:
        return {"status": "error", "message": "Impossible de déterminer l'état initial des REs.", "log_messages": log_messages, "connection_obj": current_connection}
    if initial_re_status.get("single_re"):
        return {"status": "error", "message": "Système single-RE détecté. Cette procédure est pour dual-RE.", "log_messages": log_messages, "connection_obj": current_connection}
    if 0 not in initial_re_status or 1 not in initial_re_status:
        return {"status": "error", "message": "Configuration RE inattendue (RE0 ou RE1 manquant).", "log_messages": log_messages, "connection_obj": current_connection}

    original_master_slot = -1
    original_backup_slot = -1
    if "master" in initial_re_status[0].get("state", "").lower():
        original_master_slot = 0
        original_backup_slot = 1
    elif "master" in initial_re_status[1].get("state", "").lower():
        original_master_slot = 1
        original_backup_slot = 0
    else:
        return {"status": "error", "message": "Impossible de déterminer le RE master initial.", "log_messages": log_messages, "connection_obj": current_connection}
    
    log_messages.append(f"UPDATE: RE Master initial: RE{original_master_slot}, RE Backup initial: RE{original_backup_slot}")

    try:
        # 3. Désactivation des fonctionnalités HA
        if not _set_ha_features(current_connection, activate=False, log_messages=log_messages):
            return {"status": "error", "message": "Échec de la désactivation des fonctionnalités HA.", "log_messages": log_messages, "connection_obj": current_connection}

        # --- Séquence pour le premier RE (le backup actuel) ---
        re_to_update_first = original_backup_slot
        log_messages.append(f"--- UPDATE: Phase 1 - Mise à jour de RE{re_to_update_first} (backup actuel) ---")
        if not _perform_re_upgrade(current_connection, image_file, log_messages, target_is_other_re=True): # True because we are on master, updating backup
            # No exit config mode here as _perform_re_upgrade doesn't enter it.
            return {"status": "error", "message": f"Échec de la mise à jour ou du redémarrage de RE{re_to_update_first}.", "log_messages": log_messages, "connection_obj": current_connection}
        
        if not _wait_for_re_to_reach_state(current_connection, re_to_update_first, "Backup", log_messages, _get_routing_engine_status, timeout=REBOOT_VERIFY_TIMEOUT):
            return {"status": "error", "message": f"RE{re_to_update_first} n'est pas revenu en état 'Backup' après redémarrage.", "log_messages": log_messages, "connection_obj": current_connection}

        if not _verify_re_version(current_connection, re_to_update_first, expected_junos_version, log_messages):
            return {"status": "error", "message": f"Version incorrecte sur RE{re_to_update_first} après mise à jour.", "log_messages": log_messages, "connection_obj": current_connection}
        log_messages.append(f"UPDATE: ✓ RE{re_to_update_first} mis à jour et vérifié.")

        # 5. Basculement vers le RE mis à jour (ancien backup devient nouveau master)
        log_messages.append(f"--- UPDATE: Basculement vers RE{re_to_update_first} ---")
        new_master_after_first_switch = re_to_update_first
        current_connection = _switch_mastership_and_reconnect(current_connection, device_config_for_reconnect, log_messages,
                                                              expected_new_master_slot=new_master_after_first_switch)
        if not current_connection:
            return {"status": "error", "message": f"Échec du basculement ou de la reconnexion à RE{new_master_after_first_switch}.", "log_messages": log_messages, "connection_obj": None}
        
        # Après basculement, le nouveau master est `new_master_after_first_switch` (ancien backup).
        # Le nouveau backup est `original_master_slot` (ancien master).
        re_to_update_second = original_master_slot
        log_messages.append(f"--- UPDATE: Phase 2 - Mise à jour de RE{re_to_update_second} (maintenant backup) ---")
        if not _perform_re_upgrade(current_connection, image_file, log_messages, target_is_other_re=True): # True because we are on new master, updating the other RE
            return {"status": "error", "message": f"Échec de la mise à jour ou du redémarrage de RE{re_to_update_second}.", "log_messages": log_messages, "connection_obj": current_connection}

        if not _wait_for_re_to_reach_state(current_connection, re_to_update_second, "Backup", log_messages, _get_routing_engine_status, timeout=REBOOT_VERIFY_TIMEOUT):
            return {"status": "error", "message": f"RE{re_to_update_second} n'est pas revenu en état 'Backup' après redémarrage.", "log_messages": log_messages, "connection_obj": current_connection}

        if not _verify_re_version(current_connection, re_to_update_second, expected_junos_version, log_messages):
            return {"status": "error", "message": f"Version incorrecte sur RE{re_to_update_second} après mise à jour.", "log_messages": log_messages, "connection_obj": current_connection}
        log_messages.append(f"UPDATE: ✓ RE{re_to_update_second} mis à jour et vérifié.")

        # 7. Réactivation des fonctionnalités HA
        if not _set_ha_features(current_connection, activate=True, log_messages=log_messages):
            return {"status": "error", "message": "Échec de la réactivation des fonctionnalités HA.", "log_messages": log_messages, "connection_obj": current_connection}

        # 8. Basculement optionnel final vers RE0 (ou l'original master)
        if not skip_re0_final_switchback and original_master_slot != new_master_after_first_switch : # only switch if original master is not current master
            log_messages.append(f"--- UPDATE: Basculement final optionnel vers RE{original_master_slot} (master d'origine) ---")
            current_connection = _switch_mastership_and_reconnect(current_connection, device_config_for_reconnect, log_messages,
                                                                  expected_new_master_slot=original_master_slot)
            if not current_connection:
                # This is not fatal for the upgrade itself, but the router is not in its original mastership state.
                log_messages.append(f"UPDATE WARNING: Échec du basculement final vers RE{original_master_slot}. La MAJ est finie, mais le master est RE{new_master_after_first_switch}.")
                # Return success but with a warning message and the current connection to new_master_after_first_switch
                return {
                    "status": "success_with_warning", 
                    "message": f"Mise à jour terminée, mais échec du basculement final vers RE{original_master_slot}. Master actuel: RE{new_master_after_first_switch}.",
                    "updated_junos_info": {"new_junos_version": expected_junos_version},
                    "log_messages": log_messages, 
                    "connection_obj": current_connection # This connection is to new_master_after_first_switch
                }
            log_messages.append(f"UPDATE: ✓ Basculement final vers RE{original_master_slot} réussi.")
        else:
            log_messages.append(f"UPDATE: Pas de basculement final effectué (skip_re0_final_switchback={skip_re0_final_switchback} ou déjà sur master d'origine). Master actuel: RE{new_master_after_first_switch if original_master_slot == new_master_after_first_switch else original_master_slot}.")


        log_messages.append("UPDATE: ✓ Procédure de mise à jour terminée avec succès.")
        return {
            "status": "success", 
            "message": "Mise à jour terminée avec succès.",
            "updated_junos_info": {"new_junos_version": expected_junos_version},
            "log_messages": log_messages, 
            "connection_obj": current_connection
        }

    except Exception as e_update:
        import traceback
        err_msg = f"UPDATE ERREUR: Erreur majeure imprévue dans run_update_procedure: {str(e_update)}"
        log_messages.append(err_msg + f"\nTraceback:\n{traceback.format_exc()}")
        # Try to ensure HA is re-enabled if we bailed mid-way after disabling it
        if "_set_ha_features" in str(traceback.format_exc()) and "activate=False" in str(traceback.format_exc()): # check if error occurred during deactivation
             pass # Error was during deactivation, nothing to re-activate yet
        else: # Error occurred after deactivation, or in other parts
            if current_connection and current_connection.is_alive():
                log_messages.append("UPDATE: Tentative de réactivation HA en urgence suite à une erreur...")
                _set_ha_features(current_connection, activate=True, log_messages=log_messages) # Best effort
            else:
                log_messages.append("UPDATE: Connexion perdue, impossible de tenter une réactivation HA en urgence.")


        return {"status": "error", "message": err_msg, "log_messages": log_messages, "connection_obj": current_connection if current_connection and current_connection.is_alive() else None}


if __name__ == '__main__':
    test_logs = []
    print(f"AVANT_API.py: Script chargé.")
    print(f"Répertoire des fichiers générés: {os.path.abspath(GENERATED_FILES_DIR)}")
    print(f"Répertoire des verrous: {os.path.abspath(LOCK_DIR)}")

    # Example of how device_config_for_reconnect would look (filled by run_avant_checks usually)
    # device_config_example = {
    #     'device_type': 'juniper', 'host': 'router_ip', 'username': 'user', 'password': 'pass',
    #     'timeout': 60, 'auth_timeout': 90, 'banner_timeout': 90, 'global_delay_factor': 2
    # }
    # To test run_update_procedure, you'd need a live connection object and device_config.
    # e.g. res_avant = run_avant_checks(...)
    # if res_avant['status'] == 'success':
    #    conn = res_avant['connection_obj']
    #    dev_conf = res_avant['device_details_for_update']
    #    image = "jinstall-ppc-19.4R3-S9.7-signed.tgz" # Example image
    #    update_logs = []
    #    res_update = run_update_procedure(conn, dev_conf, image, update_logs)
    #    print(json.dumps(res_update, indent=2))
    #    if res_update.get('connection_obj') and res_update['connection_obj'].is_alive():
    #        res_update['connection_obj'].disconnect()
    # elif res_avant.get('connection_obj') and res_avant['connection_obj'].is_alive(): # if avant failed but conn exists
    #        res_avant['connection_obj'].disconnect()