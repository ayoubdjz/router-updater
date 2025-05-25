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

# --- Helper Functions ---


def verrouiller_routeur(ip, log_messages):
    warnings.filterwarnings("ignore", category=UserWarning, module="portalocker.utils")
    LOCK_DIR = os.path.join(SCRIPT_DIR, "router_locks")
    Path(LOCK_DIR).mkdir(exist_ok=True, parents=True)
    ip_normalisee = ip.replace('.', '_')
    lock_file_path = os.path.join(LOCK_DIR, f"{ip_normalisee}.lock")
    if os.path.exists(lock_file_path):
        try:
            lock = portalocker.Lock(lock_file_path, flags=portalocker.LOCK_EX | portalocker.LOCK_NB)
            lock.acquire()
            lock.release()  # Si acquis = le verrou était inactif
        except (portalocker.LockException, BlockingIOError):
            # Le verrou est déjà actif
            print(f"Le routeur {ip} est déjà verrouillé par un autre processus.")
            return None, None
        except Exception as e:
            print(f"Erreur lors du test du verrou : {e}")
            return None, None
    try:
        lock = portalocker.Lock(lock_file_path, flags=portalocker.LOCK_EX)
        lock.acquire(timeout=5)  # Timeout pour éviter un blocage infini
        return lock, lock_file_path
    except portalocker.LockException:
        print(f"Impossible de verrouiller le routeur {ip} (verrou occupé).")
        return None, None
    except Exception as e:
        print(f"Erreur lors du verrouillage : {e}")
        if os.path.exists(lock_file_path):
            os.remove(lock_file_path)  # Nettoyer le fichier orphelin
        return None, None
    
    

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
                    log_messages.append(f"AVANT Parse Interfaces: 'inet' found for {interface_name} in terse but no IP followed.")
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
                            parsed_log_ip_match = re.search(r"Local:\s*([\d\.]+)", log_line)
                            if parsed_log_ip_match:
                                parsed_log_ip = parsed_log_ip_match.group(1)
                                if parsed_log_ip:
                                    log_ip = parsed_log_ip
                                    interface_ip_map[logical_interface_name] = log_ip
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
    services = set()
    for line in output.splitlines():
        line_stripped = line.strip()
        if line_stripped.endswith(";"):
            service_name = line_stripped.rstrip(";")
            if service_name:
                 services.add(service_name)
    return sorted(list(services))

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
        return {"message": "Aucun protocole configuré trouvé.", "protocols": []}

def _parse_firewall_acls_output_avant(output, log_messages, context="AVANT Parse"):
    output_stripped = output.strip()
    if output_stripped:
        return output_stripped
    else:
        return "Aucune ACL configurée trouvée."
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
    router_hostname = "inconnu"   # Default if not found, as per AVANT.py's tolerance
    
    structured_output_data = {
        "basic_info": {}, "routing_engine": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_info": "", "isis_info": "", "mpls_info": "",
        "ldp_info": "", "rsvp_info": "", "lldp_info": "", "lsp_info": "", "bgp_summary": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": "",
    }
    
    device_details_for_update = {
        'device_type': 'juniper', 'host': ip, 'username': username, 'password': password,
        'timeout': 60, 'auth_timeout': 90, 'banner_timeout': 90, 'global_delay_factor': 2
    }
    temp_avant_file_obj = None

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
            )
            log_messages.append("AVANT: Commande 'set cli screen-length 0' envoyée.")
        except Exception as e_pagination:
            log_messages.append(f"AVANT ATTENTION: Echec désactivation pagination CLI: {str(e_pagination)}. S'appuiera sur '| no-more'.")

        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True) 
        if not os.access(GENERATED_FILES_DIR, os.W_OK):
            raise PermissionError(f"AVANT CRITIQUE: Pas d'accès en écriture à GENERATED_FILES_DIR ({GENERATED_FILES_DIR})!")
        
        temp_avant_file_obj = tempfile.NamedTemporaryFile(
            mode='w+', prefix='AVANT_', suffix='.txt', delete=False, encoding='utf-8', dir=GENERATED_FILES_DIR)
        avant_file_path_internal = temp_avant_file_obj.name
        log_messages.append(f"AVANT: Fichier temporaire AVANT ouvert: {avant_file_path_internal}")
        fichiers_crees_avant.append(avant_file_path_internal) 

        # --- Section: Informations de base du routeur ---
        section_title_basic = "Informations de base du routeur"
        structured_output_data["basic_info"]["section_title"] = section_title_basic
        temp_avant_file_obj.write(f"{section_title_basic} :\n")
        
        output_version_str = ""
        junos_version, router_model = "inconnu", "inconnu" # router_hostname already "inconnu"
        try:
            if not verifier_connexion(connection, log_messages, "AVANT Collect Basic Info"):
                raise Exception("Connexion perdue avant la récupération des informations de base.")
            
            log_messages.append("AVANT Récupération: Informations de base (show version)")
            output_version_str = connection.send_command("show version | no-more", read_timeout=30)
            if isinstance(output_version_str, str):
                output_lines = output_version_str.splitlines()
                cleaned_lines = [line for line in output_lines if not line.strip().startswith("---(more")]
                output_version_str = "\n".join(cleaned_lines)

            for line in output_version_str.splitlines():
                if line.startswith("Hostname:"): router_hostname = line.split("Hostname:")[1].strip()
                elif line.startswith("Model:"): router_model = line.split("Model:")[1].strip()
                elif "Junos: " in line: 
                    try: junos_version = line.split("Junos: ")[1].split()[0].strip() 
                    except IndexError: junos_version = "inconnu (parse error)"
                elif line.startswith("JUNOS Base OS boot [") : 
                    try: junos_version = line.split('[')[1].split(']')[0].strip()
                    except IndexError: pass
            
            if router_hostname == "inconnu":
                log_messages.append(f"AVANT ATTENTION: N'a pas pu parser le hostname depuis 'show version'. Utilisation de '{router_hostname}'. Output: {output_version_str[:200]}...")
            
        except Exception as e_ver:
            err_msg_ver = f"Erreur lors de la récupération des informations de base du routeur (show version): {str(e_ver)}"
            log_messages.append(f"AVANT ERREUR CRITIQUE: {err_msg_ver}")
            temp_avant_file_obj.write(f"\n{err_msg_ver}\n")
            structured_output_data["basic_info"].update({
                "hostname": router_hostname, 
                "model": router_model,       
                "junos_version": junos_version, 
                "error_message": str(e_ver)
            })
            raise

        structured_output_data["basic_info"]["hostname"] = router_hostname
        structured_output_data["basic_info"]["model"] = router_model
        structured_output_data["basic_info"]["junos_version"] = junos_version
        
        temp_avant_file_obj.write(f"Le hostname du routeur est : {router_hostname}\n")
        temp_avant_file_obj.write(f"Le modele du routeur est : {router_model}\n")
        temp_avant_file_obj.write(f"La version du systeme Junos est : {junos_version}\n")
        log_messages.append(f"AVANT Basic Info: Host={router_hostname}, Model={router_model}, Junos={junos_version}")
        
        if temp_avant_file_obj: temp_avant_file_obj.flush(); temp_avant_file_obj.close(); temp_avant_file_obj = None
        if not os.path.exists(avant_file_path_internal): 
            raise FileNotFoundError(f"AVANT: Disparition critique du fichier temporaire AVANT après fermeture: {avant_file_path_internal}")

        final_avant_base = f"AVANT_{username}_{router_hostname}.txt"
        final_avant_path = os.path.join(GENERATED_FILES_DIR, final_avant_base)
        compteur = 1
        while os.path.exists(final_avant_path):
            final_avant_path = os.path.join(GENERATED_FILES_DIR, f"AVANT_{username}_{router_hostname}_{compteur}.txt")
            compteur += 1
        try:
            os.replace(avant_file_path_internal, final_avant_path)
            log_messages.append(f"AVANT: Fichier AVANT renommé en: {final_avant_path}")
            if avant_file_path_internal in fichiers_crees_avant: fichiers_crees_avant.remove(avant_file_path_internal)
            avant_file_path_internal = final_avant_path
            if avant_file_path_internal not in fichiers_crees_avant: fichiers_crees_avant.append(avant_file_path_internal)
        except OSError as e_replace:
            log_messages.append(f"AVANT ERREUR renommage AVANT: {e_replace}. Utilisation du nom temporaire: {avant_file_path_internal}")
        
        with open(avant_file_path_internal, 'a', encoding='utf-8') as file: 
            
            def fetch_and_store_avant(data_key_structured, title_for_file, cmd, 
                                      parser_func=None, is_raw_if_no_parser=True, read_timeout=90,
                                      not_configured_check=None):
                if not verifier_connexion(connection, log_messages, f"AVANT Collect {title_for_file}"): 
                    err_msg_conn_lost = f"Connexion perdue avant collecte de: {title_for_file}"
                    log_messages.append(f"ERREUR AVANT: {err_msg_conn_lost}")
                    structured_output_data[data_key_structured] = f"ERREUR: {err_msg_conn_lost}"
                    file.write(f"\n{title_for_file} :\n") 
                    file.write(f"ERREUR: Connexion perdue.\n")
                    raise Exception(f"AVANT: {err_msg_conn_lost}")

                log_messages.append(f"AVANT Récupération: {title_for_file} (Cmd: {cmd[:70]}{'...' if len(cmd)>70 else ''})")
                file.write(f"\n{title_for_file}:\n") 
                
                output_cmd = ""
                try:
                    cmd_to_send = cmd.strip()
                    if "show " in cmd_to_send and \
                       not cmd_to_send.endswith("| no-more") and \
                       not cmd_to_send.endswith("no-more"):
                         cmd_to_send = f"{cmd_to_send} | no-more"
                    
                    output_cmd = connection.send_command(cmd_to_send, read_timeout=read_timeout)
                    if isinstance(output_cmd, str):
                        output_lines = output_cmd.splitlines()
                        cleaned_lines = [line for line in output_lines if not line.strip().startswith("---(more")]
                        output_cmd = "\n".join(cleaned_lines)
                except Exception as e_cmd: 
                    err_msg_cmd = f"Erreur lors de la récupération de {title_for_file} (commande '{cmd_to_send[:70]}...'): {e_cmd}"
                    log_messages.append(f"ERREUR AVANT: {err_msg_cmd}")
                    structured_output_data[data_key_structured] = err_msg_cmd
                    file.write(f"{err_msg_cmd}\n")
                    log_messages.append(f"AVANT ECHEC: {title_for_file}")
                    raise Exception(f"AVANT: {err_msg_cmd}") from e_cmd

                if not_configured_check: 
                    keywords, message_if_found = not_configured_check
                    output_lower_for_check = output_cmd.lower() if isinstance(output_cmd, str) else ""
                    if isinstance(output_cmd, str) and any(keyword.lower() in output_lower_for_check for keyword in keywords):
                        structured_output_data[data_key_structured] = message_if_found
                        file.write(message_if_found + "\n")
                        log_messages.append(f"AVANT INFO ({title_for_file}): {message_if_found}")
                        log_messages.append(f"AVANT OK (Not Configured/Found): {title_for_file}")
                        return 

                if parser_func:
                    try:
                        parsed_data = parser_func(output_cmd, log_messages, f"AVANT Parse {title_for_file}") 
                        structured_output_data[data_key_structured] = parsed_data
                        if isinstance(parsed_data, list) and parsed_data and isinstance(parsed_data[0], dict):
                            for item_dict in parsed_data: 
                                for k_item,v_item in item_dict.items(): file.write(f"  {k_item}: {v_item}\n")
                                file.write("\n")
                        elif isinstance(parsed_data, list): 
                            for item_str in parsed_data: file.write(f"{item_str}\n")
                        elif isinstance(parsed_data, dict) and "message" in parsed_data : 
                             file.write(str(parsed_data["message"]) + "\n")
                             if "protocols" in parsed_data: 
                                 for p_item in parsed_data["protocols"]: file.write(f"{p_item}\n")
                        else: 
                             file.write(str(parsed_data) + "\n")
                    except Exception as e_parse:
                        parse_err_msg = f"Erreur lors du parsing pour '{title_for_file}': {e_parse}. Output brut:\n{output_cmd[:200]}..."
                        log_messages.append(f"ERREUR AVANT (Parsing): {parse_err_msg}")
                        structured_output_data[data_key_structured] = {"error": parse_err_msg, "raw_output": output_cmd.strip()}
                        file.write(output_cmd.strip() + f"\n# ERREUR DE PARSING: {parse_err_msg}\n")
                        raise Exception(f"AVANT: Erreur de parsing critique pour {title_for_file}") from e_parse
                elif is_raw_if_no_parser:
                    data_to_store = output_cmd.strip() if isinstance(output_cmd, str) else str(output_cmd)
                    structured_output_data[data_key_structured] = data_to_store
                    file.write(data_to_store + "\n")
                else: 
                    lines = [l.strip() for l in output_cmd.splitlines() if l.strip()] if isinstance(output_cmd, str) else [str(output_cmd)]
                    structured_output_data[data_key_structured] = lines
                    for line_item in lines: file.write(f"{line_item}\n")
                
                log_messages.append(f"AVANT OK: {title_for_file}")

            fetch_and_store_avant("routing_engine", "Informations du moteur de routage", "show chassis routing-engine", is_raw_if_no_parser=True, read_timeout=90)

            if not verifier_connexion(connection, log_messages, "AVANT Collect Interfaces"): 
                raise Exception("AVANT: Connexion perdue avant collecte des interfaces")
            section_title_interfaces = "Informations sur les interfaces"
            log_messages.append(f"AVANT Récupération: {section_title_interfaces}")
            file.write(f"\n{section_title_interfaces} :\n")
            try:
                cmd_terse = "show interfaces terse | no-more"
                cmd_detail = "show interfaces detail | no-more"
                out_terse_raw = connection.send_command(cmd_terse, read_timeout=90)
                out_terse_lines = out_terse_raw.splitlines()
                cleaned_terse_lines = [line for line in out_terse_lines if not line.strip().startswith("---(more")]
                out_terse = "\n".join(cleaned_terse_lines)
                out_detail_raw = connection.send_command(cmd_detail, read_timeout=180) 
                out_detail_lines = out_detail_raw.splitlines()
                cleaned_detail_lines = [line for line in out_detail_lines if not line.strip().startswith("---(more")]
                out_detail = "\n".join(cleaned_detail_lines)

                up_list, down_list = parse_interfaces_structured(out_terse, out_detail, log_messages)
                structured_output_data["interfaces_up"] = up_list
                # If down_list is empty, set a message instead of empty list
                if down_list:
                    structured_output_data["interfaces_down"] = down_list
                else:
                    structured_output_data["interfaces_down"] = "Aucune interface inactive trouvée."
                
                file.write("Les Interfaces up:\n")
                if up_list:
                    for iface in up_list: file.write(f"{iface['name']} - Vitesse: {iface['speed']} - IP: {iface['ip_address']} - MAC: {iface['mac_address']}\n")
                else: file.write("Aucune interface active trouvée.\n")
                
                file.write("Les Interfaces down:\n")
                if down_list:
                    for iface in down_list: file.write(f"{iface['name']} - Vitesse: {iface['speed']} - IP: {iface['ip_address']} - MAC: {iface['mac_address']}\n")
                else: file.write("Aucune interface inactive trouvée.\n")
                log_messages.append(f"AVANT OK: {section_title_interfaces}")
            except Exception as e_intf:
                err_msg_intf = f"Erreur lors de la récupération des informations des interfaces : {e_intf}"
                log_messages.append(f"ERREUR AVANT: {err_msg_intf}")
                structured_output_data["interfaces_up"] = [{"error": err_msg_intf}]
                structured_output_data["interfaces_down"] = [{"error": err_msg_intf}]
                file.write(f"{err_msg_intf}\n")
                raise Exception(f"AVANT: {err_msg_intf}") from e_intf

            fetch_and_store_avant("arp_table", "Informations ARP", "show arp", is_raw_if_no_parser=True, read_timeout=90)
            
            file.write("\nInformations sur les routes :\n")
            file.write("Resume des routes :\n")
            fetch_and_store_avant(
                data_key_structured="route_summary", 
                title_for_file="Resume des routes", 
                cmd="show route summary", 
                is_raw_if_no_parser=True, 
                read_timeout=90,
            )

            fetch_and_store_avant("ospf_info", "Protocole OSPF", "show ospf interface brief", is_raw_if_no_parser=True, read_timeout=90, 
                                  not_configured_check=(["OSPF instance is not running"], "OSPF n'est pas configuré sur ce routeur."))
            fetch_and_store_avant("isis_info", "Protocole IS-IS", "show isis adjacency", is_raw_if_no_parser=True, read_timeout=90,
                                  not_configured_check=(["IS-IS instance is not running"], "IS-IS n'est pas configuré sur ce routeur."))
            fetch_and_store_avant("mpls_info", "Protocole MPLS", "show mpls interface", is_raw_if_no_parser=True, read_timeout=90,
                                  not_configured_check=(["MPLS not configured"], "MPLS n'est pas configuré sur ce routeur."))
            fetch_and_store_avant("ldp_info", "Protocole LDP", "show ldp session", is_raw_if_no_parser=True, read_timeout=90,
                                  not_configured_check=(["LDP instance is not running"], "LDP n'est pas configuré sur ce routeur."))
            fetch_and_store_avant("rsvp_info", "Protocole RSVP", "show rsvp interface", is_raw_if_no_parser=True, read_timeout=90,
                                  not_configured_check=(["RSVP not configured"], "RSVP n'est pas configuré sur ce routeur."))
            
            try:
                if not verifier_connexion(connection, log_messages, "AVANT Collect LLDP"): raise Exception("Connexion perdue LLDP")
                file.write("\nProtocole LLDP :\n")
                lldp_output = connection.send_command("show lldp neighbor | no-more", read_timeout=90)
                if not lldp_output.strip():
                    msg = "LLDP n'est pas configuré ou aucun voisin n'a été détecté."
                    log_messages.append(f"AVANT INFO (LLDP): {msg}")
                    file.write(msg + "\n")
                    structured_output_data["lldp_info"] = msg
                else:
                    file.write("Voisins LLDP découverts :\n")
                    file.write(lldp_output.strip() + "\n")
                    structured_output_data["lldp_info"] = lldp_output.strip()
                log_messages.append("AVANT OK: Protocole LLDP")
            except Exception as e_lldp:
                err_msg_lldp = f"Erreur lors de la vérification du protocole LLDP : {e_lldp}"
                log_messages.append(f"ERREUR AVANT: {err_msg_lldp}")
                file.write(f"{err_msg_lldp}\n")
                structured_output_data["lldp_info"] = err_msg_lldp
                raise Exception(f"AVANT: {err_msg_lldp}") from e_lldp

            fetch_and_store_avant("lsp_info", "Protocole LSP", "show mpls lsp", is_raw_if_no_parser=True, read_timeout=90,
                                  not_configured_check=(["MPLS not configured"], "Aucune session lsp trouvé."))
            fetch_and_store_avant("bgp_summary", "Protocole BGP", "show bgp summary", is_raw_if_no_parser=True, read_timeout=90,
                                  not_configured_check=(["BGP is not running"], "BGP n'est pas configuré sur ce routeur."))
            
            fetch_and_store_avant("system_services", "Services configurés", "show configuration system services", 
                                  parser_func=_parse_services_avant, is_raw_if_no_parser=False, read_timeout=90)
            fetch_and_store_avant("configured_protocols", "Protocoles configurés", "show configuration protocols", 
                                  parser_func=_parse_configured_protocols_output_avant, is_raw_if_no_parser=False, read_timeout=90)
            fetch_and_store_avant("firewall_config", "Listes de Contrôle d'Accès (ACL)", "show configuration firewall", 
                                  parser_func=_parse_firewall_acls_output_avant, is_raw_if_no_parser=False, read_timeout=90)
            
            log_msg_cmd = 'show log messages | match "error|warning|critical" | last 10'
            fetch_and_store_avant(data_key_structured="critical_logs_messages", title_for_file="Logs des erreurs critiques - messages",
                                  cmd=log_msg_cmd, is_raw_if_no_parser=True, read_timeout=60)
            
            chassisd_log_cmd = 'show log chassisd | match "error|warning|critical" | last 10'
            fetch_and_store_avant(data_key_structured="critical_logs_chassisd", title_for_file="Logs des erreurs critiques - chassisd",
                                  cmd=chassisd_log_cmd, is_raw_if_no_parser=True, read_timeout=60)
            
            fetch_and_store_avant("full_config_set", "La configuration totale", "show configuration | display set", 
                                  is_raw_if_no_parser=True, read_timeout=300)

            base_config_filename = f"CONFIGURATION_{username}_{router_hostname}.txt"
            config_file_path = os.path.join(GENERATED_FILES_DIR, base_config_filename)
            compteur_cfg = 1
            while os.path.exists(config_file_path):
                config_file_path = os.path.join(GENERATED_FILES_DIR, f"CONFIGURATION_{username}_{router_hostname}_{compteur_cfg}.txt")
                compteur_cfg += 1
            config_content_to_save = structured_output_data.get("full_config_set", "Erreur: Contenu de configuration non récupéré.")
            if isinstance(config_content_to_save, dict) and "error" in config_content_to_save: 
                 config_content_to_save = f"Erreur lors de la récupération de la configuration:\n{config_content_to_save.get('error', '')}\nRaw output (if any):\n{config_content_to_save.get('raw_output','')}"
            elif isinstance(config_content_to_save, dict) and "message" in config_content_to_save :
                 config_content_to_save = config_content_to_save["message"]
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
            "device_details_for_update": device_details_for_update 
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
            "device_details_for_update": device_details_for_update 
        }

    except Exception as e_generic:
        import traceback
        error_msg = f"AVANT Erreur majeure dans run_avant_checks: {str(e_generic)} (Type: {type(e_generic).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        
        for key_data_error in structured_output_data:
            if not structured_output_data[key_data_error] or \
               (isinstance(structured_output_data[key_data_error], dict) and not structured_output_data[key_data_error]):
                structured_output_data[key_data_error] = {"message": f"Collecte interrompue ou donnée non récupérée suite à l'erreur: {str(e_generic)}"}

        return {
            "status": "error", "message": error_msg, 
            "lock_file_path": lock_file_path, 
            "fichiers_crees": fichiers_crees_avant, 
            "structured_data": structured_output_data, 
            "log_messages": log_messages,
            "connection_obj": connection 
        }
    finally:
        if temp_avant_file_obj and not temp_avant_file_obj.closed:
            temp_avant_file_obj.close()
            log_messages.append(f"AVANT (finally): Fichier temporaire AVANT {temp_avant_file_obj.name} fermé.")

# --- Update Procedure Helper Functions ---

def _validate_image_filename(image_file, log_messages):
    if not image_file:
        log_messages.append("UPDATE ERREUR: Nom du package non spécifié.")
        return False, None
    if not image_file.endswith('.tgz'):
        log_messages.append(f"UPDATE ATTENTION: Package {image_file} ne finit pas par .tgz.")
    if JUNOS_IMG_RE_PREFIX not in image_file:
        log_messages.append(f"UPDATE ERREUR: Format de nom de fichier {image_file} potentiellement incorrect. Attendu: {JUNOS_IMG_RE_PREFIX}<VERSION>{JUNOS_IMG_RE_SUFFIX}")
        return False, None
    try:
        expected_version = None
        if "-signed.tgz" in image_file:
             expected_version = image_file.split(JUNOS_IMG_RE_PREFIX)[-1].split("-signed.tgz")[0]
        
        if not expected_version and ".tgz" in image_file:
             expected_version = image_file.split(JUNOS_IMG_RE_PREFIX)[-1].split(".tgz")[0]
        
        if not expected_version:
            log_messages.append(f"UPDATE ERREUR: Impossible d'extraire la version de {image_file}.")
            return False, None
        return True, expected_version
    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Exception lors de l'extraction de la version de {image_file}: {e}")
        return False, None


def _check_package_on_router(connection, image_file, log_messages):
    pkg_path_re0 = f"/var/tmp/{image_file}"
    try:
        output_current_re = connection.send_command(f"file list {pkg_path_re0}", read_timeout=COMMAND_TIMEOUT_SHORT)
        found_on_current_re = "No such file or directory" not in output_current_re and image_file in output_current_re
        
        if found_on_current_re:
            log_messages.append(f"UPDATE: Package {image_file} trouvé sur {pkg_path_re0} (RE courant).")
            return True

        log_messages.append(f"UPDATE ERREUR: Package {image_file} non trouvé sur {pkg_path_re0} (RE courant). "
                            f"L'utilisateur doit s'assurer que le package est dans /var/tmp/ du RE à mettre à jour AVANT de lancer la mise à jour de ce RE.")
        return False
        
    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Exception lors de la vérification du package {image_file}: {e}")
        return False

def _get_routing_engine_status(connection, log_messages):
    try:
        output = connection.send_command("show chassis routing-engine", read_timeout=COMMAND_TIMEOUT_MEDIUM)
        re_status = {}
        current_slot = -1
        slot_info_lines = {}

        for line in output.splitlines():
            line_stripped = line.strip()
            
            slot_match = re.match(r"Slot (\d):", line_stripped)
            if slot_match:
                current_slot = int(slot_match.group(1))
                if current_slot not in re_status:
                    re_status[current_slot] = {"slot": current_slot}
                slot_info_lines[current_slot] = []
            
            if current_slot != -1:
                slot_info_lines[current_slot].append(line_stripped)
                if "Current state" in line_stripped:
                    state_val = line_stripped.split("Current state")[-1].strip()
                    re_status[current_slot]["state"] = state_val
                elif "Junos version" in line_stripped:
                    version_val = line_stripped.split("Junos version")[-1].strip()
                    re_status[current_slot]["version"] = version_val
        
        if 0 not in re_status:
            log_messages.append("UPDATE ERREUR: Impossible de déterminer l'état de RE0.")
            return None
        if 1 not in re_status:
            log_messages.append("UPDATE INFO: Seul RE0 détecté. Procédure dual-RE non applicable telle quelle.")
            return {"single_re": True, 0: re_status[0]} 
        
        return re_status

    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Impossible d'obtenir l'état des REs: {e}")
        return None

def _wait_for_re_to_reach_state(connection, re_slot_to_monitor, target_state_keywords, log_messages,
                                re_status_getter_func,
                                timeout=REBOOT_VERIFY_TIMEOUT, check_interval=RE_STATE_CHECK_INTERVAL):
    if isinstance(target_state_keywords, str):
        target_state_keywords = [target_state_keywords]
    
    start_time = time.time()
    target_states_str = ', '.join(target_state_keywords)
    log_messages.append(f"UPDATE: Attente que RE{re_slot_to_monitor} atteigne l'état contenant '{target_states_str}' (max {timeout}s)...")
    
    while time.time() - start_time < timeout:
        all_re_status = re_status_getter_func(connection, log_messages)
        if all_re_status and re_slot_to_monitor in all_re_status:
            current_re_info = all_re_status[re_slot_to_monitor]
            current_state = current_re_info.get("state")
            log_messages.append(f"UPDATE: RE{re_slot_to_monitor} état actuel: {current_state if current_state else 'Inconnu'}")
            if current_state:
                if any(keyword.lower() in current_state.lower() for keyword in target_state_keywords):
                    log_messages.append(f"UPDATE: ✓ RE{re_slot_to_monitor} a atteint un état correspondant à '{target_states_str}'. État trouvé: {current_state}.")
                    return True
        else:
            log_messages.append(f"UPDATE: Impossible d'obtenir l'état de RE{re_slot_to_monitor}, nouvelle tentative dans {check_interval}s.")
        time.sleep(check_interval)
    
    log_messages.append(f"UPDATE ERREUR: Timeout ({timeout}s) atteint. RE{re_slot_to_monitor} n'a pas atteint un état correspondant à '{target_states_str}'.")
    return False

def _verify_re_version(connection, re_slot_to_check, expected_version, log_messages):
    try:
        cmd_version = ""
        all_re_status = _get_routing_engine_status(connection, log_messages)
        if not all_re_status or ("single_re" in all_re_status and re_slot_to_check != 0):
            log_messages.append(f"UPDATE ERREUR: Impossible de déterminer l'état RE pour la vérification de version de RE{re_slot_to_check}.")
            return False

        is_single_re = all_re_status.get("single_re", False)
        current_master_slot = -1

        if not is_single_re:
            for slot, info in all_re_status.items():
                if isinstance(slot, int) and "master" in info.get("state", "").lower() :
                    current_master_slot = slot
                    break
            if current_master_slot == -1 and 0 in all_re_status and "present" in all_re_status[0].get("state", "").lower():
                 current_master_slot = 0 
                 log_messages.append(f"UPDATE INFO: Pas de master explicite trouvé, RE0 est 'présent'. On suppose connecté à RE0 pour la vérification de version.")

        if is_single_re and re_slot_to_check == 0:
            cmd_version = "show version | match Junos:"
        elif not is_single_re and current_master_slot != -1:
            if re_slot_to_check == current_master_slot:
                cmd_version = "show version | match Junos:"
            else:
                cmd_version = "show version invoke-on other-routing-engine | match Junos:"
        else:
            log_messages.append(f"UPDATE ERREUR: Logique de commande de version ambiguë pour RE{re_slot_to_check}. État REs: {all_re_status}")
            return False
            
        log_messages.append(f"UPDATE: Vérification de la version sur RE{re_slot_to_check} (Commande: {cmd_version})")
        version_output = connection.send_command(cmd_version, read_timeout=COMMAND_TIMEOUT_MEDIUM)
        
        current_version_found = None
        for line in version_output.splitlines():
            if "Junos: " in line:
                current_version_found = line.split("Junos:")[1].strip().split()[0] 
                break
            elif line.startswith("JUNOS Base OS boot [") : 
                try: current_version_found = line.split('[')[1].split(']')[0].strip()
                except IndexError: pass
                break
        
        if not current_version_found:
            log_messages.append(f"UPDATE ERREUR: Impossible d'extraire la version actuelle de RE{re_slot_to_check} depuis la sortie: {version_output}")
            return False

        log_messages.append(f"UPDATE: Version actuelle sur RE{re_slot_to_check}: {current_version_found}, Version attendue: {expected_version}")
        if expected_version in current_version_found:
            log_messages.append(f"UPDATE: ✓ La version sur RE{re_slot_to_check} ({current_version_found}) est compatible avec la version attendue ({expected_version}).")
            return True
        else:
            log_messages.append(f"UPDATE ERREUR: La version sur RE{re_slot_to_check} ({current_version_found}) ne correspond pas à la version attendue ({expected_version}).")
            return False
            
    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Exception lors de la vérification de version sur RE{re_slot_to_check}: {e}")
        return False

def _perform_re_upgrade(connection, image_file, log_messages, target_is_other_re=True):
    try:
        original_prompt = connection.base_prompt
        
        if target_is_other_re:
            login_cmd = "request routing-engine login other-routing-engine"
            log_messages.append(f"UPDATE: Connexion à l'autre RE via '{login_cmd}'...")
            output_login = connection.send_command(login_cmd, expect_string=r'(%|#|>)\s*$', read_timeout=COMMAND_TIMEOUT_MEDIUM, strip_command=False, strip_prompt=False)

            if "error" in output_login.lower() or "failed" in output_login.lower() or "unknown command" in output_login.lower():
                 log_messages.append(f"UPDATE ERREUR: Échec de la connexion à l'autre RE: {output_login}")
                 return False
            log_messages.append(f"UPDATE: Connecté à l'autre RE. Nouveau prompt trouvé: {connection.find_prompt(delay_factor=1)}")


        install_cmd = f"request system software add /var/tmp/{image_file} no-validate"
        log_messages.append(f"UPDATE: Installation du logiciel sur le RE {'autre' if target_is_other_re else 'courant'} (Cmd: {install_cmd}). Timeout: {SOFTWARE_INSTALL_TIMEOUT}s")
        
        install_output = connection.send_command(install_cmd, read_timeout=SOFTWARE_INSTALL_TIMEOUT, delay_factor=4) 

        if "error" in install_output.lower() or "fail" in install_output.lower():
            log_messages.append(f"UPDATE ERREUR: Échec de l'installation du logiciel: {install_output}")
            if target_is_other_re: 
                try:
                    connection.send_command("exit", expect_string=original_prompt, read_timeout=15)
                    connection.set_base_prompt(original_prompt)
                except Exception as e_exit: log_messages.append(f"UPDATE WARNING: échec de la sortie de la session RE distante: {e_exit}")
            return False
        log_messages.append("UPDATE: ✓ Installation du logiciel terminée.")

        reboot_cmd = "request system reboot"
        log_messages.append(f"UPDATE: Lancement du redémarrage du RE {'autre' if target_is_other_re else 'courant'} (Cmd: {reboot_cmd})")
        
        output_reboot_q = connection.send_command(
            reboot_cmd, 
            expect_string=r"Reboot the system.*\[yes,no\]", 
            read_timeout=COMMAND_TIMEOUT_SHORT, strip_prompt=False, strip_command=False
        )
        log_messages.append(f"UPDATE: Réponse à la demande de redémarrage: {output_reboot_q.strip()}")

        if "Reboot the system" in output_reboot_q and "[yes,no]" in output_reboot_q:
            output_reboot_y = connection.send_command_timing("yes", max_loops=15)
            log_messages.append(f"UPDATE: Confirmation de redémarrage ('yes') envoyée. Réponse (Timing): {output_reboot_y.strip()}")
        else:
            log_messages.append(f"UPDATE ERREUR: Question de confirmation de redémarrage non reçue comme attendu. Sortie: {output_reboot_q}")
            if target_is_other_re: 
                try:
                    connection.send_command("exit", expect_string=original_prompt, read_timeout=15)
                    connection.set_base_prompt(original_prompt)
                except: pass
            return False
            
        log_messages.append(f"UPDATE: ✓ Commande de redémarrage pour RE {'autre' if target_is_other_re else 'courant'} envoyée.")
        
        if target_is_other_re:
            connection.set_base_prompt(original_prompt) 
            log_messages.append(f"UPDATE: Prompt Netmiko restauré à: '{original_prompt}' pour la connexion principale.")

        return True

    except ReadTimeout as e_timeout:
        log_messages.append(f"UPDATE ERREUR: ReadTimeout pendant la mise à jour/redémarrage du RE: {e_timeout}")
        # Check if the timeout occurred during the reboot command specifically
        # This requires reboot_cmd to be in locals(), meaning the command was defined.
        # And, the error message itself might contain the command string.
        if 'reboot_cmd' in locals() and str(e_timeout).lower().find(reboot_cmd.lower()) != -1:
             log_messages.append("UPDATE INFO: ReadTimeout pendant la commande de redémarrage est souvent normal car la session est coupée.")
             if target_is_other_re and 'original_prompt' in locals(): connection.set_base_prompt(original_prompt)
             return True 
        if target_is_other_re and 'original_prompt' in locals(): connection.set_base_prompt(original_prompt)
        return False
    except Exception as e:
        log_messages.append(f"UPDATE ERREUR: Exception pendant la mise à jour/redémarrage du RE: {e}")
        if target_is_other_re and 'original_prompt' in locals(): 
            try:
                if connection.is_alive():
                    connection.send_command("exit", expect_string=original_prompt, read_timeout=10)
                connection.set_base_prompt(original_prompt)
            except: pass 
        return False


def _switch_mastership_and_reconnect(current_connection, device_config_for_reconnect, log_messages,
                                     expected_new_master_slot,
                                     switch_timeout=SWITCHOVER_TIMEOUT, 
                                     reconnect_attempts=RECONNECT_ATTEMPTS, 
                                     reconnect_delay=RECONNECT_DELAY):
    try:
        log_messages.append(f"UPDATE: Tentative de basculement de mastership. Nouveau master attendu: RE{expected_new_master_slot}.")
        
        switch_q_cmd = "request chassis routing-engine master switch"
        switch_q_out = current_connection.send_command(switch_q_cmd, 
                                                       expect_string=r"Toggle mastership.*\[yes,no\]", 
                                                       strip_prompt=False, strip_command=False, read_timeout=COMMAND_TIMEOUT_SHORT)
        log_messages.append(f"UPDATE: Demande de basculement: {switch_q_out.strip()}")
        if "Toggle mastership".lower() not in switch_q_out.lower():
            log_messages.append(f"UPDATE ERREUR: Message de confirmation de basculement inattendu: {switch_q_out}")
            return None 

        switch_y_out = current_connection.send_command_timing("yes", max_loops=15)
        log_messages.append(f"UPDATE: Confirmation de basculement ('yes') envoyée. Réponse (Timing): {switch_y_out.strip()}")
        
        log_messages.append("UPDATE: Basculement initié. Déconnexion de la session actuelle...")
        current_connection.disconnect()
    except Exception as e_switch_cmd:
        log_messages.append(f"UPDATE ATTENTION: Erreur pendant la commande de basculement ou la déconnexion: {e_switch_cmd}. Poursuite avec la tentative de reconnexion.")
        if current_connection and current_connection.is_alive():
            try: current_connection.disconnect()
            except: pass


    log_messages.append(f"UPDATE: Attente de {switch_timeout}s pour la fin du basculement...")
    time.sleep(switch_timeout)

    log_messages.append("UPDATE: Tentative de reconnexion après basculement...")
    new_connection = None
    for attempt in range(1, reconnect_attempts + 1):
        log_messages.append(f"UPDATE: Tentative de reconnexion {attempt}/{reconnect_attempts}...")
        try:
            new_connection = ConnectHandler(**device_config_for_reconnect)
            log_messages.append("UPDATE: ✓ Reconnecté physiquement.")
            
            re_statuses = _get_routing_engine_status(new_connection, log_messages)
            if re_statuses and expected_new_master_slot in re_statuses and \
               "master" in re_statuses[expected_new_master_slot].get("state", "").lower():
                log_messages.append(f"UPDATE: ✓ Basculement vers RE{expected_new_master_slot} réussi et vérifié.")
                return new_connection
            else:
                state_found = re_statuses.get(expected_new_master_slot, {}).get('state', 'N/A') if re_statuses else 'N/A'
                log_messages.append(f"UPDATE ERREUR: RE{expected_new_master_slot} n'est pas Master après reconnexion (état trouvé: {state_found}).")
                if new_connection and new_connection.is_alive(): new_connection.disconnect()
                new_connection = None
        except (NetmikoTimeoutException, NetmikoAuthenticationException, ReadTimeout, ConnectionRefusedError, Exception) as e_reconnect:
            log_messages.append(f"UPDATE ERREUR: Tentative de reconnexion {attempt} échouée: {e_reconnect}")
            if new_connection and new_connection.is_alive():
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
    if not activate: 
        config_commands.append("set system processes clksyncd-service disable")
    else:
        config_commands.append("delete system processes clksyncd-service disable")

    try:
        log_messages.append("UPDATE: Entrée en mode configuration pour les MàJ HA...")
        connection.config_mode()
        for cmd in config_commands:
            log_messages.append(f"UPDATE: Envoi commande HA: {cmd}")
            output = connection.send_command(cmd, read_timeout=COMMAND_TIMEOUT_SHORT)
            if "error" in output.lower() or "unknown command" in output.lower() or "failed" in output.lower():
                log_messages.append(f"UPDATE ERREUR: Commande HA '{cmd}' échouée: {output}")
                try: 
                    if connection.check_config_mode(): connection.exit_config_mode()
                except: pass
                return False
        
        log_messages.append("UPDATE: Application de la configuration HA avec 'commit synchronize'...")
        commit_output = connection.send_command("commit synchronize", read_timeout=COMMAND_TIMEOUT_LONG)

        if "commit complete" not in commit_output.lower() and "commit successful" not in commit_output.lower() and "configuration check succeeds" not in commit_output.lower():
            log_messages.append(f"UPDATE ERREUR: 'commit synchronize' pour HA a échoué ou a eu une réponse inattendue: {commit_output}")
            try: 
                if connection.check_config_mode(): connection.exit_config_mode()
            except: pass
            return False

        log_messages.append("UPDATE: Sortie du mode de configuration après MàJ HA.")
        connection.exit_config_mode()
        log_messages.append(f"UPDATE: ✓ Configuration HA {'activée' if activate else 'désactivée'}.")
        return True
    except Exception as e_ha_config:
        log_messages.append(f"UPDATE ERREUR: Exception pendant la configuration HA: {e_ha_config}")
        try: 
            if connection.is_alive() and connection.check_config_mode(): 
                connection.exit_config_mode()
        except: pass
        return False

# --- Main Update Procedure ---
def run_update_procedure(connection, device_config_for_reconnect, image_file, log_messages, skip_re0_final_switchback=False):
    log_messages.append(f"--- UPDATE: Début de run_update_procedure avec image: {image_file} ---")
    
    current_connection_obj = connection

    valid_format, expected_junos_version = _validate_image_filename(image_file, log_messages)
    if not valid_format:
        return {"status": "error", "message": "Format du nom de fichier image invalide.", "log_messages": log_messages, "connection_obj": current_connection_obj}
    log_messages.append(f"UPDATE: Version Junos attendue après MAJ (de nom de fichier): {expected_junos_version}")

    if not _check_package_on_router(current_connection_obj, image_file, log_messages):
        return {"status": "error", "message": f"Package {image_file} non trouvé ou inaccessible.", "log_messages": log_messages, "connection_obj": current_connection_obj}

    initial_re_status = _get_routing_engine_status(current_connection_obj, log_messages)
    if not initial_re_status:
        return {"status": "error", "message": "Impossible de déterminer l'état initial des REs.", "log_messages": log_messages, "connection_obj": current_connection_obj}
    if initial_re_status.get("single_re"):
        return {"status": "error", "message": "Système single-RE détecté. Cette procédure est pour dual-RE.", "log_messages": log_messages, "connection_obj": current_connection_obj}
    if 0 not in initial_re_status or 1 not in initial_re_status:
        return {"status": "error", "message": "Configuration RE inattendue (RE0 ou RE1 manquant dans le statut).", "log_messages": log_messages, "connection_obj": current_connection_obj}

    original_master_slot = -1
    original_backup_slot = -1
    if "master" in initial_re_status[0].get("state", "").lower():
        original_master_slot, original_backup_slot = 0, 1
    elif "master" in initial_re_status[1].get("state", "").lower():
        original_master_slot, original_backup_slot = 1, 0
    else:
        return {"status": "error", "message": "Impossible de déterminer le RE master initial.", "log_messages": log_messages, "connection_obj": current_connection_obj}
    log_messages.append(f"UPDATE: RE Master initial: RE{original_master_slot}, RE Backup initial: RE{original_backup_slot}")

    try:
        if not _set_ha_features(current_connection_obj, activate=False, log_messages=log_messages):
            return {"status": "error", "message": "Échec de la désactivation des fonctionnalités HA.", "log_messages": log_messages, "connection_obj": current_connection_obj}

        re_to_update_first = original_backup_slot
        log_messages.append(f"--- UPDATE: Phase 1 - Mise à jour de RE{re_to_update_first} (backup actuel) ---")
        if not _perform_re_upgrade(current_connection_obj, image_file, log_messages, target_is_other_re=True):
             if current_connection_obj and current_connection_obj.is_alive(): _set_ha_features(current_connection_obj, activate=True, log_messages=log_messages)
             return {"status": "error", "message": f"Échec de la mise à jour de RE{re_to_update_first}.", "log_messages": log_messages, "connection_obj": current_connection_obj}
        
        if not _wait_for_re_to_reach_state(current_connection_obj, re_to_update_first, ["Backup", "Present"], log_messages, _get_routing_engine_status, timeout=REBOOT_VERIFY_TIMEOUT):
             if current_connection_obj and current_connection_obj.is_alive(): _set_ha_features(current_connection_obj, activate=True, log_messages=log_messages)
             return {"status": "error", "message": f"RE{re_to_update_first} n'est pas revenu en état opérationnel (Backup/Present) après redémarrage.", "log_messages": log_messages, "connection_obj": current_connection_obj}

        if not _verify_re_version(current_connection_obj, re_to_update_first, expected_junos_version, log_messages):
             if current_connection_obj and current_connection_obj.is_alive(): _set_ha_features(current_connection_obj, activate=True, log_messages=log_messages)
             return {"status": "error", "message": f"Version incorrecte sur RE{re_to_update_first} après mise à jour.", "log_messages": log_messages, "connection_obj": current_connection_obj}
        log_messages.append(f"UPDATE: ✓ RE{re_to_update_first} mis à jour et vérifié.")

        log_messages.append(f"--- UPDATE: Basculement vers RE{re_to_update_first} ---")
        new_master_after_first_switch = re_to_update_first
        # _switch_mastership_and_reconnect returns a *new* connection object or None
        temp_conn = _switch_mastership_and_reconnect(current_connection_obj, device_config_for_reconnect, log_messages,
                                                                  expected_new_master_slot=new_master_after_first_switch)
        if not temp_conn: # If switchover failed
            # current_connection_obj might be dead or to the old master. HA re-enable might fail.
            if current_connection_obj and current_connection_obj.is_alive(): _set_ha_features(current_connection_obj, activate=True, log_messages=log_messages)
            return {"status": "error", "message": f"Échec du basculement ou de la reconnexion à RE{new_master_after_first_switch}.", "log_messages": log_messages, "connection_obj": None}
        current_connection_obj = temp_conn # Update to the new connection object
        
        re_to_update_second = original_master_slot
        log_messages.append(f"--- UPDATE: Phase 2 - Mise à jour de RE{re_to_update_second} (maintenant backup) ---")
        if not _perform_re_upgrade(current_connection_obj, image_file, log_messages, target_is_other_re=True):
            if current_connection_obj and current_connection_obj.is_alive(): _set_ha_features(current_connection_obj, activate=True, log_messages=log_messages)
            return {"status": "error", "message": f"Échec de la mise à jour de RE{re_to_update_second}.", "log_messages": log_messages, "connection_obj": current_connection_obj}

        if not _wait_for_re_to_reach_state(current_connection_obj, re_to_update_second, ["Backup", "Present"], log_messages, _get_routing_engine_status, timeout=REBOOT_VERIFY_TIMEOUT):
            if current_connection_obj and current_connection_obj.is_alive(): _set_ha_features(current_connection_obj, activate=True, log_messages=log_messages)
            return {"status": "error", "message": f"RE{re_to_update_second} n'est pas revenu en état opérationnel (Backup/Present) après redémarrage.", "log_messages": log_messages, "connection_obj": current_connection_obj}

        if not _verify_re_version(current_connection_obj, re_to_update_second, expected_junos_version, log_messages):
            if current_connection_obj and current_connection_obj.is_alive(): _set_ha_features(current_connection_obj, activate=True, log_messages=log_messages)
            return {"status": "error", "message": f"Version incorrecte sur RE{re_to_update_second} après mise à jour.", "log_messages": log_messages, "connection_obj": current_connection_obj}
        log_messages.append(f"UPDATE: ✓ RE{re_to_update_second} mis à jour et vérifié.")
        
        if not _set_ha_features(current_connection_obj, activate=True, log_messages=log_messages):
            return {"status": "error", "message": "Échec de la réactivation des fonctionnalités HA après les mises à jour.", "log_messages": log_messages, "connection_obj": current_connection_obj}

        current_master_before_final_switch = new_master_after_first_switch
        current_master_after_final_switch = current_master_before_final_switch # Default if no switchback
        
        if not skip_re0_final_switchback and original_master_slot != current_master_before_final_switch :
            log_messages.append(f"--- UPDATE: Basculement final optionnel vers RE{original_master_slot} (master d'origine) ---")
            temp_conn_final = _switch_mastership_and_reconnect(current_connection_obj, device_config_for_reconnect, log_messages,
                                                                      expected_new_master_slot=original_master_slot)
            if not temp_conn_final:
                log_messages.append(f"UPDATE ATTENTION: Échec du basculement final vers RE{original_master_slot}. La MAJ est finie, mais le master est RE{current_master_before_final_switch}.")
                # current_connection_obj is still to the master RE *before* this failed switchback attempt
                return {
                    "status": "success_with_warning", 
                    "message": f"Mise à jour terminée, mais échec du basculement final vers RE{original_master_slot}. Master actuel: RE{current_master_before_final_switch}.",
                    "updated_junos_info": {"new_junos_version": expected_junos_version, "current_master_re": current_master_before_final_switch},
                    "log_messages": log_messages, 
                    "connection_obj": current_connection_obj
                }
            current_connection_obj = temp_conn_final # Update to the connection to the new (original) master
            current_master_after_final_switch = original_master_slot
            log_messages.append(f"UPDATE: ✓ Basculement final vers RE{original_master_slot} réussi.")
        elif skip_re0_final_switchback:
            log_messages.append(f"UPDATE: Basculement final vers RE{original_master_slot} ignoré (skip_re0_final_switchback=True). Master actuel: RE{current_master_before_final_switch}.")
        else:
             log_messages.append(f"UPDATE: Pas de basculement final nécessaire, RE{original_master_slot} (master d'origine) est déjà le master actuel.")


        log_messages.append("UPDATE: ✓ Procédure de mise à jour terminée avec succès.")
        return {
            "status": "success", 
            "message": "Mise à jour terminée avec succès.",
            "updated_junos_info": {"new_junos_version": expected_junos_version, "current_master_re": current_master_after_final_switch},
            "log_messages": log_messages, 
            "connection_obj": current_connection_obj
        }

    except Exception as e_update_main:
        import traceback
        err_msg = f"UPDATE ERREUR: Erreur majeure imprévue dans run_update_procedure: {str(e_update_main)}"
        log_messages.append(err_msg + f"\nTraceback:\n{traceback.format_exc()}")
        if current_connection_obj and current_connection_obj.is_alive():
            log_messages.append("UPDATE: Tentative de réactivation HA en urgence suite à une erreur...")
            _set_ha_features(current_connection_obj, activate=True, log_messages=log_messages)
        return {"status": "error", "message": err_msg, "log_messages": log_messages, "connection_obj": current_connection_obj if current_connection_obj and current_connection_obj.is_alive() else None}


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
    #    conn = res_avant['connection_obj'] # This object would be passed
    #    dev_conf = res_avant['device_details_for_update'] # This dict would be passed
    #    image = "jinstall-ppc-19.4R3-S9.7-signed.tgz" # Example image
    #    update_logs = [] # Pass a fresh list for logs
    #    res_update = run_update_procedure(conn, dev_conf, image, update_logs)
    #    print(json.dumps(res_update, indent=2, default=str)) # Use default=str for connection obj if not removed
    #    
    #    # The connection object returned by res_update might be different from original 'conn'
    #    final_conn_obj = res_update.get('connection_obj')
    #    if final_conn_obj and final_conn_obj.is_alive():
    #        final_conn_obj.disconnect()
    #    # If original conn is different and still alive (shouldn't be if switchover happened), handle it
    #    elif conn and conn != final_conn_obj and conn.is_alive():
    #         conn.disconnect()
    #
    # elif res_avant.get('connection_obj') and res_avant['connection_obj'].is_alive(): # if avant failed but conn exists
    #        res_avant['connection_obj'].disconnect()
    print("\n--- Fin des tests locaux (si activés) ---")