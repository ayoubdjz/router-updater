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

def verifier_connexion(connection, log_messages):
    try:
        output = connection.send_command("show system uptime", read_timeout=15)
        if "error" in output.lower() or not output.strip():
            log_messages.append(f"ERREUR: Problème de communication détecté (show system uptime): '{output if output else 'No output'}'")
            return False
        log_messages.append(f"Connexion vérifiée (uptime): {output.strip().splitlines()[0] if output.strip() else 'OK'}")
        return True
    except Exception as e:
        log_messages.append(f"ERREUR: Problème de connexion (exception pendant show system uptime): {str(e)}")
        return False

def valider_ip(ip):
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

def parse_interfaces_structured(output_terse, output_detail, log_messages):
    """ Parses interface data and returns structured lists for up/down interfaces. """
    up_interfaces = []
    down_interfaces = []
    # Basic parsing from terse for up/down status
    raw_up_names = []
    raw_down_names = []

    for line in output_terse.splitlines():
        columns = line.split()
        if len(columns) >= 2:
            interface_name = columns[0]
            status = columns[1].lower()
            if "up" == status or ("up" in status and "admin" not in status): # Catch "up" but not "admin down"
                raw_up_names.append(interface_name)
            elif "down" == status:
                raw_down_names.append(interface_name)
    
    # Detailed parsing from 'show interfaces detail'
    physical_interface_sections = output_detail.split("Physical interface:")
    if len(physical_interface_sections) > 1:
        physical_interface_sections = physical_interface_sections[1:] # Skip header before first interface

    all_interface_details = {} # Store details by full interface name (e.g., ge-0/0/0.0)

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
            if "Current address:" in line or "Hardware address:" in line: # Physical MAC
                try:
                    key = "Current address:" if "Current address:" in line else "Hardware address:"
                    phys_mac = line.split(key)[1].strip().split(",")[0].split()[0] # Get MAC, avoid extra info
                except IndexError: pass

        # Store details for physical interface if it's in terse output
        if physical_interface_name in raw_up_names or physical_interface_name in raw_down_names:
            all_interface_details[physical_interface_name] = {
                "name": physical_interface_name, "status": "", # Status will be set later
                "speed": phys_speed, "ip_address": "N/A (Physical)", "mac_address": phys_mac
            }

        logical_interface_sections = section.split("Logical interface ")
        if len(logical_interface_sections) > 1:
            logical_interface_sections = logical_interface_sections[1:] # Skip physical part

        for logical_section in logical_interface_sections:
            logical_lines = logical_section.split("\n")
            if not logical_lines: continue
            
            logical_name_line = logical_lines[0].strip()
            logical_interface_name = logical_name_line.split()[0].strip() # e.g., ge-0/0/0.0
            
            log_ip = "N/A"
            # Logical interfaces inherit speed from physical. MAC is usually not distinct on logicals for data plane.
            
            for log_line in logical_lines:
                if "Local:" in log_line and "inet" in logical_section.lower(): # Look for IPv4 Address
                    try: log_ip = log_line.split("Local:")[1].split(",")[0].strip()
                    except IndexError: pass
            
            if logical_interface_name in raw_up_names or logical_interface_name in raw_down_names:
                 all_interface_details[logical_interface_name] = {
                    "name": logical_interface_name, "status": "", # Status will be set later
                    "speed": phys_speed, "ip_address": log_ip, "mac_address": phys_mac # Use physical MAC for logical
                }

    # Populate up_interfaces and down_interfaces lists
    for name in raw_up_names:
        details = all_interface_details.get(name, {"name": name, "status": "up", "speed": "N/A", "ip_address": "N/A", "mac_address": "N/A"})
        details["status"] = "up"
        up_interfaces.append(details)
        
    for name in raw_down_names:
        details = all_interface_details.get(name, {"name": name, "status": "down", "speed": "N/A", "ip_address": "N/A", "mac_address": "N/A"})
        details["status"] = "down"
        down_interfaces.append(details)
        
    return up_interfaces, down_interfaces

# --- Main Process Function for AVANT ---
def run_avant_checks(ip, username, password, log_messages):
    # ... (Initial validation, locking, connection - same as last full version) ...
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
    
    # This dictionary will hold structured data for the frontend
    structured_output_data = {
        "basic_info": {},
        "routing_engine": "",
        "interfaces_up": [],
        "interfaces_down": [],
        "arp_table": "",
        "route_summary": "",
        "ospf_info": "",
        "isis_info": "",
        "mpls_info": "",
        "ldp_info": "",
        "rsvp_info": "",
        "lldp_info": "",
        "lsp_info": "",
        "bgp_summary": "",
        "system_services": [],
        "configured_protocols": [],
        "firewall_config": "",
        "critical_logs_messages": "",
        "critical_logs_chassisd": "",
        "full_config_set": "" # Can be very large, consider if needed directly or just file path
    }

    try:
        log_messages.append(f"--- Début run_avant_checks pour {ip} ---")
        lock_acquired, attempted_lock_path = verrouiller_routeur(ip, log_messages)
        lock_file_path = attempted_lock_path
        if not lock_acquired:
            return {"status": "error", "message": f"Impossible de verrouiller le routeur {ip}. Voir logs.", 
                    "lock_file_path": lock_file_path, "logs": log_messages, "structured_data": structured_output_data}

        device = {'device_type': 'juniper', 'host': ip, 'username': username, 'password': password,
                  'timeout': 30, 'auth_timeout': 45, 'banner_timeout': 45}
        log_messages.append(f"Tentative de connexion à {ip}...")
        connection = ConnectHandler(**device)
        log_messages.append(f"Connecté avec succès au routeur {ip}")
        if not verifier_connexion(connection, log_messages):
            raise Exception("Vérification de la connexion post-établissement échouée.")

        # Create and open temp file for AVANT log
        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True) # Ensure dir exists
        if not os.access(GENERATED_FILES_DIR, os.W_OK):
            raise PermissionError(f"CRITICAL: No write access to GENERATED_FILES_DIR ({GENERATED_FILES_DIR})!")
        
        temp_avant_file_obj = tempfile.NamedTemporaryFile(
            mode='w+', prefix='AVANT_', suffix='.txt', delete=False, encoding='utf-8', dir=GENERATED_FILES_DIR)
        avant_file_path_internal = temp_avant_file_obj.name
        log_messages.append(f"Fichier AVANT temporaire ouvert: {avant_file_path_internal}")
        fichiers_crees_avant.append(avant_file_path_internal) # Add even before closing

        # Section: Basic Info
        structured_output_data["basic_info"]["section_title"] = "Informations de base du routeur"
        temp_avant_file_obj.write(f"{structured_output_data['basic_info']['section_title']}:\n")
        output_version = connection.send_command('show version')
        junos_version, router_model = "inconnu", "inconnu"
        for line in output_version.splitlines():
            if line.startswith("Hostname:"): router_hostname = line.split("Hostname:")[1].strip()
            elif line.startswith("Model:"): router_model = line.split("Model:")[1].strip()
            elif line.startswith("Junos:"): junos_version = line.split("Junos:")[1].strip()
        structured_output_data["basic_info"]["hostname"] = router_hostname
        structured_output_data["basic_info"]["model"] = router_model
        structured_output_data["basic_info"]["junos_version"] = junos_version
        temp_avant_file_obj.write(f"  Hostname: {router_hostname}\n  Modèle: {router_model}\n  Version Junos: {junos_version}\n")
        log_messages.append(f"Basic Info: Host={router_hostname}, Model={router_model}, Junos={junos_version}")

        # --- Rename temp file to final name ---
        temp_avant_file_obj.flush()
        temp_avant_file_obj.close() # Close before rename
        if not os.path.exists(avant_file_path_internal): # Should exist
            raise FileNotFoundError(f"Disparition critique du fichier temporaire AVANT: {avant_file_path_internal}")

        final_avant_base = f"AVANT_{username}_{router_hostname}.txt"
        final_avant_path = os.path.join(GENERATED_FILES_DIR, final_avant_base)
        compteur = 1
        while os.path.exists(final_avant_path):
            final_avant_path = os.path.join(GENERATED_FILES_DIR, f"AVANT_{username}_{router_hostname}_{compteur}.txt")
            compteur += 1
        try:
            os.replace(avant_file_path_internal, final_avant_path)
            log_messages.append(f"Fichier AVANT renommé en: {final_avant_path}")
            if avant_file_path_internal in fichiers_crees_avant: fichiers_crees_avant.remove(avant_file_path_internal)
            avant_file_path_internal = final_avant_path
            if avant_file_path_internal not in fichiers_crees_avant: fichiers_crees_avant.append(avant_file_path_internal)
        except OSError as e_replace:
            log_messages.append(f"ERREUR renommage AVANT: {e_replace}. Utilisation du nom temporaire: {avant_file_path_internal}")
        
        # --- Collect other data, write to file AND structure ---
        with open(avant_file_path_internal, 'a', encoding='utf-8') as file: # Reopen (now possibly renamed) in append mode
            
            def fetch_and_store(key, title, cmd, is_raw=True, special_parser=None):
                if not verifier_connexion(connection, log_messages):
                    raise Exception(f"Connexion perdue avant: {title}")
                log_messages.append(f"Récupération AVANT: {title}")
                file.write(f"\n{title}:\n")
                output = connection.send_command(cmd, read_timeout=60) # Longer timeout for some commands
                
                if special_parser:
                    parsed_data = special_parser(output)
                    structured_output_data[key] = parsed_data
                    # Write a summary or key parts of parsed_data to file if needed, or just raw
                    if isinstance(parsed_data, list) and parsed_data and isinstance(parsed_data[0], dict):
                         for item_dict in parsed_data: # e.g. list of interface dicts
                            for k,v in item_dict.items(): file.write(f"  {k}: {v}\n")
                            file.write("\n")
                    elif isinstance(parsed_data, list): # list of strings
                        for item_str in parsed_data: file.write(f"  {item_str}\n")
                    else: # assume string
                         file.write(str(parsed_data) + "\n")

                elif is_raw:
                    structured_output_data[key] = output
                    file.write(output + "\n")
                else: # Process simple list type outputs
                    lines = [l.strip() for l in output.splitlines() if l.strip() and not l.strip().startswith("---(more")]
                    structured_output_data[key] = lines
                    for line_item in lines: file.write(f"  {line_item}\n")
                log_messages.append(f"OK AVANT: {title}")

            fetch_and_store("routing_engine", "Informations du moteur de routage", "show chassis routing-engine")

            # Interfaces (uses special parser)
            if not verifier_connexion(connection, log_messages): raise Exception("Connexion perdue avant interfaces")
            log_messages.append("Récupération AVANT: Informations sur les interfaces")
            file.write("\nInformations sur les interfaces:\n")
            cmd_terse = "show interfaces terse | no-more"
            cmd_detail = "show interfaces detail | no-more"
            out_terse = connection.send_command(cmd_terse, read_timeout=60)
            out_detail = connection.send_command(cmd_detail, read_timeout=120) # Detail can be very long
            up_list, down_list = parse_interfaces_structured(out_terse, out_detail, log_messages)
            structured_output_data["interfaces_up"] = up_list
            structured_output_data["interfaces_down"] = down_list
            file.write("Interfaces UP:\n")
            if up_list:
                for iface in up_list: file.write(f"  Name: {iface['name']}, Speed: {iface['speed']}, IP: {iface['ip_address']}, MAC: {iface['mac_address']}\n")
            else: file.write("  Aucune interface UP.\n")
            file.write("Interfaces DOWN:\n")
            if down_list:
                for iface in down_list: file.write(f"  Name: {iface['name']}, Speed: {iface['speed']}, IP: {iface['ip_address']}, MAC: {iface['mac_address']}\n")
            else: file.write("  Aucune interface DOWN.\n")
            log_messages.append("OK AVANT: Informations sur les interfaces")

            fetch_and_store("arp_table", "Informations ARP", "show arp")
            fetch_and_store("route_summary", "Informations sur les routes", "show route summary")
            fetch_and_store("ospf_info", "Protocole OSPF", "show ospf interface brief")
            fetch_and_store("isis_info", "Protocole IS-IS", "show isis adjacency")
            fetch_and_store("mpls_info", "Protocole MPLS", "show mpls interface")
            fetch_and_store("ldp_info", "Protocole LDP", "show ldp session")
            fetch_and_store("rsvp_info", "Protocole RSVP", "show rsvp interface")
            fetch_and_store("lldp_info", "Protocole LLDP", "show lldp neighbor")
            fetch_and_store("lsp_info", "Protocole LSP", "show mpls lsp")
            fetch_and_store("bgp_summary", "Protocole BGP", "show bgp summary")
            
            # System Services (parsed list)
            def parse_services(output):
                return sorted(list(set(l.strip().rstrip(";") for l in output.splitlines() if l.strip().endswith(";"))))
            fetch_and_store("system_services", "Services configurés", "show configuration system services", is_raw=False, special_parser=parse_services)

            # Configured Protocols (parsed list)
            def parse_protocols(output):
                return sorted(list(set(l.split("{")[0].strip() for l in output.splitlines() if "{" in l and not l.strip().startswith("}"))))
            fetch_and_store("configured_protocols", "Protocoles configurés", "show configuration protocols", is_raw=False, special_parser=parse_protocols)

            fetch_and_store("firewall_config", "Listes de Contrôle d'Accès (ACL)", "show configuration firewall")
            
            log_msg_cmd = 'show log messages | match "error|warning|critical" | last 10'
            fetch_and_store("critical_logs_messages", "Logs erreurs critiques 'messages'", log_msg_cmd)
            
            chassisd_log_cmd = 'show log chassisd | match "error|warning|critical" | last 10'
            fetch_and_store("critical_logs_chassisd", "Logs erreurs critiques 'chassisd'", chassisd_log_cmd)

            # Full Config (set format) - also to separate file
            if not verifier_connexion(connection, log_messages): raise Exception("Connexion perdue avant config totale AVANT.")
            title_cfg = "La configuration totale (set format)"
            cmd_cfg = "show configuration | display set"
            log_messages.append(f"Récupération AVANT: {title_cfg}")
            file.write(f"\n{title_cfg}:\n")
            output_config_set = connection.send_command(cmd_cfg, read_timeout=180) # Config can be very large
            structured_output_data["full_config_set"] = output_config_set # Store for potential direct display
            file.write(output_config_set + "\n")
            log_messages.append(f"OK AVANT: {title_cfg}")

            # Create separate config file (as before)
            base_config_filename = f"CONFIGURATION_{username}_{router_hostname}.txt"
            config_file_path = os.path.join(GENERATED_FILES_DIR, base_config_filename)
            compteur_cfg = 1
            while os.path.exists(config_file_path):
                config_file_path = os.path.join(GENERATED_FILES_DIR, f"CONFIGURATION_{username}_{router_hostname}_{compteur_cfg}.txt")
                compteur_cfg += 1
            with open(config_file_path, 'w', encoding='utf-8') as cf_file: cf_file.write(output_config_set)
            fichiers_crees_avant.append(config_file_path)
            log_messages.append(f"Config AVANT sauvegardée séparément: {config_file_path}")

        # Identifiers file
        ident_base_name = f"identifiants_{username}_{router_hostname}.json"
        identifiants_file_path = os.path.join(GENERATED_FILES_DIR, ident_base_name)
        compteur_ident = 1
        while os.path.exists(identifiants_file_path): # Avoid overwrite
            identifiants_file_path = os.path.join(GENERATED_FILES_DIR, f"identifiants_{username}_{router_hostname}_{compteur_ident}.json")
            compteur_ident += 1
        ident_data = {
            "ip": ip, "username": username, "router_hostname": router_hostname,
            "lock_file_path": lock_file_path, 
            "avant_file_path": avant_file_path_internal, 
            "config_file_path": config_file_path
        }
        with open(identifiants_file_path, "w") as f_ident: json.dump(ident_data, f_ident, indent=2)
        fichiers_crees_avant.append(identifiants_file_path)
        log_messages.append(f"Données d'identification sauvegardées dans: {identifiants_file_path}")
        log_messages.append(f"--- Fin run_avant_checks pour {ip} ---")

        return {
            "status": "success", "message": "Vérifications AVANT terminées.",
            "ident_data": ident_data, "ident_file_path": identifiants_file_path,
            "avant_file_path": avant_file_path_internal, 
            "config_file_path": config_file_path,
            "lock_file_path": lock_file_path, 
            "connection_obj": connection, # For API endpoint to manage
            "structured_data": structured_output_data, # NEW: structured data for frontend
            "log_messages": log_messages
        }

    except Exception as e_generic: # Catch-all for broader errors during the process
        import traceback
        error_msg = f"Erreur majeure dans run_avant_checks: {str(e_generic)} (Type: {type(e_generic).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        # Attempt to return a consistent error structure
        return {
            "status": "error", "message": error_msg, 
            "lock_file_path": lock_file_path, # Important for cleanup by API
            "fichiers_crees": fichiers_crees_avant, # List of files that might need cleanup
            "structured_data": structured_output_data, # Partial data if any
            "log_messages": log_messages
        }
    # No 'finally' block here to clean lock/connection; API endpoint will manage this.

# --- run_update_procedure remains conceptually the same (long, complex) ---
# It should primarily return logs and status. Structured data isn't typically its main output,
# but it could return new version info if desired.
def run_update_procedure(connection, device_details, image_file, log_messages):
    log_messages.append(f"--- run_update_procedure avec image: {image_file} ---")
    # ... (Full, complex update logic for dual RE Junos as discussed before)
    # This function *must* be robust and handle all states of REs, mastership switches,
    # reconnections (potentially by raising specific exceptions the API layer catches to trigger reconnect logic),
    # and version verifications.
    # For this example, it remains a detailed simulation.
    
    log_messages.append(f"Vérification de la présence du package {image_file} sur le routeur...")
    # Actual check: connection.send_command(f"file list /var/tmp/{image_file}") etc.
    # Simulate package found for now, unless image_file is "simulate_not_found.tgz"
    if image_file == "simulate_not_found.tgz":
        log_messages.append(f"ERREUR: Package {image_file} non trouvé (simulation).")
        return {"status": "error", "message": f"Package {image_file} non trouvé (simulation).", "connection_obj": connection}
    log_messages.append(f"Package {image_file} trouvé (simulation).")

    log_messages.append("Désactivation des fonctionnalités HA (simulation)...")
    # Actual: connection.config_mode(), send "deactivate..." commands, connection.commit()
    time.sleep(1)

    log_messages.append("Mise à jour RE backup (simulation)...")
    # Actual: login other RE, request system software add, reboot other RE, wait, verify
    time.sleep(2) # Simulate install + reboot
    
    # Version Check simulation for RE backup
    expected_version_from_image = image_file.split("jinstall-ppc-")[-1].split("-signed.tgz")[0] if "jinstall-ppc-" in image_file else "unknown_format"
    log_messages.append(f"Vérification version sur RE backup (cible: {expected_version_from_image}) (simulation)...")
    # Actual: connection.send_command("show version invoke-on other-routing-engine | match Junos:")
    current_backup_re_version = expected_version_from_image # Simulate match
    if current_backup_re_version != expected_version_from_image:
        msg = f"ERREUR: Version RE backup ({current_backup_re_version}) ne correspond pas à {expected_version_from_image} (simulation)."
        log_messages.append(msg)
        return {"status": "error", "message": msg, "connection_obj": connection}
    log_messages.append("Version RE backup OK (simulation).")

    log_messages.append("Basculement vers RE mis à jour (simulation)...")
    # Actual: request chassis routing-engine master switch. Connection will drop.
    # The API layer calling this would need to handle the disconnect and reconnect to the new master.
    # For simplicity within this function, we assume 'connection' object is now to the new master.
    time.sleep(1)

    log_messages.append("Mise à jour nouveau RE backup (ancien master) (simulation)...")
    time.sleep(2)

    log_messages.append(f"Vérification version sur nouveau RE backup (cible: {expected_version_from_image}) (simulation)...")
    # Actual: connection.send_command("show version invoke-on other-routing-engine | match Junos:")
    current_new_backup_re_version = expected_version_from_image # Simulate match
    if current_new_backup_re_version != expected_version_from_image:
        msg = f"ERREUR: Version nouveau RE backup ({current_new_backup_re_version}) ne correspond pas à {expected_version_from_image} (simulation)."
        log_messages.append(msg)
        return {"status": "error", "message": msg, "connection_obj": connection}
    log_messages.append("Version nouveau RE backup OK (simulation).")
    
    log_messages.append("Réactivation HA (simulation)...")
    time.sleep(1)

    # Optional: Switch back to original master if needed
    # log_messages.append("Basculement final vers RE0 (si nécessaire) (simulation)...")

    log_messages.append("✓ Procédure de mise à jour (simulée) terminée avec succès.")
    updated_junos_info = {"new_junos_version": expected_version_from_image} # Example structured data from update
    return {"status": "success", "message": "Mise à jour (simulée) terminée.", 
            "connection_obj": connection, "updated_junos_info": updated_junos_info}


if __name__ == '__main__':
    # ... (Main testing block can be updated to print structured_data if desired) ...
    test_logs = []
    print(f"AVANT_API.py: Script chargé.")
    print(f"Répertoire des fichiers générés: {os.path.abspath(GENERATED_FILES_DIR)}")
    print(f"Répertoire des verrous: {os.path.abspath(LOCK_DIR)}")
    
    # Example test
    # test_ip = "YOUR_IP"
    # test_user = "YOUR_USER"
    # test_pass = "YOUR_PASS"
    # if test_ip != "YOUR_IP": # Basic check to prevent accidental run with placeholder
    #     avant_result = run_avant_checks(test_ip, test_user, test_pass, test_logs)
    #     print("\n--- AVANT Result Summary ---")
    #     print(f"Status: {avant_result.get('status')}")
    #     print(f"Message: {avant_result.get('message')}")
    #     if avant_result.get('status') == 'success':
    #         print(f"Hostname: {avant_result.get('structured_data', {}).get('basic_info', {}).get('hostname')}")
    #         print(f"Interfaces UP count: {len(avant_result.get('structured_data', {}).get('interfaces_up', []))}")
    #         # print("\n--- Structured Data (Partial) ---")
    #         # print(json.dumps(avant_result.get('structured_data', {}).get('basic_info'), indent=2))
    #         # print(json.dumps(avant_result.get('structured_data', {}).get('interfaces_up')[:2], indent=2)) # Print first 2 UP interfaces

    #     conn_obj = avant_result.get("connection_obj")
    #     l_file_path = avant_result.get("lock_file_path")

    #     # Simulate API closing connection and releasing lock
    #     if conn_obj and conn_obj.is_alive(): conn_obj.disconnect(); test_logs.append("Test: Connexion fermée.")
    #     if l_file_path: liberer_verrou(l_file_path, test_logs); test_logs.append("Test: Verrou libéré.")
        
    #     print("\n--- Logs ---")
    #     for log in test_logs: print(log)