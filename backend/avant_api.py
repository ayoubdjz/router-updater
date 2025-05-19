import os
import sys
import json
import time
import warnings
from pathlib import Path
# from getpass import getpass # No longer needed here
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import ipaddress
import tempfile
import portalocker
import subprocess # Kept for lancer_apres, though ideally APRES is also an API call
from pathlib import Path

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCK_DIR = os.path.join(SCRIPT_DIR, "router_locks")
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
Path(LOCK_DIR).mkdir(exist_ok=True, parents=True)
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

# --- Helper Functions (modified or kept as is) ---
def verrouiller_routeur(ip, log_messages):
    warnings.filterwarnings("ignore", category=UserWarning, module="portalocker.utils")
    Path(LOCK_DIR).mkdir(exist_ok=True, parents=True)
    ip_normalisee = ip.replace('.', '_')
    lock_file_path = os.path.join(LOCK_DIR, f"{ip_normalisee}.lock")

    if os.path.exists(lock_file_path):
        try:
            test_lock = portalocker.Lock(lock_file_path, flags=portalocker.LOCK_EX | portalocker.LOCK_NB)
            test_lock.acquire()
            test_lock.release()
        except (portalocker.LockException, BlockingIOError):
            msg = f"Le routeur {ip} est déjà verrouillé par un autre processus."
            log_messages.append(msg)
            return None, None
        except Exception as e:
            msg = f"Erreur lors du test du verrou : {e}"
            log_messages.append(msg)
            return None, None
    try:
        lock = portalocker.Lock(lock_file_path, flags=portalocker.LOCK_EX)
        lock.acquire(timeout=5)
        log_messages.append(f"Routeur {ip} verrouillé avec {lock_file_path}")
        return lock, lock_file_path
    except portalocker.LockException:
        msg = f"Impossible de verrouiller le routeur {ip} (verrou occupé)."
        log_messages.append(msg)
        return None, None
    except Exception as e:
        msg = f"Erreur lors du verrouillage : {e}"
        log_messages.append(msg)
        if os.path.exists(lock_file_path):
            try:
                os.remove(lock_file_path)
            except Exception as e_rem:
                log_messages.append(f"Erreur nettoyage fichier verrou orphelin: {e_rem}")
        return None, None

def liberer_verrou(lock, lock_file_path, log_messages):
    if lock:
        try:
            lock.release()
            log_messages.append(f"Verrou {lock_file_path} libéré.")
        except Exception as e:
            log_messages.append(f"Erreur lors de la libération du verrou : {e}")
    if lock_file_path and os.path.exists(lock_file_path):
        try:
            os.remove(lock_file_path)
            log_messages.append(f"Fichier de verrou {lock_file_path} supprimé.")
        except Exception as e:
            log_messages.append(f"Erreur lors de la suppression du fichier de verrou : {e}")


def verifier_connexion(connection, log_messages):
    try:
        output = connection.send_command("show system uptime", read_timeout=10)
        if "error" in output.lower():
            log_messages.append(f"ERREUR: Problème de communication détecté: {output}")
            return False
        return True
    except Exception as e:
        log_messages.append(f"ERREUR: Problème de connexion: {str(e)}")
        return False

def nettoyer_fichiers_api(fichiers_a_supprimer, log_messages):
    for fichier in fichiers_a_supprimer:
        try:
            if os.path.exists(fichier):
                os.remove(fichier)
                log_messages.append(f"Fichier supprimé : {fichier}")
        except Exception as e:
            log_messages.append(f"Erreur lors de la suppression du fichier {fichier}: {e}")

def valider_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# This function remains if you want AVANT to directly trigger APRES via subprocess
# But it's better if the API orchestrates this as two separate calls.
# For now, let's assume the API will call APRES separately.
# def lancer_apres(fichier_identifiants, log_messages, max_tentatives=3):
#     tentatives = 0
#     python_exec = sys.executable
#     script_apres = os.path.join(os.path.dirname(__file__), "APRES_API.py") # Adjusted name
#     while tentatives < max_tentatives:
#         try:
#             log_messages.append(f"Lancement de APRES_API.py avec {fichier_identifiants}")
#             # This needs to be rethought for API context.
#             # subprocess.run won't work well if APRES_API.py expects to be an importable module.
#             # For now, this illustrates the original intent.
#             # A better way: API calls avant, gets ident_file, then API calls apres with ident_file.
#             result = subprocess.run(
#                 [python_exec, script_apres, fichier_identifiants], # APRES_API.py needs to handle CLI args
#                 check=True, capture_output=True, text=True
#             )
#             log_messages.append(f"APRES_API.py stdout: {result.stdout}")
#             if result.stderr:
#                  log_messages.append(f"APRES_API.py stderr: {result.stderr}")
#             return True
#         except subprocess.CalledProcessError as e:
#             tentatives += 1
#             log_messages.append(f"Erreur APRES_API.py (Code {e.returncode}): {e.stderr.strip() if e.stderr else e.stdout.strip()}")
#             if tentatives < max_tentatives:
#                 log_messages.append("Nouvelle tentative pour APRES_API.py...")
#             else:
#                 log_messages.append("Échec APRES_API.py après plusieurs tentatives.")
#                 return False
#         except Exception as e:
#             log_messages.append(f"Erreur inattendue lancement APRES_API.py: {e}")
#             return False


# --- Main Process Function for AVANT ---
def run_avant_checks(ip, username, password, log_messages):
    if not valider_ip(ip):
        log_messages.append("Adresse IP invalide.")
        return {"status": "error", "message": "Adresse IP invalide."}

    fichiers_crees_avant = []
    connection = None
    lock = None
    lock_file_path = None
    avant_file_path = None
    config_file_path = None
    identifiants_file_path = None
    router_hostname = "inconnu" # Default

    try:
        lock, lock_file_path = verrouiller_routeur(ip, log_messages)
        if not lock:
            return {"status": "error", "message": f"Impossible de verrouiller le routeur {ip}." , "lock_file": lock_file_path}

        device = {
            'device_type': 'juniper',
            'host': ip,
            'username': username,
            'password': password,
            'timeout': 30,
            'auth_timeout': 45, # Longer for initial auth
            'banner_timeout': 45, # Longer for banners
        }

        log_messages.append(f"Tentative de connexion à {ip}...")
        connection = ConnectHandler(**device)
        log_messages.append(f"Connecté avec succès au routeur {ip}")

        if not verifier_connexion(connection, log_messages):
            raise Exception("Vérification de la connexion post-établissement échouée.")

        # Create AVANT file
        temp_avant_file = tempfile.NamedTemporaryFile(
            mode='w+', prefix='AVANT_', suffix='.txt', delete=False, encoding='utf-8',
            dir=GENERATED_FILES_DIR
        )
        avant_file_path = temp_avant_file.name
        fichiers_crees_avant.append(avant_file_path)
        temp_avant_file.close() # Close it to reopen in append mode or for os.replace

        with open(avant_file_path, 'a', encoding='utf-8') as file:
            log_messages.append("\nRécupération des informations de base du routeur...")
            file.write("Informations de base du routeur :\n")
            output = connection.send_command('show version')
            junos_version = "inconnu"
            router_model = "inconnu"
            # router_hostname already defaulted
            for line in output.splitlines():
                if line.startswith("Hostname:"):
                    router_hostname = line.split("Hostname:")[1].strip()
                elif line.startswith("Model:"):
                    router_model = line.split("Model:")[1].strip()
                elif line.startswith("Junos:"):
                    junos_version = line.split("Junos:")[1].strip()
            
            log_messages.append(f"Hostname: {router_hostname}, Model: {router_model}, Junos: {junos_version}")
            file.write(f"Le hostname du routeur est : {router_hostname}\n")
            file.write(f"Le modele du routeur est : {router_model}\n")
            file.write(f"La version du systeme Junos est : {junos_version}\n")

        # Renaming logic for AVANT file (if temp_avant_file was used and now we want a permanent name)
        # This part might be complex if temp_avant_file was written to then closed.
        # The current structure keeps avant_file_path as the temp name.
        # Let's ensure the final name is more structured.
        final_avant_base = f"AVANT_{username}_{router_hostname}.txt"
        final_avant_path = os.path.join(GENERATED_FILES_DIR, final_avant_base)
        compteur = 1
        while os.path.exists(final_avant_path):
            final_avant_path = os.path.join(GENERATED_FILES_DIR, f"AVANT_{username}_{router_hostname}_{compteur}.txt")
            compteur += 1
        
        if os.path.exists(avant_file_path): # avant_file_path is the temp file
            os.replace(avant_file_path, final_avant_path)
            fichiers_crees_avant.remove(avant_file_path) # remove temp from list
            avant_file_path = final_avant_path # update to final path
            fichiers_crees_avant.append(avant_file_path) # add final to list
            log_messages.append(f"Fichier AVANT renommé en: {avant_file_path}")
        else:
            log_messages.append(f"Avertissement: Fichier temporaire {avant_file_path} non trouvé pour renommage.")
            # Fallback: If os.replace failed or file disappeared, avant_file_path might still point to temp or be invalid.
            # Re-assign to what it should be, even if empty.
            avant_file_path = final_avant_path


        # Continue writing to the now correctly named avant_file_path
        with open(avant_file_path, 'a', encoding='utf-8') as file:
            commands_to_run = {
                "Informations du moteur de routage :": "show chassis routing-engine",
                "Informations sur les interfaces :": [
                    "show interfaces terse | no-more",
                    "show interfaces detail | no-more" # Special parsing needed for this one still
                ],
                "Informations ARP :": "show arp",
                "Informations sur les routes :": "show route summary",
                "Protocole OSPF :": "show ospf interface brief",
                "Protocole IS-IS :": "show isis adjacency",
                "Protocole MPLS :": "show mpls interface",
                "Protocole LDP :": "show ldp session",
                "Protocole RSVP :": "show rsvp interface",
                "Protocole LLDP :": "show lldp neighbor",
                "Protocole LSP :": "show mpls lsp",
                "Protocole BGP :": "show bgp summary",
                "Services configurés :": "show configuration system services", # Special parsing
                "Protocoles configurés :": "show configuration protocols", # Special parsing
                "Listes de Contrôle d'Accès (ACL) :": "show configuration firewall",
                "Logs des erreurs critiques dans 'messages' :": 'show log messages | match "error|warning|critical" | last 10',
                "Logs des erreurs critiques dans 'chassisd' :": 'show log chassisd | match "error|warning|critical" | last 10',
            }

            for title, cmd_or_cmds in commands_to_run.items():
                if not verifier_connexion(connection, log_messages):
                    raise Exception("Connexion perdue avec le routeur pendant la collecte AVANT.")
                
                log_messages.append(f"\nRécupération: {title}")
                file.write(f"\n{title}\n")
                
                if title == "Informations sur les interfaces :":
                    output_terse = connection.send_command(cmd_or_cmds[0])
                    output_detail = connection.send_command(cmd_or_cmds[1])
                    # Simplified parsing for brevity, original logic was more detailed
                    interfaces_up, interfaces_down, interfaces_info, interfaces_ip, interfaces_mac = \
                        parse_interfaces(output_terse, output_detail, log_messages)
                    
                    file.write("Les Interfaces up :\n")
                    if interfaces_up:
                        for intf_data in interfaces_up: file.write(intf_data + "\n")
                    else: file.write("Aucune interface active trouvee.\n")
                    
                    file.write("Les Interfaces down :\n")
                    if interfaces_down:
                        for intf_data in interfaces_down: file.write(intf_data + "\n")
                    else: file.write("Aucune interface inactive trouvee.\n")
                    log_messages.append("Interfaces traitées.")
                    continue # Skip generic command handling for this special case

                elif title == "Services configurés :":
                    output_services = connection.send_command(cmd_or_cmds)
                    services = set()
                    for line in output_services.splitlines():
                        if line.strip().endswith(";"):
                            services.add(line.strip().rstrip(";"))
                    for service in sorted(services):
                        file.write(service + "\n")
                    log_messages.append(f"Services: {', '.join(sorted(services)) if services else 'Aucun'}")
                    continue

                elif title == "Protocoles configurés :":
                    output_protocols = connection.send_command(cmd_or_cmds)
                    protocols = set()
                    for line in output_protocols.splitlines():
                        if "{" in line and not line.strip().startswith("}"):
                            protocols.add(line.split("{")[0].strip())
                    for protocol in sorted(protocols):
                        file.write(protocol + "\n")
                    log_messages.append(f"Protocoles: {', '.join(sorted(protocols)) if protocols else 'Aucun'}")
                    continue
                
                # Generic command handling
                output = connection.send_command(cmd_or_cmds)
                # Filter ---more--- lines for logs
                filtered_output_lines = [line for line in output.splitlines() if not line.strip().startswith("---(more")]
                filtered_output = "\n".join(filtered_output_lines)
                
                file.write(filtered_output + "\n")
                log_messages.append(f"OK: {title}")
                # print(output) # No direct print to console from here

            # Configuration totale
            if not verifier_connexion(connection, log_messages):
                raise Exception("Connexion perdue avant la sauvegarde de la configuration.")
            log_messages.append("\nRécupération de la configuration totale...")
            file.write("\nLa configuration totale :\n")
            output_config = connection.send_command("show configuration | display set")
            file.write(output_config + "\n")
            log_messages.append("Configuration totale récupérée.")

            # Create separate config file
            base_config_filename = f"CONFIGURATION_{username}_{router_hostname}.txt"
            config_file_path = os.path.join(GENERATED_FILES_DIR, base_config_filename)
            compteur_config = 1
            while os.path.exists(config_file_path):
                config_file_path = os.path.join(GENERATED_FILES_DIR, f"CONFIGURATION_{username}_{router_hostname}_{compteur_config}.txt")
                compteur_config += 1
            with open(config_file_path, 'w', encoding='utf-8') as cf_file:
                cf_file.write(output_config)
            fichiers_crees_avant.append(config_file_path)
            log_messages.append(f"Configuration sauvegardée dans: {config_file_path}")

        # Save identifiers
        ident_base_name = f"identifiants_{username}_{router_hostname}.json"
        identifiants_file_path = os.path.join(GENERATED_FILES_DIR, ident_base_name)
        compteur_ident = 1
        while os.path.exists(identifiants_file_path):
            identifiants_file_path = os.path.join(GENERATED_FILES_DIR, f"identifiants_{username}_{router_hostname}_{compteur_ident}.json")
            compteur_ident += 1

        ident_data = {
            "ip": ip,
            "username": username,
            # "password": password, # DO NOT STORE PASSWORD IN THE FILE
            "router_hostname": router_hostname,
            "lock_file_path": lock_file_path, # Corrected to actual path
            "avant_file_path": avant_file_path,
            "config_file_path": config_file_path
        }
        with open(identifiants_file_path, "w") as f_ident:
            json.dump(ident_data, f_ident, indent=2)
        fichiers_crees_avant.append(identifiants_file_path)
        log_messages.append(f"Données d'identification sauvegardées dans: {identifiants_file_path}")

        return {
            "status": "success",
            "message": "Vérifications AVANT terminées.",
            "ident_data": ident_data, # Return the data directly
            "ident_file_path": identifiants_file_path, # And the path
            "avant_file_path": avant_file_path,
            "config_file_path": config_file_path,
            "lock_file_path": lock_file_path, # Important for API to manage unlock
            "log_messages": log_messages
        }

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        error_msg = f"Erreur de connexion Netmiko: {str(e)}"
        log_messages.append(error_msg)
        # Ensure lock_file_path is set if lock was acquired before error
        current_lock_file_path = lock_file_path if lock_file_path else (os.path.join(LOCK_DIR, f"{ip.replace('.', '_')}.lock") if ip else None)
        return {"status": "error", "message": error_msg, "lock_file_path": current_lock_file_path, "fichiers_crees": fichiers_crees_avant, "log_messages": log_messages}
    except Exception as e:
        error_msg = f"Erreur inattendue dans run_avant_checks: {str(e)}"
        log_messages.append(error_msg)
        # Ensure lock_file_path is set
        current_lock_file_path = lock_file_path if lock_file_path else (os.path.join(LOCK_DIR, f"{ip.replace('.', '_')}.lock") if ip else None)
        return {"status": "error", "message": error_msg, "lock_file_path": current_lock_file_path, "fichiers_crees": fichiers_crees_avant, "log_messages": log_messages}
    # `finally` block for releasing lock and disconnecting should be handled by the caller (API endpoint)
    # because the connection and lock might be needed for subsequent "update" step.


def parse_interfaces(output_terse, output_detail, log_messages):
    """Helper to parse interface details. Simplified from original."""
    interfaces_up_data = []
    interfaces_down_data = []
    interfaces_info = {} # speed
    interfaces_ip_map = {} # ip
    interfaces_mac_map = {} # mac

    # Process terse output for status and basic IP
    for line in output_terse.splitlines():
        columns = line.split()
        if len(columns) >= 2:
            interface_name = columns[0]
            status = columns[1]
            current_list = None
            if "up" in status.lower(): current_list = interfaces_up_data
            elif "down" in status.lower(): current_list = interfaces_down_data
            
            if current_list is not None:
                 # Store basic name for now, will enrich later
                current_list.append(interface_name)

            if "inet" in columns:
                try:
                    ip_index = columns.index("inet") + 1
                    if ip_index < len(columns):
                        interfaces_ip_map[interface_name] = columns[ip_index]
                except ValueError:
                    pass # inet found but no IP next to it, or format error

    # Process detail output for speed and MAC
    physical_interface_sections = output_detail.split("Physical interface:")[1:]
    for section in physical_interface_sections:
        lines = section.split("\n")
        if not lines: continue
        
        interface_name_line = lines[0].strip()
        physical_interface_name = interface_name_line.split(",")[0] # e.g., ge-0/0/0
        
        speed = "Indisponible"
        mac_address = None
        
        for line in lines:
            if "Speed:" in line:
                try:
                    speed = line.split("Speed:")[1].split(",")[0].strip()
                except IndexError:
                    log_messages.append(f"Format de vitesse non reconnu pour {physical_interface_name}: {line}")
            if "Current address:" in line: # For physical MAC
                try:
                    mac_address = line.split("Current address:")[1].strip().split()[0]
                except IndexError:
                    log_messages.append(f"Format d'adresse MAC non reconnu pour {physical_interface_name}: {line}")
        
        interfaces_info[physical_interface_name] = speed
        if mac_address:
            interfaces_mac_map[physical_interface_name] = mac_address

        # Logical interfaces within this physical section
        logical_interface_sections = section.split("Logical interface ")[1:]
        for logical_section in logical_interface_sections:
            logical_lines = logical_section.split("\n")
            if not logical_lines: continue
            
            logical_name_line = logical_lines[0].strip()
            logical_interface_name = logical_name_line.split()[0] # e.g., ge-0/0/0.0

            # Inherit speed from physical, MAC is usually not on logicals unless specifically configured
            interfaces_info[logical_interface_name] = speed 
            # IP for logical interfaces (often primary address)
            for line in logical_lines:
                if "Local:" in line and "Destination:" in line: # Protocol inet section
                    try:
                        logical_ip = line.split("Local:")[1].split(",")[0].strip()
                        interfaces_ip_map[logical_interface_name] = logical_ip
                    except IndexError:
                        log_messages.append(f"Format IP local non reconnu pour {logical_interface_name}: {line}")

    # Combine data for final output
    formatted_up_interfaces = []
    for intf_name in interfaces_up_data: # interfaces_up_data currently just has names
        speed = interfaces_info.get(intf_name, "Indisponible")
        ip = interfaces_ip_map.get(intf_name, "Aucune IP")
        mac = interfaces_mac_map.get(intf_name) # MAC might not exist for all (e.g. logical)
        output_line = f"{intf_name} - Vitesse: {speed} - IP: {ip}"
        if mac: output_line += f" - MAC: {mac}"
        formatted_up_interfaces.append(output_line)
        
    formatted_down_interfaces = []
    for intf_name in interfaces_down_data:
        speed = interfaces_info.get(intf_name, "Indisponible")
        ip = interfaces_ip_map.get(intf_name, "Aucune IP")
        mac = interfaces_mac_map.get(intf_name)
        output_line = f"{intf_name} - Vitesse: {speed} - IP: {ip}"
        if mac: output_line += f" - MAC: {mac}"
        formatted_down_interfaces.append(output_line)

    return formatted_up_interfaces, formatted_down_interfaces, interfaces_info, interfaces_ip_map, interfaces_mac_map


# --- MISE A JOUR Function (extracted and parameterized) ---
def run_update_procedure(connection, device_details, image_file, log_messages):
    """
    device_details should be the same dict used for ConnectHandler
    {'host': ip, 'username': username, 'password': password, ...}
    """
    try:
        log_messages.append(f"Début de la procédure de mise à jour avec l'image: {image_file}")

        # Verify package presence
        log_messages.append(f"Vérification de la présence du package {image_file} sur le routeur...")
        # Assuming dual RE setup for these commands
        output_re0 = connection.send_command(f"file list /var/tmp/{image_file}")
        output_re1 = ""
        try: # Check if other RE is accessible, might not be in single RE setups
            output_re1 = connection.send_command(f"request routing-engine login other-routing-engine command \"file list /var/tmp/{image_file}\"")
        except Exception as e_re1_check:
            log_messages.append(f"Avertissement: Impossible de vérifier le fichier sur RE1 (peut-être single RE ou RE1 down): {e_re1_check}")
            # If single RE, output_re0 is enough. If dual RE and RE1 check fails, we might have an issue.
            # For simplicity, we proceed if re0 has it, or if re1 has it (in case of primary/backup role)
        
        re0_has_file = "No such file or directory" not in output_re0 and image_file in output_re0
        re1_has_file = "No such file or directory" not in output_re1 and image_file in output_re1

        if not (re0_has_file or re1_has_file):
            msg = f"Le package {image_file} est introuvable sur RE0 et RE1. Abandon de la mise à jour."
            log_messages.append(msg)
            return {"status": "error", "message": msg}
        log_messages.append(f"Package {image_file} trouvé.")

        # DÉSACTIVATION DES FONCTIONNALITÉS HA
        log_messages.append("Désactivation des fonctionnalités de haute disponibilité...")
        connection.config_mode()
        ha_deactivate_commands = [
            "deactivate chassis redundancy",
            "deactivate routing-options nonstop-routing",
            "deactivate system commit synchronize",
            "set system processes clksyncd-service disable" # Check if this command is valid for your Junos
        ]
        for cmd in ha_deactivate_commands:
            connection.send_command_timing(cmd)
        connection.commit(comment="API: Désactivation HA pour MAJ", and_quit=True) # commit and exit config mode
        # For commit synchronize, it might need expect_string or careful handling
        # output_commit_sync = connection.send_command("commit synchronize", expect_string=r'commit complete|commit confirmed') # This can be tricky
        # log_messages.append(f"Commit sync output: {output_commit_sync}")
        # connection.exit_config_mode() # if not using and_quit
        log_messages.append("Configuration de haute disponibilité désactivée (ou tentative).")

        # Determine current master RE
        re_status_output = connection.send_command("show chassis routing-engine")
        master_re_slot = "0" # Assume RE0 is master initially
        if "Slot 1" in re_status_output and "Master" in re_status_output.split("Slot 1")[1].split("\n")[1]:
            master_re_slot = "1"
        
        log_messages.append(f"RE Master actuel: RE{master_re_slot}")
        
        # Update sequence: Update backup RE first, reboot it, wait, switch mastership, update new backup RE, reboot, wait, switch back.
        # This is a simplified flow. Real NSSU/ISSU is more complex. This looks like a manual dual RE update.

        first_re_to_update = "1" if master_re_slot == "0" else "0"
        second_re_to_update = master_re_slot

        # --- UPDATE RE (Backup First) ---
        log_messages.append(f"\nMise à jour de RE{first_re_to_update} (Backup)...")
        login_cmd = f"request routing-engine login other-routing-engine" # This command logs into the *other* RE
        connection.send_command_timing(login_cmd, strip_prompt=False, strip_command=False) # Enter other RE context
        log_messages.append(f"Connexion à RE{first_re_to_update} établie (via console du Master).")
        
        install_cmd = f"request system software add /var/tmp/{image_file} no-validate"
        log_messages.append(f"Installation du nouveau logiciel sur RE{first_re_to_update}: {install_cmd}")
        # This command can take a VERY long time. delay_factor and max_loops are important.
        install_output = connection.send_command_timing(install_cmd, delay_factor=10, max_loops=300) # 50 minutes timeout
        log_messages.append(f"Sortie d'installation RE{first_re_to_update}: {install_output}")
        if "error" in install_output.lower() or "fail" in install_output.lower():
            # Attempt to return to original RE prompt before raising
            connection.send_command_timing("exit", strip_prompt=False, strip_command=False) # Exit from other-routing-engine shell
            raise Exception(f"Échec de l'installation sur RE{first_re_to_update}: {install_output}")

        log_messages.append(f"Lancement du redémarrage de RE{first_re_to_update}...")
        connection.send_command_timing("request system reboot", strip_prompt=False, strip_command=False)
        # Handle "Reboot the system ? [yes,no] (no)" prompt
        reboot_confirm_output = connection.send_command_timing("yes", strip_prompt=False, strip_command=False)
        log_messages.append(f"Confirmation de redémarrage RE{first_re_to_update}: {reboot_confirm_output}")
        # After 'yes', the console to other RE will drop. We should be back on the master RE's prompt.
        # Send a newline or a simple command to re-establish prompt.
        connection.send_command_timing("\n", strip_prompt=False, strip_command=False) # Ensure we are back on master RE prompt
        connection.send_command_timing("exit", strip_prompt=False, strip_command=False) # Exit from other-routing-engine shell (if still in it)
        
        log_messages.append(f"Attente du redémarrage de RE{first_re_to_update} (jusqu'à 15 mins)...")
        if not wait_for_re_state(connection, first_re_to_update, ["backup", "online"], log_messages, timeout=900): # Online for backup, Present for offline
             raise Exception(f"Timeout: RE{first_re_to_update} n'a pas redémarré correctement ou n'est pas en état 'backup/online'.")
        log_messages.append(f"✓ RE{first_re_to_update} a terminé son redémarrage et est en état attendu.")
        verify_re_version(connection, f"other-routing-engine", image_file, log_messages)


        # --- BASCULEMENT VERS RE fraîchement mis à jour ---
        log_messages.append(f"\nBasculement vers RE{first_re_to_update}...")
        # The 'connection' object is to the current master (second_re_to_update).
        # We are asking IT to make the OTHER one (first_re_to_update) the master.
        switch_output = connection.send_command("request chassis routing-engine master switch", strip_prompt=False, strip_command=False)
        log_messages.append(f"Sortie de la demande de basculement: {switch_output}")
        time.sleep(2) # Give it a moment
        confirm_switch = connection.send_command("yes", strip_prompt=False, strip_command=False) # Send 'yes'
        log_messages.append(f"Confirmation de basculement: {confirm_switch}")
        log_messages.append("Déconnexion en attente du basculement...")
        connection.disconnect()
        connection = None # Mark as disconnected

        log_messages.append("Attente de 5 minutes pour la stabilisation post-basculement...")
        time.sleep(300) # 5 minutes

        log_messages.append(f"Tentative de reconnexion au routeur (devrait être sur RE{first_re_to_update} maintenant)...")
        connection = reconnect_after_switch(device_details, log_messages, expected_master_slot=first_re_to_update)
        if not connection:
            raise Exception(f"Échec de reconnexion ou RE{first_re_to_update} n'est pas devenu Master.")
        log_messages.append(f"✓ Reconnexion réussie. RE{first_re_to_update} est maintenant Master.")


        # --- MISE À JOUR DE L'ANCIEN MASTER (maintenant RE Backup: second_re_to_update) ---
        log_messages.append(f"\nMise à jour de RE{second_re_to_update} (maintenant Backup)...")
        login_cmd_2 = f"request routing-engine login other-routing-engine"
        connection.send_command_timing(login_cmd_2, strip_prompt=False, strip_command=False)
        log_messages.append(f"Connexion à RE{second_re_to_update} établie (via console du nouveau Master RE{first_re_to_update}).")

        install_cmd_2 = f"request system software add /var/tmp/{image_file} no-validate"
        log_messages.append(f"Installation du nouveau logiciel sur RE{second_re_to_update}: {install_cmd_2}")
        install_output_2 = connection.send_command_timing(install_cmd_2, delay_factor=10, max_loops=300)
        log_messages.append(f"Sortie d'installation RE{second_re_to_update}: {install_output_2}")
        if "error" in install_output_2.lower() or "fail" in install_output_2.lower():
            connection.send_command_timing("exit", strip_prompt=False, strip_command=False)
            raise Exception(f"Échec de l'installation sur RE{second_re_to_update}: {install_output_2}")

        log_messages.append(f"Lancement du redémarrage de RE{second_re_to_update}...")
        connection.send_command_timing("request system reboot", strip_prompt=False, strip_command=False)
        reboot_confirm_output_2 = connection.send_command_timing("yes", strip_prompt=False, strip_command=False)
        log_messages.append(f"Confirmation de redémarrage RE{second_re_to_update}: {reboot_confirm_output_2}")
        connection.send_command_timing("\n", strip_prompt=False, strip_command=False)
        connection.send_command_timing("exit", strip_prompt=False, strip_command=False)

        log_messages.append(f"Attente du redémarrage de RE{second_re_to_update} (jusqu'à 15 mins)...")
        if not wait_for_re_state(connection, second_re_to_update, ["backup", "online"], log_messages, timeout=900):
             raise Exception(f"Timeout: RE{second_re_to_update} n'a pas redémarré correctement ou n'est pas en état 'backup/online'.")
        log_messages.append(f"✓ RE{second_re_to_update} a terminé son redémarrage et est en état attendu.")
        verify_re_version(connection, f"other-routing-engine", image_file, log_messages)


        # --- RÉACTIVATION HA ---
        log_messages.append("\nRéactivation des fonctionnalités de haute disponibilité...")
        # Current connection is to RE{first_re_to_update} which is Master
        connection.config_mode()
        ha_activate_commands = [
            "activate chassis redundancy", # Ensure these are correct for your setup
            "activate routing-options nonstop-routing",
            "activate system commit synchronize",
            # "delete system processes clksyncd-service disable" # If you disabled it
        ]
        for cmd in ha_activate_commands:
            connection.send_command_timing(cmd)
        connection.commit(comment="API: Réactivation HA post-MAJ", and_quit=True)
        log_messages.append("✓ Configuration HA réactivée (ou tentative).")

        # --- BASCULEMENT FINAL VERS RE0 (si RE0 était le master original) ---
        original_master_slot = "0" # Or "1" depending on your standard config
        current_master_slot = first_re_to_update # This RE is currently master

        if current_master_slot != original_master_slot:
            log_messages.append(f"\nBasculement final vers RE{original_master_slot} (master d'origine)...")
            switch_output_final = connection.send_command("request chassis routing-engine master switch", strip_prompt=False, strip_command=False)
            log_messages.append(f"Sortie de la demande de basculement final: {switch_output_final}")
            time.sleep(2)
            confirm_switch_final = connection.send_command("yes", strip_prompt=False, strip_command=False)
            log_messages.append(f"Confirmation de basculement final: {confirm_switch_final}")
            connection.disconnect()
            connection = None

            log_messages.append("Attente de 5 minutes pour la stabilisation post-basculement final...")
            time.sleep(300)

            log_messages.append(f"Tentative de reconnexion au routeur (devrait être sur RE{original_master_slot})...")
            connection = reconnect_after_switch(device_details, log_messages, expected_master_slot=original_master_slot)
            if not connection:
                raise Exception(f"Échec de reconnexion ou RE{original_master_slot} n'est pas devenu Master.")
            log_messages.append(f"✓ Reconnexion réussie. RE{original_master_slot} est maintenant Master.")
        else:
            log_messages.append(f"RE{original_master_slot} est déjà Master. Aucun basculement final nécessaire.")

        log_messages.append("✓ Procédure de mise à jour terminée avec succès")
        return {"status": "success", "message": "Mise à jour terminée.", "connection": connection} # Return connection for APRES

    except Exception as e:
        error_msg = f"Erreur majeure pendant la mise à jour: {str(e)}"
        log_messages.append(error_msg)
        # Try to ensure connection is returned if it exists, for cleanup by API
        return {"status": "error", "message": error_msg, "connection": connection if 'connection' in locals() else None}


def wait_for_re_state(conn, re_slot_to_check, target_states, log_messages, timeout=900):
    """Waits for a specific RE to reach one of the target states."""
    log_messages.append(f"Attente de RE{re_slot_to_check} pour atteindre l'état(s): {', '.join(target_states)}...")
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        try:
            re_output = conn.send_command("show chassis routing-engine")
            # Find the section for the RE slot
            re_section = None
            if f"Slot {re_slot_to_check}" in re_output:
                # Split by "Slot X" and take the part after our target slot's header
                # Then take lines until the next "Slot Y" or end of output
                parts = re_output.split(f"Slot {re_slot_to_check}")
                if len(parts) > 1:
                    current_re_details = parts[1].split("\n")
                    # Find "Current state" within these lines
                    for line in current_re_details:
                        if "Current state" in line:
                            current_state = line.split("Current state")[-1].strip()
                            log_messages.append(f"RE{re_slot_to_check} état actuel: {current_state} (cible: {', '.join(target_states)})")
                            if any(ts.lower() in current_state.lower() for ts in target_states):
                                return True
                            break # Found current state for this RE slot
            time.sleep(30)  # Check every 30 seconds
        except Exception as e:
            log_messages.append(f"Erreur pendant l'attente de l'état RE: {e}. Réessai...")
            time.sleep(30)
    log_messages.append(f"Timeout: RE{re_slot_to_check} n'a pas atteint {', '.join(target_states)} dans les {timeout}s.")
    return False

def verify_re_version(conn, re_target_specifier, image_file, log_messages):
    """
    Verifies Junos version on a specific RE.
    re_target_specifier can be 'local' (for current RE) or 'other-routing-engine'.
    """
    log_messages.append(f"\nVérification de la version sur RE spécifié par '{re_target_specifier}'...")
    cmd = f"show version"
    if re_target_specifier == "other-routing-engine":
        cmd += " invoke-on other-routing-engine"
    cmd += " | match Junos:"
    
    version_output = conn.send_command(cmd)
    if not version_output or "Junos:" not in version_output:
        raise Exception(f"Impossible de récupérer la version pour '{re_target_specifier}'. Output: {version_output}")

    current_version = version_output.split("Junos:")[1].strip().split()[0] # Get first part of version string

    # Extract expected version from image_file: jinstall-ppc-VERSION-signed.tgz
    # Or more generally: <platform>-<version>-<type>.tgz (e.g. junos-evo-install-ptx-x86-64-23.2R1.13-EVO.tgz)
    # This parsing is highly dependent on your image naming convention
    try:
        # Attempt original parsing
        if "jinstall-ppc-" in image_file and "-signed.tgz" in image_file:
             expected_version_parts = image_file.split("jinstall-ppc-")[1].split("-signed.tgz")[0]
        else: # More generic attempt, might need adjustment
            parts = image_file.replace(".tgz", "").split('-')
            # Find a part that looks like a version number (e.g., 21.4R3.14 or 23.2R1-S2.1 or 23.2R1.13)
            version_candidates = [p for p in parts if p[0].isdigit() and ('.' in p or 'R' in p.upper())]
            if not version_candidates:
                raise ValueError("Cannot determine expected version from image filename.")
            expected_version_parts = version_candidates[0] # Take the first likely candidate

        log_messages.append(f"Version actuelle sur '{re_target_specifier}': {current_version}")
        log_messages.append(f"Version attendue (déduite de {image_file}): {expected_version_parts}")

        # Junos version string from 'show version' can be like "21.4R3-S2.1" or "21.4R3.14"
        # The image might be "jinstall-ppc-21.4R3-S2.1-signed.tgz" or "jinstall-ppc-21.4R3.14-signed.tgz"
        # We need a somewhat flexible match.
        if expected_version_parts in current_version:
            log_messages.append(f"✓ La version sur '{re_target_specifier}' ({current_version}) correspond à la version attendue ({expected_version_parts})")
        else:
            raise Exception(f"ERREUR: La version sur '{re_target_specifier}' ({current_version}) ne correspond PAS à la version attendue ({expected_version_parts})")
    except Exception as e:
        log_messages.append(f"Erreur lors de l'extraction/comparaison de version: {e}")
        raise


def reconnect_after_switch(device_details, log_messages, expected_master_slot, max_attempts=5, delay=60):
    """Attempts to reconnect after a mastership switch and verifies the new master."""
    for attempt in range(1, max_attempts + 1):
        log_messages.append(f"Tentative de reconnexion {attempt}/{max_attempts} après basculement...")
        try:
            time.sleep(delay if attempt > 1 else 5) # shorter delay for first attempt
            conn = ConnectHandler(**device_details)
            log_messages.append("Connecté. Vérification du nouveau master...")
            
            re_status = conn.send_command("show chassis routing-engine")
            # Parse re_status to find current master
            # Example: "Slot 0:", then few lines later "Current state Master"
            lines = re_status.split('\n')
            found_slot_header = False
            current_master_verified = False
            for i, line in enumerate(lines):
                if f"Slot {expected_master_slot}" in line:
                    found_slot_header = True
                if found_slot_header and "Current state" in line and "Master" in line:
                    log_messages.append(f"✓ RE{expected_master_slot} est confirmé Master.")
                    current_master_verified = True
                    break # Found and confirmed
                if found_slot_header and "Slot " in line and f"Slot {expected_master_slot}" not in line:
                    # We've passed the section for the expected master without confirming
                    break
            
            if current_master_verified:
                return conn
            else:
                log_messages.append(f"RE{expected_master_slot} n'est pas Master ou état non trouvé. Statut:\n{re_status}")
                conn.disconnect() # Disconnect if not the right state
                if attempt == max_attempts: break # Exit loop if last attempt
                log_messages.append(f"Nouvel essai dans {delay}s...")

        except Exception as e:
            log_messages.append(f"Tentative {attempt}/{max_attempts} échouée: {str(e)}")
            if attempt == max_attempts: break # Exit loop if last attempt
            log_messages.append(f"Nouvel essai dans {delay}s...")
    return None


if __name__ == '__main__':
    # Example of how to call (for testing, not for API direct use)
    test_logs = []
    # Replace with your test VM credentials
    # test_ip = "YOUR_ROUTER_IP"
    # test_user = "YOUR_USERNAME"
    # test_password = "YOUR_PASSWORD"
    # test_image = "jinstall-ppc-YOUR_JUNOS_VERSION-signed.tgz" # Or your actual image name

    # print("--- Test run_avant_checks ---")
    # avant_result = run_avant_checks(test_ip, test_user, test_password, test_logs)
    # print(json.dumps(avant_result, indent=2))
    # print("\nLogs from avant_checks:")
    # for log_entry in test_logs:
    #     print(log_entry)

    # if avant_result.get("status") == "success":
    #     # Simulate API keeping connection open or re-establishing
    #     lock_to_release = None
    #     if avant_result.get("lock_file_path"):
    #         # For testing, we'd need to re-acquire the lock object if it wasn't returned
    #         # In API, the lock object might be stored in a session or the connection kept.
    #         # Here, we can't easily get the 'lock' object back if run_avant_checks returned it.
    #         # The API must handle this. For now, just use path.
    #         pass

    #     # Test update - CAUTION: THIS WILL MODIFY YOUR ROUTER IF IT CONNECTS
    #     # print("\n--- Test run_update_procedure (Commented out for safety) ---")
    #     # test_device_details = {
    #     #     'device_type': 'juniper', 'host': test_ip,
    #     #     'username': test_user, 'password': test_password, 'timeout': 30
    #     # }
    #     # test_conn_for_update = None
    #     # try:
    #     #     print(f"Connecting for update test with {test_ip}")
    #     #     test_conn_for_update = ConnectHandler(**test_device_details)
    #     #     update_logs = []
    #     #     update_result = run_update_procedure(test_conn_for_update, test_device_details, test_image, update_logs)
    #     #     print(json.dumps(update_result, indent=2))
    #     #     print("\nLogs from update_procedure:")
    #     #     for log_entry in update_logs:
    #     #         print(log_entry)
    #     #     if update_result.get("connection"): # If update returns a connection
    #     #         test_conn_for_update = update_result["connection"]
    #     # except Exception as e:
    #     #     print(f"Error during update test setup or execution: {e}")
    #     # finally:
    #     #     if test_conn_for_update and test_conn_for_update.is_alive():
    #     #         test_conn_for_update.disconnect()
    #     #         print("Update test connection closed.")

    #     # Clean up lock from avant_result if it was created
    #     if avant_result.get("lock_file_path") and os.path.exists(avant_result["lock_file_path"]):
    #          # The lock object itself isn't easily passed back from run_avant_checks in this test setup
    #          # So we manually try to release by path, which isn't perfect with portalocker
    #          print(f"Test: Manually removing lock file {avant_result['lock_file_path']}")
    #          # os.remove(avant_result["lock_file_path"]) #This would be a forceful removal
    #          # A proper test would need the lock object returned or a global lock manager.
    #          # For the API, the API endpoint holds the lock and releases it.
    #          # For now, just simulate the API would call liberer_verrou
    #          mock_lock_for_test = None # We don't have the real lock object here.
    #          liberer_verrou(mock_lock_for_test, avant_result["lock_file_path"], test_logs)
    #          print("\nFinal Logs after potential lock release:")
    #          for log_entry in test_logs:
    #              print(log_entry)

    print("AVANT_API.py is meant to be imported as a module, not run directly for full flow.")
    print("Use the example `if __name__ == '__main__':` block for targeted function testing.")
    print(f"GENERATED_FILES_DIR: {GENERATED_FILES_DIR}")
    print(f"LOCK_DIR: {LOCK_DIR}")