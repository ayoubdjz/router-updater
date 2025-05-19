import os
import sys
import json
import glob
# from getpass import getpass # No longer needed here
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import ipaddress
import tempfile
import chardet
import unicodedata
from pathlib import Path
from collections import OrderedDict

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files") # Same as AVANT_API
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)


# --- Helper Functions (from original, slightly adapted) ---
def valider_ip_apres(ip): # Renamed to avoid clash if in same namespace
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def verifier_connexion_apres(connection, log_messages): # Renamed
    try:
        output = connection.send_command("show system uptime", read_timeout=10)
        if "error" in output.lower():
            log_messages.append(f"ERREUR APRES: Problème de communication détecté: {output}")
            return False
        return True
    except Exception as e:
        log_messages.append(f"ERREUR APRES: Problème de connexion: {str(e)}")
        return False

def nettoyer_fichiers_apres_api(fichiers_a_supprimer, log_messages): # Renamed
    for fichier in fichiers_a_supprimer:
        try:
            if os.path.exists(fichier):
                os.remove(fichier)
                log_messages.append(f"Fichier APRES supprimé : {fichier}")
        except Exception as e:
            log_messages.append(f"Erreur APRES lors de la suppression du fichier {fichier}: {e}")

def normalize_text(text):
    try:
        if isinstance(text, list):
            return [normalize_text(line) for line in text]
        # Ensure text is string before normalize
        if not isinstance(text, str):
            text = str(text)
        text = unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII')
        return text.lower()
    except Exception as e:
        # print(f"Erreur lors de la normalisation du texte : {e}", file=sys.stderr) # No stderr print
        return str(text) # Return original text as string if normalization fails

def detect_encoding(file_path):
    try:
        with open(file_path, 'rb') as file:
            raw_data = file.read(1024)
            return chardet.detect(raw_data)['encoding'] or 'utf-8'
    except Exception:
        return 'utf-8' # Fallback

def read_file_by_line(file_path, log_messages):
    try:
        encoding = detect_encoding(file_path)
        with open(file_path, 'r', encoding=encoding, errors='replace') as file:
            for line in file:
                yield line.rstrip('\n')
    except FileNotFoundError:
        log_messages.append(f"Le fichier {file_path} n'a pas été trouvé.")
        yield None
    except Exception as e:
        log_messages.append(f"Erreur lors de la lecture du fichier {file_path} : {e}")
        yield None

def extract_sections(file_content_generator, log_messages):
    sections = OrderedDict()
    current_section = None
    try:
        for line in file_content_generator:
            if line is None: # Error during file reading
                return OrderedDict() # Return empty, error already logged
            stripped_line = line.strip()
            if stripped_line.endswith(" :") and len(stripped_line) < 100: # Avoid very long lines being sections
                current_section = stripped_line
                sections[current_section] = []
            elif current_section:
                sections[current_section].append(stripped_line)
    except Exception as e:
        log_messages.append(f"Erreur lors de l'extraction des sections : {e}")
    return sections

def compare_sections(sections_avant, sections_apres, log_messages):
    differences = OrderedDict()
    try:
        all_section_keys = set(sections_avant.keys()) | set(sections_apres.keys())
        
        for section_key in sorted(list(all_section_keys)): # Sort for consistent order
            content_avant = sections_avant.get(section_key, [])
            content_apres = sections_apres.get(section_key, [])

            # Normalize once per section content list
            norm_avant = set(normalize_text(content_avant))
            norm_apres = set(normalize_text(content_apres))

            if norm_avant != norm_apres:
                # Find lines unique to avant (removed) and apres (added) based on normalized content
                # But return the original (non-normalized) lines for display
                
                # Lines that were in 'avant' but their normalized form is not in 'apres'
                removed_lines = [line for line in content_avant if normalize_text(line) not in norm_apres]
                # Lines that are in 'apres' but their normalized form was not in 'avant'
                added_lines = [line for line in content_apres if normalize_text(line) not in norm_avant]

                # Handle cases where one side is empty to provide clear messages
                if not added_lines and removed_lines: # Effectively all original content removed
                    pass # added_lines remains empty
                if not removed_lines and added_lines: # Effectively all new content added
                    pass # removed_lines remains empty
                
                if added_lines or removed_lines: # Only add to differences if there's something to show
                    differences[section_key] = {
                        "avant_orig": content_avant, # Full original content for reference
                        "apres_orig": content_apres, # Full original content for reference
                        "removed": removed_lines if removed_lines else ["✓ (Aucun retrait ou contenu identique)"],
                        "added": added_lines if added_lines else ["✓ (Aucun ajout ou contenu identique)"]
                    }
            else: # Sections are identical after normalization
                 differences[section_key] = {
                        "avant_orig": content_avant,
                        "apres_orig": content_apres,
                        "removed": ["✓ (Identique)"],
                        "added": ["✓ (Identique)"]
                    }


    except Exception as e:
        log_messages.append(f"Erreur lors de la comparaison des sections : {e}")
    return differences


def format_differences_for_report(differences, log_messages):
    """Formats differences into a string or structured list for the report file/display."""
    report_lines = []
    if not differences:
        report_lines.append("Aucun changement substantiel détecté entre les configurations AVANT et APRÈS.")
        return report_lines

    report_lines.append("\nRapport des changements :\n")
    for section, content in differences.items():
        report_lines.append(f"\nSection: {section}")
        
        # Max lines for side-by-side display
        # Using the 'removed' and 'added' fields which contain actual differences or status messages
        max_lines = max(len(content["removed"]), len(content["added"]))

        if max_lines > 0:
            # Simple textual representation for now
            report_lines.append("--- AVANT ---")
            for line in content["removed"]: # Show what was removed or status
                report_lines.append(line)
            if not content["removed"]: report_lines.append("(Contenu inchangé ou non présent initialement)")

            report_lines.append("--- APRÈS ---")
            for line in content["added"]: # Show what was added or status
                report_lines.append(line)
            if not content["added"]: report_lines.append("(Contenu inchangé ou non présent finalement)")
            report_lines.append("-" * 30)
        else: # Should not happen if differences has this section
            report_lines.append("Aucun changement ou données non comparables.")
            
    return report_lines

# --- Main Process Function for APRES ---
def run_apres_checks_and_compare(ident_data, password, log_messages, avant_connection=None):
    """
    ident_data: Dictionary loaded from the identifiants_*.json file.
    password: Router password, as it's not stored in ident_data.
    avant_connection: Optional. If the connection from AVANT/UPDATE is still alive and passed.
    """
    ip = ident_data.get("ip")
    username = ident_data.get("username")
    avant_file_to_compare = ident_data.get("avant_file_path")

    if not all([ip, username, avant_file_to_compare]):
        msg = "Données d'identification incomplètes pour lancer APRES."
        log_messages.append(msg)
        return {"status": "error", "message": msg}

    if not os.path.exists(avant_file_to_compare):
        msg = f"Fichier AVANT ({avant_file_to_compare}) non trouvé pour comparaison."
        log_messages.append(msg)
        return {"status": "error", "message": msg}

    fichiers_crees_apres = []
    connection = avant_connection # Use existing connection if provided
    apres_file_path = None
    comparison_file_path = None
    router_hostname = ident_data.get("router_hostname", "inconnu")


    try:
        if connection is None or not connection.is_alive():
            if connection is not None: # was provided but dead
                log_messages.append("Connexion fournie pour APRES non active. Tentative de reconnexion.")
                connection.disconnect()

            device = {
                "device_type": "juniper",
                "host": ip,
                "username": username,
                "password": password,
                "timeout": 30,
            }
            log_messages.append(f"APRES: Tentative de connexion à {ip}...")
            connection = ConnectHandler(**device)
            log_messages.append(f"APRES: Connecté avec succès au routeur {ip}")
        else:
            log_messages.append("APRES: Utilisation de la connexion existante.")


        if not verifier_connexion_apres(connection, log_messages):
            raise Exception("APRES: Vérification de la connexion post-établissement échouée.")

        # Create APRES file (similar to AVANT)
        temp_apres_file = tempfile.NamedTemporaryFile(
            mode='w+', prefix='APRES_', suffix='.txt', delete=False, encoding='utf-8',
            dir=GENERATED_FILES_DIR
        )
        apres_file_path = temp_apres_file.name
        fichiers_crees_apres.append(apres_file_path)
        temp_apres_file.close()

        with open(apres_file_path, 'a', encoding='utf-8') as file:
            log_messages.append("\nAPRES: Récupération des informations de base du routeur...")
            file.write("Informations de base du routeur :\n")
            output = connection.send_command('show version')
            junos_version = "inconnu"
            router_model = "inconnu"
            current_router_hostname = "inconnu" # Potentially different if changed during update (unlikely for just version)
            for line in output.splitlines():
                if line.startswith("Hostname:"):
                    current_router_hostname = line.split("Hostname:")[1].strip()
                elif line.startswith("Model:"):
                    router_model = line.split("Model:")[1].strip()
                elif line.startswith("Junos:"):
                    junos_version = line.split("Junos:")[1].strip()
            
            log_messages.append(f"APRES Hostname: {current_router_hostname}, Model: {router_model}, Junos: {junos_version}")
            file.write(f"Le hostname du routeur est : {current_router_hostname}\n") # Use current
            file.write(f"Le modele du routeur est : {router_model}\n")
            file.write(f"La version du systeme Junos est : {junos_version}\n")

        # Rename APRES file
        # Use original hostname from ident_data for consistency in naming, unless it significantly changed
        final_apres_base = f"APRES_{username}_{router_hostname}.txt" # original hostname
        final_apres_path = os.path.join(GENERATED_FILES_DIR, final_apres_base)
        compteur = 1
        while os.path.exists(final_apres_path):
            final_apres_path = os.path.join(GENERATED_FILES_DIR, f"APRES_{username}_{router_hostname}_{compteur}.txt")
            compteur += 1
        
        if os.path.exists(apres_file_path): # apres_file_path is the temp file
            os.replace(apres_file_path, final_apres_path)
            fichiers_crees_apres.remove(apres_file_path)
            apres_file_path = final_apres_path
            fichiers_crees_apres.append(apres_file_path)
            log_messages.append(f"Fichier APRES renommé en: {apres_file_path}")
        else:
            log_messages.append(f"Avertissement: Fichier temporaire APRES {apres_file_path} non trouvé pour renommage.")
            apres_file_path = final_apres_path # Ensure it points to the intended final path

        # Continue writing to APRES file
        with open(apres_file_path, 'a', encoding='utf-8') as file:
            # Re-use the command list from AVANT_API or define it here
            # For simplicity, assuming similar commands are needed for APRES
            commands_to_run = {
                "Informations du moteur de routage :": "show chassis routing-engine",
                "Informations sur les interfaces :": [ # Special handling
                    "show interfaces terse | no-more",
                    "show interfaces detail | no-more"
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
                "La configuration totale :": "show configuration | display set" # Usually compared separately or not at all post-update
            }

            # Import parse_interfaces from AVANT_API or duplicate it here.
            # For this example, let's assume it's accessible (e.g. from AVANT_API import parse_interfaces)
            # If running standalone, this import needs to be handled.
            # from AVANT_API import parse_interfaces # This would require AVANT_API.py to be in PYTHONPATH

            for title, cmd_or_cmds in commands_to_run.items():
                if not verifier_connexion_apres(connection, log_messages): # Use apres version
                    raise Exception("APRES: Connexion perdue avec le routeur pendant la collecte.")
                
                log_messages.append(f"APRES - Récupération: {title}")
                file.write(f"\n{title}\n")
                
                if title == "Informations sur les interfaces :":
                    output_terse = connection.send_command(cmd_or_cmds[0])
                    output_detail = connection.send_command(cmd_or_cmds[1])
                    # You need parse_interfaces function available here
                    # For now, let's write raw output for interfaces in APRES to simplify
                    # In a real scenario, you'd use the same parsing as AVANT
                    file.write("--- TERSE ---\n" + output_terse + "\n")
                    file.write("--- DETAIL ---\n" + output_detail + "\n")
                    log_messages.append("APRES: Interfaces (raw) traitées.")
                    continue

                elif title == "Services configurés :":
                    output_services = connection.send_command(cmd_or_cmds)
                    services = set()
                    for line in output_services.splitlines():
                        if line.strip().endswith(";"): services.add(line.strip().rstrip(";"))
                    for service in sorted(services): file.write(service + "\n")
                    log_messages.append(f"APRES Services: {', '.join(sorted(services)) if services else 'Aucun'}")
                    continue

                elif title == "Protocoles configurés :":
                    output_protocols = connection.send_command(cmd_or_cmds)
                    protocols = set()
                    for line in output_protocols.splitlines():
                        if "{" in line and not line.strip().startswith("}"): protocols.add(line.split("{")[0].strip())
                    for protocol in sorted(protocols): file.write(protocol + "\n")
                    log_messages.append(f"APRES Protocoles: {', '.join(sorted(protocols)) if protocols else 'Aucun'}")
                    continue

                output = connection.send_command(cmd_or_cmds)
                filtered_output_lines = [line for line in output.splitlines() if not line.strip().startswith("---(more")]
                filtered_output = "\n".join(filtered_output_lines)
                file.write(filtered_output + "\n")
                log_messages.append(f"APRES - OK: {title}")


        # --- Comparaison ---
        log_messages.append("\nLancement de la comparaison entre AVANT et APRES...")
        content_gen_avant = read_file_by_line(avant_file_to_compare, log_messages)
        content_gen_apres = read_file_by_line(apres_file_path, log_messages)

        sections_avant = extract_sections(content_gen_avant, log_messages)
        sections_apres = extract_sections(content_gen_apres, log_messages)

        if not sections_avant and os.path.exists(avant_file_to_compare): # File exists but no sections extracted
            log_messages.append(f"AVERTISSEMENT: Aucune section extraite de {avant_file_to_compare}. Le fichier est-il vide ou mal formaté?")
        if not sections_apres and os.path.exists(apres_file_path):
            log_messages.append(f"AVERTISSEMENT: Aucune section extraite de {apres_file_path}. Le fichier est-il vide ou mal formaté?")


        differences = compare_sections(sections_avant, sections_apres, log_messages)
        
        # Save comparison report
        comp_base_name = f"COMPARAISON_{username}_{router_hostname}.txt"
        comparison_file_path = os.path.join(GENERATED_FILES_DIR, comp_base_name)
        compteur_comp = 1
        while os.path.exists(comparison_file_path):
            comparison_file_path = os.path.join(GENERATED_FILES_DIR, f"COMPARAISON_{username}_{router_hostname}_{compteur_comp}.txt")
            compteur_comp += 1
        
        formatted_diff_lines = format_differences_for_report(differences, log_messages)
        with open(comparison_file_path, 'w', encoding='utf-8') as f_comp:
            for line in formatted_diff_lines:
                f_comp.write(line + "\n")
        fichiers_crees_apres.append(comparison_file_path)
        log_messages.append(f"Rapport de comparaison sauvegardé dans: {comparison_file_path}")

        # Remove original identifiants file (as it's processed now)
        original_ident_file = ident_data.get("ident_file_path_from_avant_run") # if API passed it
        if not original_ident_file and len(sys.argv) > 1 and os.path.exists(sys.argv[1]): # if run by CLI
             original_ident_file = sys.argv[1]
        
        if original_ident_file and os.path.exists(original_ident_file):
            try:
                os.remove(original_ident_file)
                log_messages.append(f"Fichier d'identification {original_ident_file} supprimé.")
            except Exception as e_rem_ident:
                log_messages.append(f"Erreur suppression fichier identification {original_ident_file}: {e_rem_ident}")
        
        return {
            "status": "success",
            "message": "Vérifications APRES et comparaison terminées.",
            "apres_file_path": apres_file_path,
            "comparison_file_path": comparison_file_path,
            "comparison_data": differences, # The raw differences dict
            "log_messages": log_messages,
            "fichiers_crees_apres": fichiers_crees_apres
        }

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        error_msg = f"APRES: Erreur de connexion Netmiko: {str(e)}"
        log_messages.append(error_msg)
        return {"status": "error", "message": error_msg, "fichiers_crees": fichiers_crees_apres, "log_messages": log_messages}
    except Exception as e:
        error_msg = f"APRES: Erreur inattendue: {str(e)}"
        log_messages.append(error_msg)
        return {"status": "error", "message": error_msg, "fichiers_crees": fichiers_crees_apres, "log_messages": log_messages}
    finally:
        if connection and (avant_connection is None or connection != avant_connection) : # Disconnect only if APRES established it
            if connection.is_alive():
                connection.disconnect()
                log_messages.append("APRES: Connexion Netmiko fermée.")
        elif connection and avant_connection and not avant_connection.is_alive(): # if it was provided but died
             if connection.is_alive(): connection.disconnect() # if reconnected and died again


if __name__ == '__main__':
    # This part is for testing individual functions or a limited flow.
    # The full flow is orchestrated by the API.
    test_logs_apres = []
    
    # To test, you need an existing identifiants_*.json file from an AVANT run
    # Or craft a mock one:
    mock_ident_data = {
        "ip": "YOUR_ROUTER_IP", # Replace
        "username": "YOUR_USERNAME", # Replace
        "router_hostname": "test-router",
        "avant_file_path": "path/to/your/AVANT_user_test-router.txt", # Replace with actual AVANT file
        "lock_file_path": "path/to/router_locks/IP_norm.lock", # Replace
        "config_file_path": "path/to/CONFIGURATION_user_test-router.txt" # Replace
        # "ident_file_path_from_avant_run": "path/to/generated_files/identifiants_user_test-router.json" # Path to itself for deletion
    }
    # Ensure the avant_file_path in mock_ident_data points to a real AVANT output file for comparison.

    # test_password_apres = "YOUR_PASSWORD" # Replace

    # print("--- Test run_apres_checks_and_compare (Commented out for safety) ---")
    # if os.path.exists(mock_ident_data["avant_file_path"]):
    #     apres_result = run_apres_checks_and_compare(mock_ident_data, test_password_apres, test_logs_apres)
    #     print(json.dumps(apres_result, indent=2, ensure_ascii=False))
    #     print("\nLogs from apres_checks:")
    #     for log_entry in test_logs_apres:
    #         print(log_entry)
    # else:
    #     print(f"Skipping APRES test: mock avant_file_path does not exist: {mock_ident_data['avant_file_path']}")
    
    print("APRES_API.py is meant to be imported as a module.")
    print(f"GENERATED_FILES_DIR: {GENERATED_FILES_DIR}")

    # If called with a file argument (like original subprocess call from AVANT.py)
    if len(sys.argv) > 1:
        ident_file_arg = sys.argv[1]
        if os.path.exists(ident_file_arg):
            print(f"APRES_API.py: CLI mode: ident file provided: {ident_file_arg}")
            # This mode is tricky because it needs the password.
            # The original AVANT.py -> APRES.py flow didn't pass password via file.
            # For API, password will be supplied to the API endpoint.
            # This CLI mode is mostly for compatibility with the old subprocess call if strictly needed.
            # It would require getting password via input() here, which we are trying to avoid.
            # For now, just acknowledge the file.
            # with open(ident_file_arg, "r") as f:
            #     cli_ident_data = json.load(f)
            # cli_password = input("Enter password for APRES CLI mode: ")
            # cli_logs = []
            # run_apres_checks_and_compare(cli_ident_data, cli_password, cli_logs)
            # for log in cli_logs: print(log)

        else:
            print(f"APRES_API.py: CLI mode: ident file {ident_file_arg} not found.")