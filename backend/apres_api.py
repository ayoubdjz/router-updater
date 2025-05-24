import os
import sys
import json
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from pathlib import Path
import tempfile
import chardet
import unicodedata
from collections import OrderedDict
import portalocker # Stays, though not actively used for router locking in this context
import ipaddress

# --- Configuration & Basic Helpers ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GENERATED_FILES_DIR = os.path.join(SCRIPT_DIR, "generated_files")
Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

# Headers for the textual comparison report, styled like APRES.py
APRES_REPORT_HEADERS_MAP = {
    "Interfaces OSPF actives :": "Interface           State   Area            DR ID           BDR ID          Nbrs",
    "interfaces isis actives :": "Interface           System        Hold        SNPA",
    "les interfaces MPLS actives. :": "Interface            State        Administrative groups(x:extended)",
    "les interfaces  MPLS  actives. :": "Interface            State        Administrative groups(x:extended)", # Exact from APRES.py generated file
    "Sessions LDP actives :": "address            State        connection    timeAdv.Mode",
    "sessions LDP activé :": "address            State        connection    timeAdv.Mode", # Exact from APRES.py generated file
    "Voisins LLDP découverts :": "local interface            parent interafce        Port info     System Name",
    "voisin LLDP découvert  :": "local interface            parent interafce        Port info     System Name", # Exact from APRES.py generated file
    "Interfaces configurees avec RSVP :": "interface           active resv       subscr-iption     static BW    Available BW      Resrved BW     highwater mark",
    "interfaces configuré avec RSVP :" : "interface           active resv       subscr-iption     static BW    Available BW      Resrved BW     highwater mark" # Exact from APRES.py generated file
}

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
                    if ip_index < len(columns):
                        try:
                            ipaddress.ip_interface(columns[ip_index])
                            interface_ip_map[interface_name] = columns[ip_index]
                        except ValueError:
                            pass
                except ValueError: pass

    all_interface_details = {}
    physical_interface_sections = output_detail.split("Physical interface:")
    if len(physical_interface_sections) > 1: physical_interface_sections = physical_interface_sections[1:]

    for section in physical_interface_sections:
        lines = section.split("\n")
        if not lines: continue
        physical_interface_name_line = lines[0].strip()
        physical_interface_name = physical_interface_name_line.split(",")[0].strip()

        phys_speed = "Indisponible"; phys_mac = "N/A"
        for line in lines:
            if "Speed:" in line: phys_speed = line.split("Speed:")[1].split(",")[0].strip()
            if "Current address:" in line or "Hardware address:" in line:
                key = "Current address:" if "Current address:" in line else "Hardware address:"
                phys_mac = line.split(key)[1].strip().split(",")[0].split()[0]

        phys_ip = interface_ip_map.get(physical_interface_name, "Aucune IP (Physique)")
        all_interface_details[physical_interface_name] = {
            "name": physical_interface_name,
            "speed": phys_speed,
            "mac_address": phys_mac,
            "ip_address": phys_ip
        }

        logical_interface_sections = section.split("Logical interface ")
        if len(logical_interface_sections) > 1: logical_interface_sections = logical_interface_sections[1:]

        for logical_section in logical_interface_sections:
            logical_lines = logical_section.split("\n")
            if not logical_lines: continue

            logical_interface_name_line = logical_lines[0].strip()
            logical_interface_name = logical_interface_name_line.split()[0].strip()
            log_ip = interface_ip_map.get(logical_interface_name, "Aucune IP")

            if log_ip == "Aucune IP":
                for log_line in logical_lines:
                    if "Local:" in log_line and "inet" in logical_section.lower():
                        try:
                            parsed_log_ip_full = log_line.split("Local:")[1].split(",")[0].strip()
                            ipaddress.ip_address(parsed_log_ip_full.split('/')[0])
                            if parsed_log_ip_full: log_ip = parsed_log_ip_full; break
                        except (IndexError, ValueError): pass

            all_interface_details[logical_interface_name] = {
                "name": logical_interface_name,
                "speed": phys_speed,
                "ip_address": log_ip,
                "mac_address": phys_mac # Logical interfaces inherit MAC from physical
            }

    for name, status_val in interface_status_map.items():
        details = all_interface_details.get(name, {
            "name": name,
            "speed": "Indisponible",
            "ip_address": interface_ip_map.get(name, "Aucune IP"),
            "mac_address": "N/A"
        })
        details["status"] = status_val
        if status_val == "up": up_interfaces.append(details)
        else: down_interfaces.append(details)
    return up_interfaces, down_interfaces

def parse_interfaces_for_file_display_apres(up_obj_list, down_obj_list):
    up_display_lines = []
    for iface in up_obj_list:
        speed = iface['speed'] if iface['speed'] and iface['speed'] != "N/A" else "Indisponible"
        ip_address = iface['ip_address'] if iface['ip_address'] and iface['ip_address'] != "N/A" else "Aucune IP"
        mac = iface['mac_address'] if iface['mac_address'] and iface['mac_address'] != "N/A" else ""
        line_str = f"{iface['name']} - Vitesse: {speed} - IP: {ip_address}"
        if mac: line_str += f" - MAC: {mac}"
        up_display_lines.append(line_str)

    down_display_lines = []
    for iface in down_obj_list:
        speed = iface['speed'] if iface['speed'] and iface['speed'] != "N/A" else "Indisponible"
        ip_address = iface['ip_address'] if iface['ip_address'] and iface['ip_address'] != "N/A" else "Aucune IP"
        mac = iface['mac_address'] if iface['mac_address'] and iface['mac_address'] != "N/A" else ""
        line_str = f"{iface['name']} - Vitesse: {speed} - IP: {ip_address}"
        if mac: line_str += f" - MAC: {mac}"
        down_display_lines.append(line_str)
    return up_display_lines, "\n".join(down_display_lines) if down_display_lines else "Aucune interface inactive trouvee."

# --- Start of APRES.py comparison logic integration ---
def apres_normalize_text(text):
    try:
        if isinstance(text, list):
            return [apres_normalize_text(line) for line in text]
        text = unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII')
        return text.lower()
    except Exception as e:
        print(f"Erreur lors de la normalisation du texte : {e}", file=sys.stderr)
        return text

def detect_encoding(file_path):
    with open(file_path, 'rb') as file:
        raw_data = file.read(1024)  
        return chardet.detect(raw_data)['encoding'] or 'utf-8'


def read_file_by_line(file_path):
    try:
        encoding = detect_encoding(file_path)
        with open(file_path, 'r', encoding=encoding, errors='replace') as file:
            for line in file:
                yield line.rstrip('\n')
    except FileNotFoundError:
        print(f"Le fichier {file_path} n'a pas été trouvé.", file=sys.stderr)
        yield None
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier {file_path} : {e}", file=sys.stderr)
        yield None

def normalize_section_header(header):
    # Remove accents, lowercase, strip, collapse spaces, remove space before colon, ensure single colon
    if not isinstance(header, str):
        return header
    header = unicodedata.normalize('NFKD', header).encode('ASCII', 'ignore').decode('ASCII')
    header = header.lower().strip()
    header = header.replace(' :', ':')  # Remove space before colon
    header = header.replace('  ', ' ')
    header = header.replace('\t', ' ')
    header = ' '.join(header.split())  # Collapse multiple spaces
    if header.endswith(':'):
        header = header[:-1].strip() + ':'  # Ensure only one colon at end
    return header


def extract_sections(file_content):
    # Unified section extraction for both AVANT and APRES
    sections = OrderedDict()
    current_section = None
    current_section_orig = None
    for line in file_content:
        if line is None:
            return OrderedDict()
        stripped_line = line.strip()
        if not stripped_line:
            continue  # skip empty lines
        try:
            # Accept both ' :' and ':' as section delimiters
            if stripped_line.endswith(' :') or (stripped_line.endswith(':') and not stripped_line.endswith(' :')):
                normalized = normalize_section_header(stripped_line)
                current_section = normalized
                current_section_orig = stripped_line
                if current_section not in sections:
                    sections[current_section] = {"header": current_section_orig, "lines": []}
            elif current_section:
                sections[current_section]["lines"].append(stripped_line)
        except Exception as e:
            print(f"Erreur lors de l'extraction des sections : {e}", file=sys.stderr)
    return sections


def compare_sections(sections_avant, sections_apres):
    # Unified comparison for both AVANT and APRES
    differences = OrderedDict()
    try:
        all_sections = OrderedDict()
        for section in sections_avant.keys():
            all_sections[section] = True
        for section in sections_apres.keys():
            all_sections[section] = True
        for section in all_sections.keys():
            avant_lines = sections_avant.get(section, {"header": section, "lines": []})["lines"]
            apres_lines = sections_apres.get(section, {"header": section, "lines": []})["lines"]
            # Compare line by line, but also handle empty/added/removed
            removed = []
            added = []
            max_len = max(len(avant_lines), len(apres_lines))
            for i in range(max_len):
                if i < len(avant_lines) and i < len(apres_lines):
                    if apres_normalize_text(avant_lines[i]) == apres_normalize_text(apres_lines[i]):
                        removed.append("\u2713 (Identique)")
                        added.append("\u2713 (Identique)")
                    else:
                        removed.append(avant_lines[i])
                        added.append(apres_lines[i])
                elif i < len(avant_lines):
                    removed.append(avant_lines[i])
                    added.append("\u2717 (Supprim\u00e9e)")
                elif i < len(apres_lines):
                    removed.append("\u2717 (Aucune)")
                    added.append(apres_lines[i])
            # Only add if there is a difference
            if any(r != "\u2713 (Identique)" or a != "\u2713 (Identique)" for r, a in zip(removed, added)):
                header_display = sections_avant.get(section, sections_apres.get(section, {"header": section}))['header']
                differences[header_display] = {"removed": removed, "added": added}
    except Exception as e:
        print(f"Erreur lors de la comparaison des sections : {e}", file=sys.stderr)
    return differences

def display_differences(differences):
    if not differences:
        print("Aucun changement détecté entre les configurations avant et après le mis a jour")
        return
    print("\nRapport des changements :")
    for section, content in differences.items():
        print(f"\n{section}")
        # Afficher les en-têtes spécifiques si nécessaire
        headers = {
            "Interfaces OSPF actives :": "Interface           State   Area            DR ID           BDR ID          Nbrs",
            "interfaces isis actives :": "Interface           System        Hold        SNPA",
            "interfaces mpls actives :": "Interface            State        Administrative groups(x:extended)",
            "sessions LDP activé :": "address            State        connection    timeAdv.Mode",
            "voisin LLDP découvert  :": "local interface            parent interafce        Port info     System Name",
            "interfaces configuré avec RSVP :": "interface           active resv       subscr-iption     static BW    Available BW      Resrved BW     highwater mark"
        }
        if section in headers:
            print(headers[section])
        max_lines = max(len(content["removed"]), len(content["added"]))
        if max_lines > 0:
            # Calculer la largeur maximale pour chaque colonne
            max_before = max((len(line) for line in content["removed"]), default=0)
            max_after = max((len(line) for line in content["added"]), default=0)
            # Déterminer si on doit utiliser le mode vertical
            terminal_width = 120  # Largeur typique d'un terminal
            use_vertical = (max_before + max_after + 3) > terminal_width
            if use_vertical:
                # Mode vertical amélioré avec tableau
                print("\n" + " AVANT ".center(terminal_width, "="))
                for line in content["removed"]:
                    print(line)
                print("\n" + " APRÈS ".center(terminal_width, "="))
                for line in content["added"]:
                    print(line)
                print("=" * terminal_width)
            else:
                # Mode tableau côte à côte
                # Ajuster les largeurs pour l'alignement
                col_before = max(max_before, 20)
                col_after = max(max_after, 20)
                # En-têtes
                print("\n" + "-" * (col_before + col_after + 3))
                print(f"{'AVANT'.center(col_before)} | {'APRÈS'.center(col_after)}")
                print("-" * (col_before + col_after + 3))
                # Contenu
                for i in range(max_lines):
                    before = content["removed"][i] if i < len(content["removed"]) else "✓ (Identique)"
                    after = content["added"][i] if i < len(content["added"]) else "✓ (Identique)"
                    # Gestion spéciale des messages explicites
                    if before == "✗ (Aucune)":
                        after = content["added"][i] if i < len(content["added"]) else ""
                    elif after == "✗ (Supprimée)":
                        before = content["removed"][i] if i < len(content["removed"]) else ""
                    # Découper les lignes trop longues
                    before_lines = [before[j:j+col_before] for j in range(0, len(before), col_before)] or [""]
                    after_lines = [after[j:j+col_after] for j in range(0, len(after), col_after)] or [""]
                    max_sub_lines = max(len(before_lines), len(after_lines))
                    for j in range(max_sub_lines):
                        before_part = before_lines[j] if j < len(before_lines) else ""
                        after_part = after_lines[j] if j < len(after_lines) else ""
                        # Afficher seulement la première ligne avec le séparateur
                        if j == 0:
                            print(f"{before_part.ljust(col_before)} | {after_part.ljust(col_after)}")
                        else:
                            print(f"{before_part.ljust(col_before)}   {after_part.ljust(col_after)}")
                print("-" * (col_before + col_after + 3) + "\n")


def _format_single_section_for_report(section_name, section_content, headers_map, terminal_width=120):
    section_report_lines = []
    section_report_lines.append(f"\n{section_name}\n")

    matched_header = headers_map.get(section_name)
    # Fallback for slight variations in header names (e.g. accents, double spaces)
    if not matched_header:
        normalized_key_form = apres_normalize_text(section_name).replace(":", "").strip()
        for k_map, v_map_header in headers_map.items():
            if apres_normalize_text(k_map).replace(":", "").strip() == normalized_key_form:
                matched_header = v_map_header
                break
    if matched_header:
        section_report_lines.append(matched_header + "\n")

    # These are the lists potentially modified by apres_compare_sections with placeholders
    removed_lines_for_display = section_content["removed"]
    added_lines_for_display = section_content["added"]
    
    max_lines_count = max(len(removed_lines_for_display), len(added_lines_for_display))

    if max_lines_count > 0:
        max_before_len = max((len(str(line)) for line in removed_lines_for_display), default=0)
        max_after_len = max((len(str(line)) for line in added_lines_for_display), default=0)
        
        # Condition from APRES.py
        use_vertical = (max_before_len + max_after_len + 3) > terminal_width

        if use_vertical:
            section_report_lines.append("\n" + " AVANT ".center(terminal_width, "=") + "\n")
            # APRES.py iterates over content["removed"] and content["added"] directly for vertical.
            # Here, removed_lines_for_display and added_lines_for_display already contain placeholders.
            for line in removed_lines_for_display: # Uses the list that might contain "✗ (Aucune)"
                section_report_lines.append(str(line) + "\n")
            
            section_report_lines.append("\n" + " APRÈS ".center(terminal_width, "=") + "\n")
            for line in added_lines_for_display: # Uses the list that might contain "✗ (Supprimée)"
                section_report_lines.append(str(line) + "\n")
            section_report_lines.append("=" * terminal_width + "\n")
        else: # Side-by-side
            col_before_width = max(max_before_len, 20) # As in APRES.py
            col_after_width = max(max_after_len, 20)   # As in APRES.py
            
            section_report_lines.append("\n" + "-" * (col_before_width + col_after_width + 3) + "\n")
            section_report_lines.append(f"{'AVANT'.center(col_before_width)} | {'APRÈS'.center(col_after_width)}\n")
            section_report_lines.append("-" * (col_before_width + col_after_width + 3) + "\n")

            for i in range(max_lines_count):
                # Default to "✓ (Identique)" if index out of bounds
                before_text = str(removed_lines_for_display[i]) if i < len(removed_lines_for_display) else "✓ (Identique)"
                after_text = str(added_lines_for_display[i]) if i < len(added_lines_for_display) else "✓ (Identique)"

                # Special handling from APRES.py
                if before_text == "✗ (Aucune)": # Implies this was a placeholder for an added line
                    # Show the actual added line in 'APRÈS' column
                    after_text = str(added_lines_for_display[i]) if i < len(added_lines_for_display) else ""
                elif after_text == "✗ (Supprimée)": # Implies this was a placeholder for a removed line
                    # Show the actual removed line in 'AVANT' column
                    before_text = str(removed_lines_for_display[i]) if i < len(removed_lines_for_display) else ""
                
                # Line wrapping logic from APRES.py
                before_text_lines = [before_text[j:j+col_before_width] for j in range(0, len(before_text), col_before_width)] or [""]
                after_text_lines = [after_text[j:j+col_after_width] for j in range(0, len(after_text), col_after_width)] or [""]
                max_sub_lines_count = max(len(before_text_lines), len(after_text_lines))

                for j_sub in range(max_sub_lines_count):
                    before_part_text = before_text_lines[j_sub] if j_sub < len(before_text_lines) else ""
                    after_part_text = after_text_lines[j_sub] if j_sub < len(after_text_lines) else ""
                    
                    if j_sub == 0: # First sub-line gets "|"
                        section_report_lines.append(f"{before_part_text.ljust(col_before_width)} | {after_part_text.ljust(col_after_width)}\n")
                    else: # Subsequent sub-lines get spaces for alignment
                        section_report_lines.append(f"{before_part_text.ljust(col_before_width)}   {after_part_text.ljust(col_after_width)}\n")
            section_report_lines.append("-" * (col_before_width + col_after_width + 3) + "\n\n")
    return section_report_lines


def apres_generate_differences_report_string(differences, log_messages):
    report_lines = []
    try:
        if not differences:
            return "Aucun changement détecté entre les configurations avant et après la mise à jour.\n" # APRES.py: "le mis a jour"

        report_lines.append("RAPPORT DE COMPARAISON AVANT/APRÈS (Style APRES.py)\n" + "="*80 + "\n") # API specific header
        # APRES.py: print("\nRapport des changements :")
        # For API, the string will be returned, so the above header is fine. Let's add the APRES.py one too.
        report_lines.append("\nRapport des changements :\n")


        for section, content in differences.items():
            report_lines.extend(_format_single_section_for_report(section, content, APRES_REPORT_HEADERS_MAP))
        return "".join(report_lines)
    except Exception as e:
        log_messages.append(f"APRES ERREUR: Génération string rapport comparaison: {str(e)}")
        return f"Erreur lors de la génération du rapport de comparaison: {str(e)}"

def apres_write_differences_to_file(differences, filename, log_messages):
    try:
        # Generate report string using the same logic as for API response
        report_string = apres_generate_differences_report_string(differences, log_messages)
        
        # APRES.py "write_differences_to_file" has a slightly different intro for "no differences"
        # and doesn't have the "RAPPORT DE COMPARAISON..." header.
        # To match APRES.py file output *exactly*:
        file_report_lines = []
        if not differences:
            file_report_lines.append("Aucun changement détecté entre les configurations avant et après le mis a jour.\n")
        else:
            file_report_lines.append("\nRapport des changements :\n") # As in APRES.py write_differences_to_file
            for section, content in differences.items():
                 file_report_lines.extend(_format_single_section_for_report(section, content, APRES_REPORT_HEADERS_MAP)) # Re-use the formatter

        with open(filename, 'w', encoding='utf-8') as file:
            file.write("".join(file_report_lines))
        log_messages.append(f"APRES: Rapport de comparaison textuel (style APRES.py) sauvegardé : {filename}")
    except Exception as e:
        log_messages.append(f"APRES ERREUR: Écriture comparaison (fichier {filename}): {str(e)}")

# --- End of APRES.py comparison logic integration ---

def _parse_configured_protocols_output(output, log_messages, context="APRES"):
    protocols = set()
    for line in output.splitlines():
        line_stripped = line.strip()
        if "{" in line_stripped and not line_stripped.startswith("}") and not line_stripped.startswith("#"):
            protocol_name = line_stripped.split("{")[0].strip()
            if protocol_name and not ' ' in protocol_name and len(protocol_name) > 0:
                protocols.add(protocol_name)
    if protocols: return sorted(list(protocols))
    else: return {"message": "No configured protocols found in the output.", "protocols": []}

def _parse_firewall_acls_output(output, log_messages, context="APRES"):
    output_stripped = output.strip()
    if output_stripped: return output_stripped
    else: return "Aucune ACL configuree trouvee." # APRES.py: "Aucune ACL configurée trouvée."

def run_apres_checks_and_compare(ident_data, password, log_messages, avant_connection=None):
    ip = ident_data.get("ip"); username = ident_data.get("username")
    avant_file_to_compare_path = ident_data.get("avant_file_path")
    print(avant_file_to_compare_path)
    router_hostname = ident_data.get("router_hostname", "inconnu")
    original_ident_file_path = ident_data.get("ident_file_path")

    if not all([ip, username, avant_file_to_compare_path]):
        msg = "APRES: ident_data (ip, username, avant_file_path) incomplet."
        log_messages.append(msg)
        return {"status": "error", "message": msg, "logs": log_messages, "structured_data_apres": {}, "comparison_results": ""}
    if not os.path.exists(avant_file_to_compare_path):
        msg = f"APRES: Fichier AVANT {avant_file_to_compare_path} non trouvé pour comparaison."
        log_messages.append(msg)
        # Mirroring APRES.py behavior if files are missing, it would print and exit.
        # For API, we return an error and the comparison_results string should reflect this.
        error_comparison_string = f"Erreur lors de la lecture des fichiers. Veuillez vérifier les fichiers d'entrée.\nFichier AVANT '{avant_file_to_compare_path}' non trouvé ou illisible."
        return {"status": "error", "message": msg, "logs": log_messages, "structured_data_apres": {}, "comparison_results": error_comparison_string}

    fichiers_crees_apres = []; connection = None
    apres_file_path_internal = None; comparison_file_path_for_archive = None

    structured_output_data_apres = {
        "basic_info": {}, "routing_engine": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_info": "", "isis_info": "", "mpls_info": "", # Corrected ospf_info duplicate
        "ldp_info": "", "rsvp_info": "", "lldp_info": "", "lsp_info": "", "bgp_summary": "",
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
            connection.send_command('set cli screen-length 0', expect_string=r'[\#>]', read_timeout=10)
            log_messages.append("APRES: Pagination CLI désactivée (set cli screen-length 0).")
        except Exception as e_pagination:
            log_messages.append(f"APRES Warning: Impossible de désactiver la pagination CLI: {str(e_pagination)}")

        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)
        if not os.access(GENERATED_FILES_DIR, os.W_OK):
            raise PermissionError(f"APRES: Pas accès écriture à {GENERATED_FILES_DIR}")

        temp_apres_file_obj = tempfile.NamedTemporaryFile(mode='w+', prefix='APRES_TEMP_', suffix='.txt', delete=False, encoding='utf-8', dir=GENERATED_FILES_DIR)
        current_apres_file_path = temp_apres_file_obj.name
        fichiers_crees_apres.append(current_apres_file_path)

        section_title_basic_ap = "Informations de base du routeur"
        # structured_output_data_apres["basic_info"]["section_title_display"] = f"{section_title_basic_ap} (APRES)" # Not used in APRES.py
        temp_apres_file_obj.write(f"{section_title_basic_ap} :\n") # Key for section extraction

        out_ver_ap = connection.send_command('show version', read_timeout=30)
        if isinstance(out_ver_ap, str):
            out_ver_lines = out_ver_ap.splitlines()
            cleaned_ver_lines = [line for line in out_ver_lines if not line.strip().startswith("---(more")]
            out_ver_ap = "\n".join(cleaned_ver_lines)

        j_ver_ap, r_model_ap, cur_host_ap = "inconnu", "inconnu", router_hostname
        for l_idx, l in enumerate(out_ver_ap.splitlines()):
            if l.startswith("Hostname:"): cur_host_ap = l.split("Hostname:")[1].strip()
            elif l.startswith("Model:"): r_model_ap = l.split("Model:")[1].strip()
            elif l.startswith("Junos:"):
                 j_ver_ap_parts = l.split("Junos:", 1)
                 if len(j_ver_ap_parts) > 1: j_ver_ap = j_ver_ap_parts[1].strip()

        if cur_host_ap != "inconnu" and cur_host_ap != router_hostname:
            log_messages.append(f"APRES: Hostname a changé de {router_hostname} à {cur_host_ap}.")
            router_hostname = cur_host_ap # Update router_hostname for file naming

        structured_output_data_apres["basic_info"]["hostname"] = cur_host_ap
        structured_output_data_apres["basic_info"]["model"] = r_model_ap
        structured_output_data_apres["basic_info"]["junos_version"] = j_ver_ap
        temp_apres_file_obj.write(f"Le hostname du routeur est : {cur_host_ap}\n")
        temp_apres_file_obj.write(f"Le modele du routeur est : {r_model_ap}\n")
        temp_apres_file_obj.write(f"La version du systeme Junos est : {j_ver_ap}\n")
        log_messages.append(f"APRES Basic Info: Host={cur_host_ap}, Model={r_model_ap}, Junos={j_ver_ap}")

        temp_apres_file_obj.flush(); temp_apres_file_obj.close()

        final_apres_base = f"APRES_{username}_{router_hostname}.txt"
        final_apres_path = os.path.join(GENERATED_FILES_DIR, final_apres_base)
        compteur_ap = 1
        while os.path.exists(final_apres_path):
            final_apres_path = os.path.join(GENERATED_FILES_DIR, f"APRES_{username}_{router_hostname}_{compteur_ap}.txt"); compteur_ap += 1
        try:
            os.replace(current_apres_file_path, final_apres_path)
            log_messages.append(f"APRES: Fichier temporaire renommé en: {final_apres_path}")
            if current_apres_file_path in fichiers_crees_apres: fichiers_crees_apres.remove(current_apres_file_path)
            apres_file_path_internal = final_apres_path
            if apres_file_path_internal not in fichiers_crees_apres: fichiers_crees_apres.append(apres_file_path_internal)
        except OSError as e_rep_ap:
            log_messages.append(f"APRES ERREUR: Renommage fichier temp: {e_rep_ap}. Utilisation: {current_apres_file_path}")
            apres_file_path_internal = current_apres_file_path
            if apres_file_path_internal not in fichiers_crees_apres: fichiers_crees_apres.append(apres_file_path_internal)

        with open(apres_file_path_internal, 'a', encoding='utf-8') as file_ap:
            def fetch_and_store_apres(data_key_structured, title_for_file, cmd, parser_func=None, is_raw=True, read_timeout=90, not_configured_check=None, output_prefix_if_data="", check_empty_output_as_not_configured=False, empty_output_message="", section_title_in_file_override=None):
                if not verifier_connexion_apres(connection, log_messages, f"APRES Collect ({title_for_file})"):
                    err_msg = f"ERREUR APRES: Connexion perdue avant collecte de: {title_for_file}"; log_messages.append(err_msg); raise ConnectionError(err_msg)
                
                actual_section_title_for_file = section_title_in_file_override if section_title_in_file_override else title_for_file
                log_messages.append(f"APRES Récupération: {title_for_file} (Cmd: {cmd[:70]}{'...' if len(cmd)>70 else ''}) -> File Section: '{actual_section_title_for_file}'")
                file_ap.write(f"\n{actual_section_title_for_file} :\n") # Use the override for section key
                output = ""
                try:
                    cmd_to_send = cmd if cmd.strip().endswith("| no-more") or cmd.strip().endswith("no-more") else f"{cmd.strip()} | no-more"
                    output = connection.send_command(cmd_to_send, read_timeout=read_timeout)
                    if isinstance(output, str):
                        output_lines = output.splitlines()
                        cleaned_lines = [line for line in output_lines if not (line.strip().startswith("---(more") or line.strip() == "{master}")]
                        output = "\n".join(cleaned_lines).strip()
                    else: output = str(output).strip()
                except Exception as e_cmd:
                    err_msg = f"ERREUR APRES: Echec cmd '{cmd_to_send[:70]}...' pour '{title_for_file}': {e_cmd}"; log_messages.append(err_msg); file_ap.write(f"{err_msg}\n"); raise RuntimeError(f"Echec cmd pour {title_for_file}: {e_cmd}")

                if not_configured_check:
                    keywords, message_if_found = not_configured_check
                    if any(keyword.lower() in output.lower() for keyword in keywords):
                        structured_output_data_apres[data_key_structured] = message_if_found; file_ap.write(message_if_found + "\n"); log_messages.append(f"APRES INFO ({title_for_file}): {message_if_found}"); return
                if check_empty_output_as_not_configured and not output.strip():
                    msg_to_use = empty_output_message if empty_output_message else f"Aucune donnée pour {title_for_file}." # APRES.py often uses more specific messages
                    structured_output_data_apres[data_key_structured] = msg_to_use; file_ap.write(msg_to_use + "\n"); log_messages.append(f"APRES INFO ({title_for_file}): {msg_to_use}"); return
                if output.strip() and output_prefix_if_data: file_ap.write(output_prefix_if_data + "\n")

                if parser_func:
                    try:
                        parsed_data = parser_func(output, log_messages, f"APRES Parse ({title_for_file})")
                        structured_output_data_apres[data_key_structured] = parsed_data
                        # Writing to file: APRES.py writes raw output for most things, or specific formats
                        # For parsed data, we generally write the raw output to the file to match APRES.py format
                        file_ap.write(output + "\n") # Write raw output even if parsed for structured_data
                    except Exception as e_parse:
                        parse_err_msg = f"ERREUR APRES: Parse '{title_for_file}': {e_parse}. Output:\n{output[:300]}..."; log_messages.append(parse_err_msg); structured_output_data_apres[data_key_structured] = {"error": parse_err_msg, "raw_output": output}; file_ap.write(output + f"\n# ERREUR_PARSE: {parse_err_msg}\n")
                else: # is_raw or simple list
                    structured_output_data_apres[data_key_structured] = output # Store raw for is_raw=True
                    file_ap.write(output + "\n")
                log_messages.append(f"APRES OK: {title_for_file}")

            fetch_and_store_apres("routing_engine", "Informations du moteur de routage", "show chassis routing-engine", is_raw=True, read_timeout=90)
            
            section_title_interfaces_ap = "Informations sur les interfaces"; log_messages.append(f"APRES Récupération: {section_title_interfaces_ap}"); file_ap.write(f"\n{section_title_interfaces_ap} :\n")
            out_terse_ap = connection.send_command("show interfaces terse | no-more", read_timeout=90)
            if isinstance(out_terse_ap, str): out_terse_ap = "\n".join([l for l in out_terse_ap.splitlines() if not (l.strip().startswith("---(more") or l.strip() == "{master}")]).strip()
            out_detail_ap = connection.send_command("show interfaces detail | no-more", read_timeout=180)
            if isinstance(out_detail_ap, str): out_detail_ap = "\n".join([l for l in out_detail_ap.splitlines() if not (l.strip().startswith("---(more") or l.strip() == "{master}")]).strip()
            
            up_obj_list_ap, down_obj_list_ap = parse_interfaces_structured_for_table_apres(out_terse_ap, out_detail_ap, log_messages)
            structured_output_data_apres["interfaces_up"] = up_obj_list_ap
            structured_output_data_apres["interfaces_down"] = down_obj_list_ap if down_obj_list_ap else "Aucune interface inactive trouvée." # Match APRES.py wording
            
            up_file_lines_ap, down_file_str_ap = parse_interfaces_for_file_display_apres(up_obj_list_ap, down_obj_list_ap)
            file_ap.write("Les Interfaces up :\n") # This is a sub-section, not a main key for extraction
            if up_file_lines_ap:
                for lstr in up_file_lines_ap: file_ap.write(lstr + "\n")
            else: file_ap.write("Aucune interface active trouvee.\n") # APRES.py: "trouvée"
            file_ap.write("Les Interfaces down :\n") # This is a sub-section
            file_ap.write(down_file_str_ap + "\n"); log_messages.append(f"APRES OK: {section_title_interfaces_ap}")

            fetch_and_store_apres("arp_table", "Informations ARP", "show arp", is_raw=True, read_timeout=90)
            
            # Main title from APRES.py, not a section key itself for extraction.
            # The fetch_and_store_apres call below will write "Resume des routes :" as the key.
            file_ap.write(f"\nInformations sur les routes :\n")
            fetch_and_store_apres("route_summary", "Résumé des routes", "show route summary", is_raw=True, read_timeout=90, check_empty_output_as_not_configured=True, empty_output_message="Aucun résumé de route trouvé.", section_title_in_file_override="Resume des routes") # APRES.py: "Resume des routes"

            # Using section titles exactly as in APRES.py for file content to ensure matching section keys
            fetch_and_store_apres("ospf_info", "Protocole OSPF", "show ospf interface brief", section_title_in_file_override="Interfaces OSPF actives", is_raw=True, read_timeout=90, not_configured_check=(["OSPF instance is not running"], "OSPF n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("isis_info", "Protocole IS-IS", "show isis adjacency", section_title_in_file_override="interfaces isis actives", is_raw=True, read_timeout=90, not_configured_check=(["IS-IS is not running", "IS-IS is not enabled"], "IS-IS n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("mpls_info", "Protocole MPLS", "show mpls interface", section_title_in_file_override="les interfaces  MPLS  actives.", is_raw=True, read_timeout=90, not_configured_check=(["MPLS is not enabled", "MPLS not configured"], "MPLS n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("ldp_info", "Protcole LDP", "show ldp session", section_title_in_file_override="sessions LDP activé", is_raw=True, read_timeout=90, not_configured_check=(["LDP is not running"], "LDP n'est pas configuré sur ce routeur.")) # APRES.py: "Protcole LDP"
            fetch_and_store_apres("rsvp_info", "Protocole RSVP", "show rsvp interface", section_title_in_file_override="interfaces configuré avec RSVP", is_raw=True, read_timeout=90, not_configured_check=(["RSVP is not enabled", "RSVP not configured"], "RSVP n'est pas configuré sur ce routeur."))
            fetch_and_store_apres("lldp_info", "Protocole LLDP", "show lldp neighbor", section_title_in_file_override="voisin LLDP découvert ", is_raw=True, read_timeout=90, check_empty_output_as_not_configured=True, empty_output_message="LLDP n'est pas configuré ou aucun voisin n'a été détecté.") # APRES.py: "aucun voisin n'a ete detecte."
            fetch_and_store_apres("lsp_info", "Protocole LSP", "show mpls lsp", section_title_in_file_override="statut des LSP", is_raw=True, read_timeout=90, not_configured_check=(["No LSPs found", "MPLS not configured"], "Aucune session lsp trouvé.")) # APRES.py: "trouvé"
            fetch_and_store_apres("bgp_summary", "Protocole BGP", "show bgp summary", section_title_in_file_override="Protocole BGP", is_raw=True, read_timeout=90, not_configured_check=(["BGP is not running"], "BGP n'est pas configuré sur ce routeur.")) # Section title matches data key here.

            def parse_svcs_ap(output, l,c): return sorted(list(set(l.strip().rstrip(";") for l in output.splitlines() if l.strip().endswith(";"))))
            fetch_and_store_apres("system_services", "Services configurés", "show configuration system services", parser_func=parse_svcs_ap, is_raw=False, read_timeout=90, section_title_in_file_override="Services configures") # APRES.py: "Services configures"
            fetch_and_store_apres("configured_protocols", "Protocoles configurés", "show configuration protocols", parser_func=_parse_configured_protocols_output, is_raw=False, read_timeout=90, section_title_in_file_override="Protocoles configures") # APRES.py: "Protocoles configures"
            
            # APRES.py has "Reponse de la commande 'show configuration firewall' :" as a sub-header within this section
            fetch_and_store_apres("firewall_config", "Listes de Contrôle d'Accès (ACL)", "show configuration firewall", parser_func=_parse_firewall_acls_output, is_raw=False, read_timeout=90, output_prefix_if_data="Reponse de la commande 'show configuration firewall' :", check_empty_output_as_not_configured=True, empty_output_message="Aucune ACL configurée trouvée.", section_title_in_file_override="Listes de Controle d'Acces (ACL)") # APRES.py: "Controle d'Acces (ACL)"

            file_ap.write(f"\nLogs des erreurs critiques :\n") # Main title, not section key
            fetch_and_store_apres("critical_logs_messages", "Logs des erreurs critiques dans 'messages'", 'show log messages | match "error|warning|critical" | last 10', is_raw=True, read_timeout=60, check_empty_output_as_not_configured=True, empty_output_message="Aucun log critique recent dans 'messages'.", section_title_in_file_override="Logs des erreurs critiques dans 'messages'")
            fetch_and_store_apres("critical_logs_chassisd", "Logs des erreurs critiques dans 'chassisd'", 'show log chassisd | match "error|warning|critical" | last 10', is_raw=True, read_timeout=60, check_empty_output_as_not_configured=True, empty_output_message="Aucun log critique recent dans 'chassisd'.", section_title_in_file_override="Logs des erreurs critiques dans 'chassisd'")
            
            fetch_and_store_apres("full_config_set", "La configuration totale", "show configuration | display set", is_raw=True, read_timeout=300, section_title_in_file_override="La configuration totale")

        log_messages.append(f"\nAPRES Lancement comparaison AVANT/APRES...")
        content_avant_gen = read_file_by_line(avant_file_to_compare_path)
        sections_from_avant_file = extract_sections(content_avant_gen)
        
        # Check if APRES file was created and is readable
        if not apres_file_path_internal or not os.path.exists(apres_file_path_internal):
            msg = f"APRES: Fichier APRES ({apres_file_path_internal}) non créé ou inaccessible. Comparaison impossible."
            log_messages.append(msg)
            error_comparison_string = f"Erreur lors de la lecture des fichiers. Veuillez vérifier les fichiers d'entrée.\nFichier APRES non généré ou illisible."
            # Clean up connection if open
            if connection and connection.is_alive(): connection.disconnect()
            return {"status": "error", "message": msg, "logs": log_messages, "structured_data_apres": structured_output_data_apres, "comparison_results": error_comparison_string, "fichiers_crees_apres": fichiers_crees_apres, "connection_obj": None}

        content_apres_gen = read_file_by_line(apres_file_path_internal)
        sections_from_apres_file = extract_sections(content_apres_gen)

        comparison_report_string_for_api = ""
        if (not sections_from_avant_file and os.path.exists(avant_file_to_compare_path)) or \
           (not sections_from_apres_file and os.path.exists(apres_file_path_internal)):
            log_messages.append(f"APRES AVERT: Section(s) manquante(s) AVANT ou APRES. La comparaison peut être partielle ou vide.")
            # APRES.py behavior is to print error and exit
            comparison_report_string_for_api = "Erreur lors de la lecture des fichiers. Veuillez vérifier les fichiers d'entrée.\n"
            if not sections_from_avant_file:
                 comparison_report_string_for_api += f"Impossible d'extraire les sections du fichier AVANT: {avant_file_to_compare_path}\n"
            if not sections_from_apres_file:
                 comparison_report_string_for_api += f"Impossible d'extraire les sections du fichier APRES: {apres_file_path_internal}\n"
        
        # Proceed with comparison even if one set of sections is empty, to show all as added/removed
        differences_data = compare_sections(sections_from_avant_file, sections_from_apres_file)
        display_differences(differences_data)
        # If comparison_report_string_for_api is already set due to extraction errors, don't overwrite with "Aucun changement"
        if not comparison_report_string_for_api:
            comparison_report_string_for_api = apres_generate_differences_report_string(differences_data, log_messages)

        comp_base_name = f"COMPARAISON_{username}_{router_hostname}.txt"
        comparison_file_path_for_archive = os.path.join(GENERATED_FILES_DIR, comp_base_name)
        comp_counter = 1
        while os.path.exists(comparison_file_path_for_archive):
            comparison_file_path_for_archive = os.path.join(GENERATED_FILES_DIR, f"COMPARAISON_{username}_{router_hostname}_{comp_counter}.txt"); comp_counter+=1
        apres_write_differences_to_file(differences_data, comparison_file_path_for_archive, log_messages)
        fichiers_crees_apres.append(comparison_file_path_for_archive)

        if original_ident_file_path and os.path.exists(original_ident_file_path):
            try: os.remove(original_ident_file_path); log_messages.append(f"APRES: Fichier identifiant {original_ident_file_path} supprimé.")
            except Exception as e_del_id: log_messages.append(f"APRES Erreur suppression identifiant {original_ident_file_path}: {e_del_id}")
        else: log_messages.append(f"APRES: Ancien identifiant ({original_ident_file_path}) non trouvé/spécifié pour suppression.")
        
        log_messages.append(f"--- Fin run_apres_checks_and_compare pour {ip} ---")
        return {
            "status": "success", "message": "Vérifications APRES et comparaison terminées.",
            "apres_file_path": apres_file_path_internal, 
            "comparison_file_path": comparison_file_path_for_archive, 
            "structured_data_apres": structured_output_data_apres, 
            "comparison_results": comparison_report_string_for_api,
            "log_messages": log_messages,
            "fichiers_crees_apres": fichiers_crees_apres, 
            "connection_obj": connection 
        }

    except (NetmikoTimeoutException, NetmikoAuthenticationException, ConnectionError, RuntimeError, PermissionError) as e_critical:
        import traceback
        error_msg = f"APRES: Erreur critique: {str(e_critical)} (Type: {type(e_critical).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        # Ensure structured data reflects the error for all potentially uncollected fields
        for k_d in structured_output_data_apres:
            if not structured_output_data_apres[k_d] or (isinstance(structured_output_data_apres[k_d], dict) and not structured_output_data_apres[k_d]):
                structured_output_data_apres[k_d] = {"message": f"Collecte interrompue: {str(e_critical)}"}
        if connection:
            try:
                if connection.is_alive(): connection.disconnect()
                log_messages.append("APRES: Connexion fermée (erreur critique).")
            except Exception as e_disc: log_messages.append(f"APRES: Erreur fermeture connexion (erreur critique): {e_disc}")
        return {"status": "error", "message": error_msg, "fichiers_crees_apres": fichiers_crees_apres, "structured_data_apres": structured_output_data_apres, "comparison_results": f"Erreur critique pendant l'exécution : {error_msg}", "log_messages": log_messages, "connection_obj": None}
    except Exception as e_generic_apres:
        import traceback
        error_msg = f"APRES: Erreur majeure inattendue: {str(e_generic_apres)} (Type: {type(e_generic_apres).__name__})"
        log_messages.append(error_msg + f"\nTraceback:\n{traceback.format_exc()}")
        for k_d in structured_output_data_apres:
            if not structured_output_data_apres[k_d] or (isinstance(structured_output_data_apres[k_d], dict) and not structured_output_data_apres[k_d]):
                structured_output_data_apres[k_d] = {"message": f"Collecte interrompue (erreur majeure): {error_msg}"}
        if connection:
            try:
                if connection.is_alive(): connection.disconnect()
                log_messages.append("APRES: Connexion fermée (erreur majeure).")
            except Exception as e_disc: log_messages.append(f"APRES: Erreur fermeture connexion (erreur majeure): {e_disc}")
        return {"status": "error", "message": error_msg, "fichiers_crees_apres": fichiers_crees_apres, "structured_data_apres": structured_output_data_apres, "comparison_results": f"Erreur majeure inattendue : {error_msg}", "log_messages": log_messages, "connection_obj": None}

if __name__ == '__main__':
    print("APRES_API.py: Script chargé. Prêt pour les tests unitaires ou d'intégration.")
    # Example test (requires a Juniper device or mock, and a dummy AVANT file)
    # Ensure GENERATED_FILES_DIR exists for dummy file creation
    if not os.path.exists(GENERATED_FILES_DIR):
        os.makedirs(GENERATED_FILES_DIR)

    # dummy_avant_content = """Informations de base du routeur :
# Le hostname du routeur est : AVANT_ROUTER
# Le modele du routeur est : AVANT_MODEL
# La version du systeme Junos est : AVANT_JUNOS_VERSION
# interfaces isis actives :
# xe-0/0/0 UP STATE1
# xe-0/0/1 OLD_STATE
# Protocole BGP :
# Groups: 2 Peers: 4 Down peers: 0
# Table inet.0 Contrib Status: Accepted
# Removed Section :
# this line was removed
# """
    # dummy_avant_path = os.path.join(GENERATED_FILES_DIR, "dummy_avant_main_test.txt")
    # with open(dummy_avant_path, "w", encoding="utf-8") as f:
    #     f.write(dummy_avant_content)
    # print(f"Dummy AVANT file created at: {dummy_avant_path}")
    
    # dummy_ident_file_path = os.path.join(GENERATED_FILES_DIR, "dummy_ident_main_test.json")
    # test_ident_data = {
    #     "ip": "YOUR_DEVICE_IP", # Replace
    #     "username": "YOUR_USERNAME", # Replace
    #     "router_hostname": "initial_hostname_test",
    #     "avant_file_path": dummy_avant_path,
    #     "ident_file_path": dummy_ident_file_path 
    # }
    # # Create a dummy ident file for deletion testing
    # with open(test_ident_data["ident_file_path"], "w") as f_id_test: json.dump({"test_key":"test_val"}, f_id_test)
    # print(f"Dummy IDENT file created at: {dummy_ident_file_path}")

    # test_password = "YOUR_PASSWORD" # Replace
    # test_log_messages = []

    # print(f"APRES_API Main Test: Démarrage pour {test_ident_data['ip']}")
    # # Assuming you have a device at YOUR_DEVICE_IP or use a mock
    # # For local test without live device, you might need to mock ConnectHandler
    # # or comment out the run_apres_checks_and_compare call.
    # results = run_apres_checks_and_compare(test_ident_data, test_password, test_log_messages)
    
    # print("\n--- APRES_API Main Test Results ---")
    # print(f"Status: {results.get('status')}")
    # print(f"Message: {results.get('message')}")
    # if results.get('apres_file_path'): print(f"APRES file: {results.get('apres_file_path')}")
    # if results.get('comparison_file_path'): print(f"Comparison file (archive): {results.get('comparison_file_path')}")
    
    # print("\n--- Comparison Results (Textual Report String from API) ---")
    # print(results.get('comparison_results', "Aucun rapport de comparaison généré."))

    # print("\n--- Log Messages ---")
    # for log_idx, log_msg_item in enumerate(results.get('log_messages', [])): print(f"{log_idx + 1}: {log_msg_item}")
        
    # print("\n--- Cleaning up dummy files from __main__ ---")
    # files_to_clean_from_test = [
    #     dummy_avant_path,
    #     results.get('apres_file_path'), # This is already in results.get('fichiers_crees_apres')
    #     results.get('comparison_file_path'), # This is also in results.get('fichiers_crees_apres')
    #     # test_ident_data["ident_file_path"] # This should be deleted by the script if found
    # ]
    # if results.get('fichiers_crees_apres'):
    #     files_to_clean_from_test.extend(results.get('fichiers_crees_apres'))

    # for file_path_to_clean in set(filter(None, files_to_clean_from_test)): # Use set to avoid duplicates, filter None
    #     if file_path_to_clean and os.path.exists(file_path_to_clean):
    #         try: os.remove(file_path_to_clean); print(f"Removed: {file_path_to_clean}")
    #         except Exception as e_clean: print(f"Error removing {file_path_to_clean}: {e_clean}")
    
    # # Check if ident file was deleted
    # if os.path.exists(dummy_ident_file_path):
    #     print(f"WARNING: Dummy ident file {dummy_ident_file_path} was NOT deleted.")
    #     try: os.remove(dummy_ident_file_path); print(f"Manually removed: {dummy_ident_file_path}")
    #     except: pass
    # else:
    #     print(f"Dummy ident file {dummy_ident_file_path} was successfully deleted by the script.")