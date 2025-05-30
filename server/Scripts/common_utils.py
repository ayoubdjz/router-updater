import os
import sys
import ipaddress
import chardet
import unicodedata
from collections import OrderedDict
from netmiko import ConnectHandler, BaseConnection

# Fonction pour vérifier la connexion
def verifier_connexion(connection):
    try:
        output = connection.send_command("show system uptime", read_timeout=5)
        if "error" in output.lower():
            return False
        return True
    except Exception as e:
        print(f"\nERREUR: Problème de connexion: {str(e)}")
        return False

# Fonction pour nettoyer les fichiers et verrous
def nettoyer_fichiers(fichiers_a_supprimer, lock=None, lock_file=None):
    # Nettoyage des fichiers créés
    for fichier in fichiers_a_supprimer:
        try:
            if os.path.exists(fichier):
                os.remove(fichier)
                print(f"Fichier supprimé : {fichier}")
        except Exception as e:
            print(f"Erreur lors de la suppression du fichier {fichier}: {e}")
    # Libération du verrou si fourni
    if lock:
        try:
            lock.release()
            print("Verrou libéré.")
        except Exception as e:
            print(f"Erreur lors de la libération du verrou : {e}")
    # Suppression du fichier de verrou si fourni
    if lock_file and os.path.exists(lock_file):
        try:
            os.remove(lock_file)
            print(f"Fichier de verrou supprimé: {lock_file}")
        except Exception as e:
            print(f"Erreur lors de la suppression du fichier de verrou : {e}")

# Boîte de confirmation centrée 
def confirmation_box(question):
    # Récupérer la taille du terminal
    cols = os.get_terminal_size().columns
    lines = os.get_terminal_size().lines
    # Calcul des dimensions
    box_width = min(max(len(question), 30) + 8, cols - 4)
    left_padding = (cols - box_width) // 2
    top_padding = (lines - 7) // 2  # 7 = nombre de lignes de la boîte
    # Construction de la boîte
    border = " " * left_padding + "┌" + "─" * (box_width - 2) + "┐"
    empty_line = " " * left_padding + "│" + " " * (box_width - 2) + "│"
    question_line = " " * left_padding + "│" + f" {question.center(box_width - 4)} " + "│"
    buttons_line = " " * left_padding + "│" + " [1] Oui ".center(box_width // 2) + " [2] Non ".center(box_width // 2) + "│"
    # Affichage centré
    print("\n" * top_padding)  # Positionnement vertical
    print(border)
    print(" " * left_padding + "│" + " CONFIRMATION ".center(box_width - 2) + "│")
    print(empty_line)
    print(question_line)
    print(empty_line)
    print(buttons_line)
    print(" " * left_padding + "└" + "─" * (box_width - 2) + "┘")
    # Gestion de la saisie
    while True:
        try:
            choice = input(" " * left_padding + "Votre choix [1/2]: ").strip().lower()
            if choice in ('1', 'oui'):
                return True
            elif choice in ('2','non'):
                return False
            print(" " * left_padding + "Choix invalide")
        except KeyboardInterrupt:
            print("\n" + " " * left_padding + "Opération annulée")
            sys.exit(0)

# Fonction pour vérifier si l'adresse IP fournie est valide
def valider_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
def normalize_text(text):
    try:
        if isinstance(text, list):
            return [normalize_text(line) for line in text]
        text = unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII')
        return text.lower()
    except Exception as e:
        print(f"Erreur lors de la normalisation du texte : {e}", file=sys.stderr)
        return text

def detect_encoding(file_path):
    with open(file_path, 'rb') as file:
        raw_data = file.read(1024)  
        return chardet.detect(raw_data)['encoding'] or 'utf-8'

# Fonction pour lire un fichier ligne par ligne
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

# Fonction pour extraire les sections du fichier
def extract_sections(file_content):
    sections = OrderedDict()
    current_section = None
    for line in file_content:
        if line is None: 
            return OrderedDict()
        stripped_line = line.strip()
        try:
            if stripped_line.endswith(" :"):
                current_section = stripped_line
                sections[current_section] = []
            elif current_section:
                sections[current_section].append(stripped_line)
        except Exception as e:
            print(f"Erreur lors de l'extraction des sections : {e}", file=sys.stderr)
    return sections

# Fonction pour comparer les sections
def compare_sections(sections_avant, sections_apres):
    differences = OrderedDict()
    try:
        all_sections = OrderedDict()
        for section in sections_avant.keys():
            all_sections[section] = True
        for section in sections_apres.keys():
            all_sections[section] = True
        for section in all_sections.keys():
            content1 = sections_avant.get(section, [])
            content2 = sections_apres.get(section, [])
            norm1 = set(normalize_text(content1))
            norm2 = set(normalize_text(content2))
            if norm1 != norm2:
                # Modifier ici pour ajouter des messages explicites
                added = [line for line in content2 if normalize_text(line) in norm2 - norm1]
                removed = [line for line in content1 if normalize_text(line) in norm1 - norm2]
                # Si added est vide mais qu'il y a des removed, ajouter un message
                if not added and removed:
                    added = ["✗ (Supprimée)"]
                # Si removed est vide mais qu'il y a des added, ajouter un message
                if not removed and added:
                    removed = ["✗ (Aucune)"]
                differences[section] = {
                    "file1": content1,
                    "file2": content2,
                    "added": added,
                    "removed": removed
                }
    except Exception as e:
        print(f"Erreur lors de la comparaison des sections : {e}", file=sys.stderr)
    return differences

# Fonction pour afficher les différences
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

# Fonction pour écrire les différences dans un fichier
def write_differences_to_file(differences, filename):
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            if not differences:
                file.write("Aucun changement détecté entre les configurations avant et après le mis a jour.\n")
                return
            file.write("\nRapport des changements :\n")
            for section, content in differences.items():
                file.write(f"\n{section}\n")
                headers = {
                    "Interfaces OSPF actives :": "Interface           State   Area            DR ID           BDR ID          Nbrs",
                    "interfaces isis actives :": "Interface           System        Hold        SNPA",
                    "interfaces mpls actives :": "Interface            State        Administrative groups(x:extended)",
                    "sessions LDP activé :": "address            State        connection    timeAdv.Mode",
                    "voisin LLDP découvert  :": "local interface            parent interafce        Port info     System Name",
                    "interfaces configuré avec RSVP :": "interface           active resv       subscr-iption     static BW    Available BW      Resrved BW     highwater mark"
                }
                if section in headers:
                    file.write(headers[section] + "\n")
                max_lines = max(len(content["removed"]), len(content["added"]))
                if max_lines > 0:
                    max_before = max((len(line) for line in content["removed"]), default=0)
                    max_after = max((len(line) for line in content["added"]), default=0)
                    file_width = 120
                    use_vertical = (max_before + max_after + 3) > file_width
                    if use_vertical:
                        file.write("\n" + " AVANT ".center(file_width, "=") + "\n")
                        for line in content["removed"]:
                            file.write(line + "\n")
                        file.write("\n" + " APRÈS ".center(file_width, "=") + "\n")
                        for line in content["added"]:
                            file.write(line + "\n")
                        file.write("=" * file_width + "\n")
                    else:
                        col_before = max(max_before, 20)
                        col_after = max(max_after, 20)
                        file.write("\n" + "-" * (col_before + col_after + 3) + "\n")
                        file.write(f"{'AVANT'.center(col_before)} | {'APRÈS'.center(col_after)}\n")
                        file.write("-" * (col_before + col_after + 3) + "\n")
                        for i in range(max_lines):
                            # Modifications ici pour gérer les cas spéciaux
                            before = content["removed"][i] if i < len(content["removed"]) else "✓ (Identique)"
                            after = content["added"][i] if i < len(content["added"]) else "✓ (Identique)"
                            # Gestion spéciale des messages explicites
                            if before == "✗ (Aucune)":
                                after = content["added"][i] if i < len(content["added"]) else ""
                            elif after == "✗ (Supprimée)":
                                before = content["removed"][i] if i < len(content["removed"]) else ""
                            before_lines = [before[j:j+col_before] for j in range(0, len(before), col_before)] or [""]
                            after_lines = [after[j:j+col_after] for j in range(0, len(after), col_after)] or [""]
                            max_sub_lines = max(len(before_lines), len(after_lines))
                            for j in range(max_sub_lines):
                                before_part = before_lines[j] if j < len(before_lines) else ""
                                after_part = after_lines[j] if j < len(after_lines) else ""
                                
                                if j == 0:
                                    file.write(f"{before_part.ljust(col_before)} | {after_part.ljust(col_after)}\n")
                                else:
                                    file.write(f"{before_part.ljust(col_before)}   {after_part.ljust(col_after)}\n")
                        file.write("-" * (col_before + col_after + 3) + "\n\n")
        print(f"\nLe rapport détaillé des changements a été sauvegardé dans le fichier : {filename}.")
    except Exception as e:
        print(f"Erreur lors de l'écriture des différences dans le fichier : {e}")

def nettoyer_fichiers_disque(fichiers_a_supprimer):
    for fichier in fichiers_a_supprimer:
        try:
            if os.path.exists(fichier):
                os.remove(fichier)
                print(f"Fichier supprimé : {fichier}")
        except Exception as e:
            print(f"Erreur lors de la suppression du fichier {fichier}: {e}")

def fetch_and_store(
    connection,
    structured_output_data,
    data_key_structured,
    cmd,
    parser_func=None,
    read_timeout=90
):
    """
    Fetch data from the router, parse, and store in structured_output_data[data_key_structured].
    - connection: Netmiko connection object
    - structured_output_data: dict to store results
    - data_key_structured: key in structured_output_data
    - cmd: command to send
    - parser_func: function to parse output (optional)
    - read_timeout: timeout for command
    Returns: output (parsed or raw)
    Raises: Exception on error (collectors handle error in structured_output_data)
    """
    if not verifier_connexion(connection):
        raise Exception(f"Connexion perdue avant collecte de: {data_key_structured}")
    try:
        cmd_to_send = cmd.strip()
        if "show " in cmd_to_send and not cmd_to_send.endswith("| no-more") and not cmd_to_send.endswith("no-more"):
            cmd_to_send = f"{cmd_to_send} | no-more"
        output_cmd = connection.send_command(cmd_to_send, read_timeout=read_timeout)
        if isinstance(output_cmd, str):
            output_lines = output_cmd.splitlines()
            cleaned_lines = [line for line in output_lines if not line.strip().startswith("---(more")]
            output_cmd = "\n".join(cleaned_lines)
        if parser_func:
            parsed_data = parser_func(output_cmd)
            structured_output_data[data_key_structured] = parsed_data
        else:
            data_to_store = output_cmd.strip() if isinstance(output_cmd, str) else str(output_cmd)
            structured_output_data[data_key_structured] = data_to_store
        return output_cmd
    except Exception as e:
        # Do not update structured_output_data here; let collector handle it
        raise


def sanitize_for_json(data_dict):
    if not isinstance(data_dict, dict):
        return data_dict # Should not happen if our functions return dicts

    # Explicitly remove known non-serializable keys and check for Netmiko connection objects
    # Create a new dictionary to avoid modifying the original during iteration if it's complex
    sanitized_dict = {}
    for k, v in data_dict.items():
        if k in ['connection_obj', 'lock_obj']: # Known keys for objects
            continue
        if isinstance(v, BaseConnection): # Check if value is a Netmiko connection object
            continue
        sanitized_dict[k] = v
    return sanitized_dict