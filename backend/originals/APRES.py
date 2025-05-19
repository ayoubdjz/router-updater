import os
import sys
import json
import glob
from getpass import getpass
from netmiko import ConnectHandler
import ipaddress
import tempfile
import chardet
import unicodedata
from collections import OrderedDict

# Fonction pour vérifier si l'adresse IP fournie est valide
def valider_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Fonction pour vérifier la connexion
def verifier_connexion(connection):
    try:
        output = connection.send_command("show system uptime", read_timeout=5)
        if "error" in output.lower():
            return False
        return True
    except Exception as e:
        print(f"\nErreur : Problème de connexion: {str(e)}")
        return False
    
# Fonction pour nettoyer les fichiers
def nettoyer_fichiers(fichiers_a_supprimer):
    for fichier in fichiers_a_supprimer:
        try:
            if os.path.exists(fichier):
                os.remove(fichier)
                print(f"Le fichier {fichier} a été supprimé")
        except Exception as e:
            print(f"Erreur lors de la suppression du fichier {fichier}: {e}")

# Fonction pour normaliser le texte
def normalize_text(text):
    try:
        if isinstance(text, list):
            return [normalize_text(line) for line in text]
        text = unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII')
        return text.lower()
    except Exception as e:
        print(f"Erreur lors de la normalisation du texte : {e}", file=sys.stderr)
        return text

# Fonction pour détecter l'encodage d'un fichier
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

# Trouver et charger le fichier d'identification
try:
    # Vérifier si un fichier d'identifiants a été passé en argument
    if len(sys.argv) > 1:
        selected_file = sys.argv[1]
        if not os.path.exists(selected_file):
            raise FileNotFoundError(f"Fichier spécifié introuvable: {selected_file}")
    else:
        # Fallback à la recherche automatique si aucun argument
        fichier_identifiants = glob.glob("identifiants_*.json")
        if not fichier_identifiants:
            raise FileNotFoundError("Aucun fichier d'identification trouvé. Exécutez AVANT.py d'abord.")
        
        if len(fichier_identifiants) > 1:
            print("Plusieurs sessions actives détectées:")
            for i, file in enumerate(fichier_identifiants, 1):
                print(f"{i}. {file}")
            choice = int(input("Choisissez le numéro de la session à utiliser: ")) - 1
            selected_file = fichier_identifiants[choice]
        else:
            selected_file = fichier_identifiants[0]
    # Charger le fichier d'identifiants
    with open(selected_file, "r") as f:
        identifiants = json.load(f)
    # Validation des champs requis
    ip = identifiants.get("ip")
    username = identifiants.get("username")
    lock_file = identifiants.get("lock_file")
    AVANT = identifiants.get("AVANT", "")
    config_filename = identifiants.get("config_filename","")
    if not all([ip, username, lock_file]):
        raise ValueError("Fichier d'identifiants incomplet ou corrompu")
    if not valider_ip(ip):
        raise ValueError("Adresse IP invalide dans le fichier d'identifiants")
except Exception as e:
    print(f"ERREUR: {str(e)}")
    sys.exit(1)

# Boucle pour la connexion SSH
connection = None
fichiers_crees = [] 
APRES = None
fichier_identifiants = None
try:
    while True:
        password = getpass("Veuillez entrer votre mot de passe : ")
        device = {
            "device_type": "juniper",
            "host": ip,
            "username": username,
            "password": password,
            "timeout": 30,  # Augmenté le timeout pour les connexions lentes
        }
        try:
            connection = ConnectHandler(**device)
            # Vérification de la connexion
            if verifier_connexion(connection):
                break
            else:
                print("Échec de la connexion. Veuillez réessayer.")
                connection.disconnect()
        except Exception as e:
            print(f"Échec de la connexion: {str(e)}")
            print("Veuillez vérifier votre mot de passe et réessayer.\n")
            if connection:
                connection.disconnect()

    # Création du fichier temporaire
    temp_file = tempfile.NamedTemporaryFile(
        mode='w+',
        prefix='APRES_',
        suffix='.txt',
        delete=False,  # Ne pas supprimer automatiquement à la fermeture
        encoding='utf-8'
    )
    fichier_temporaire = temp_file.name
    fichiers_crees.append(fichier_temporaire)
    # Fermer le fichier car nous allons le rouvrir en mode 'with' plus tard
    temp_file.close()
    # Réouvrir le fichier en mode append pour y écrire les données
    with open(fichier_temporaire, 'a', encoding='utf-8') as file:
        try: 
            # Récupérer les informations de version
            #Vérifie si la connexion est toujours active
            if not verifier_connexion(connection):
                raise Exception("Connexion perdue avec le routeur")
            print("\nInformations de base du routeur :")
            file.write("Informations de base du routeur :\n")
            output = connection.send_command('show version')
            junos_version = "inconnu"
            router_model = "inconnu"
            router_hostname = "inconnu"
            for line in output.splitlines():
                if line.startswith("Hostname:"):
                    router_hostname = line.split("Hostname:")[1].strip()
                    print(f"Le hostname du routeur est : {router_hostname}")
                    file.write(f"Le hostname du routeur est : {router_hostname}\n")
                elif line.startswith("Model:"):
                    router_model = line.split("Model:")[1].strip()
                    print(f"Le modèle du routeur est : {router_model}")
                    file.write(f"Le modele du routeur est : {router_model}\n")
                elif line.startswith("Junos:"): 
                    junos_version = line.split("Junos:")[1].strip()
                    print(f"La version du système Junos est : {junos_version}")
                    file.write(f"La version du systeme Junos est : {junos_version}\n")
        except Exception as e:
            print(f"Erreur lors de la récupération des informations de base du routeur : {str(e)}")
            file.write(f"\nErreur lors de la recuperation des informations de base du routeur : {str(e)}")
            junos_version = "inconnu"
            router_model = "inconnu"
            router_hostname = "inconnu"
            raise # Relance l'exception pour arrêter le script

    # Renommage sécurisé du fichier temporaire
    # Renommer le fichier temporaire avec le nom du routeur
    base_APRES = f"APRES_{username}_{router_hostname}.txt"
    APRES = base_APRES
    # Vérifier si le fichier final existe déjà et trouver un nom disponible
    compteur = 1
    while os.path.exists(APRES):
        APRES = f"APRES_{username}_{router_hostname}_{compteur}.txt"
        compteur += 1
    try:
        # Vérifier que le fichier source existe
        if os.path.exists(fichier_temporaire):
            # Fermer explicitement le fichier s'il est ouvert
            if 'file' in locals() and not file.closed:
                file.close()
            # Renommer de manière atomique
            os.replace(fichier_temporaire, APRES)
            # Mettre à jour la liste des fichiers créés
            fichiers_crees.remove(fichier_temporaire)
            fichiers_crees.append(APRES)
        else:
            print("Avertissement : Le fichier temporaire est introuvable.")
            APRES = fichier_temporaire
    except Exception as e:
        print(f"Erreur lors du renommage : {e}. Le fichier reste {fichier_temporaire}")
        APRES = fichier_temporaire
        # Ajouter le fichier temporaire à la liste s'il n'y est pas déjà
        if fichier_temporaire not in fichiers_crees:
            fichiers_crees.append(fichier_temporaire)

    with open(APRES, 'a') as file:
        # Afficher les informations du moteur de routage 
        try:
            if not verifier_connexion(connection):
                raise Exception("Connexion perdue avec le routeur")
            print("\nInformations du moteur de routage :")
            file.write("\nInformations du moteur de routage :\n")
            routing_engine_output = connection.send_command("show chassis routing-engine")
            print(routing_engine_output)
            file.write(routing_engine_output + "\n")
        except Exception as e:
            print(f"Erreur lors de la récupération des informations du moteur de routage : {e}")
            file.write(f"Erreur lors de la recuperation des informations du moteur de routage : {e}")
            raise  

        # Récupérer les informations des interfaces
        try:
            if not verifier_connexion(connection):
                raise Exception("Connexion perdue avec le routeur")
            print("\nInformations sur les interfaces :")
            file.write("\nInformations sur les interfaces :\n")
            output_terse = connection.send_command("show interfaces terse | no-more")
            output_detail = connection.send_command("show interfaces detail | no-more")
            interfaces_up = []
            interfaces_down = []
            interfaces_info = {}
            interfaces_ip = {}
            interfaces_mac = {}  
            # Traitement des interfaces physiques et logiques
            for line in output_terse.splitlines():
                columns = line.split()
                if len(columns) >= 2:
                    interface_name = columns[0]
                    status = columns[1]
                    if "up" in status.lower():
                        interfaces_up.append(interface_name)
                    elif "down" in status.lower():
                        interfaces_down.append(interface_name)
                    if "inet" in columns:
                        ip_index = columns.index("inet") + 1
                        if ip_index < len(columns):
                            interfaces_ip[interface_name] = columns[ip_index]
            # Extraction des informations détaillées (BP et adresse MAC)
            interfaces = output_detail.split("Physical interface:")[1:]
            for interface in interfaces:
                lines = interface.split("\n")
                interface_name = lines[0].strip().split(",")[0]
                speed = "Indisponible"
                mac_address = None  # Par défaut, pas d'adresse MAC
                for line in lines:
                    if "Speed:" in line:
                        speed = line.split("Speed:")[1].split(",")[0].strip()
                    if "Current address:" in line:
                        mac_address = line.split("Current address:")[1].strip().split()[0]  # Ne garde que l'adresse MAC
                interfaces_info[interface_name] = speed
                interfaces_mac[interface_name] = mac_address  # Stocker l'adresse MAC
                # Traitement des interfaces logiques
                logical_interfaces = interface.split("Logical interface")[1:]
                for logical_interface in logical_interfaces:
                    logical_lines = logical_interface.split("\n")
                    logical_name = logical_lines[0].strip().split()[0]
                    # Stocker les informations de l'interface logique
                    interfaces_info[logical_name] = speed
                    # Récupérer l'adresse IP de l'interface logique
                    for line in logical_lines:
                        if "Local:" in line and "Destination:" in line:
                            logical_ip = line.split("Local:")[1].split(",")[0].strip()
                            interfaces_ip[logical_name] = logical_ip
            # Affichage des interfaces up
            print("Les Interfaces up :")
            file.write("Les Interfaces up :\n")
            if interfaces_up:
                for intf in interfaces_up:
                    speed = interfaces_info.get(intf, "Indisponible")
                    ip_address = interfaces_ip.get(intf, "Aucune IP")
                    mac_address = interfaces_mac.get(intf)
                    output = f"{intf} - Vitesse: {speed} - IP: {ip_address}"
                    if mac_address: 
                        output += f" - MAC: {mac_address}"
                    print(output)
                    file.write(output + "\n")
            else:
                print("Aucune interface active trouvée.")
                file.write("Aucune interface active trouvee.\n")
            # Affichage des interfaces down
            print("Les Interfaces down :")
            file.write("Les Interfaces down :\n")
            if interfaces_down:
                for intf in interfaces_down:
                    speed = interfaces_info.get(intf, "Indisponible")
                    ip_address = interfaces_ip.get(intf, "Aucune IP")
                    mac_address = interfaces_mac.get(intf)
                    output = f"{intf} - Vitesse: {speed} - IP: {ip_address}"
                    if mac_address:  
                        output += f" - MAC: {mac_address}"
                    print(output)
                    file.write(output + "\n")
            else:
                print("Aucune interface inactive trouvée.")
                file.write("Aucune interface inactive trouvee.\n")
        except Exception as e:
            print(f"Erreur lors de la récupération des informations des interfaces : {e}")
            file.write(f"Erreur lors de la recuperation des informations des interfaces : {e}")
            raise  
        
        # Récupération des informations ARP 
        try:
            print("\nInformations ARP :")
            file.write("\nInformations ARP :\n")
            # Exécuter la commande show arp
            arp_output = connection.send_command("show arp")
            # Afficher le résultat brut directement
            print(arp_output)
            file.write(arp_output + "\n")   
        except Exception as e:
            print(f"Erreur lors de la récupération des informations ARP : {e}")
            file.write(f"Erreur lors de la recuperation des informations ARP : {e}\n")  

        # Les routes Informations sur les routes 
        try:
            if not verifier_connexion(connection):
                raise Exception("Connexion perdue avec le routeur")
            print("\nInformations sur les routes :")
            file.write("\nInformations sur les routes :\n")
            print("Résumé des routes :")
            file.write("Resume des routes :\n")
            route_summary = connection.send_command("show route summary")
            if route_summary.strip():  # Vérifier si la sortie n'est pas vide
                print(route_summary)
                file.write(route_summary + "\n")
            else:
                print("Aucun résumé de route trouvé.")
                file.write("Aucun resume de route trouve.\n")
        except Exception as e:
            print(f"Erreur lors de la récupération des informations sur les routes : {e}")
            file.write(f"Erreur lors de la recuperation des informations sur les routes : {e}")
            raise  
        
        # Vérifier le protocol OSPF
        try:
            print("\nProtocole OSPF :")
            file.write("\nProtocole OSPF :\n")
            ospf_interfaces = connection.send_command("show ospf interface brief")
            if "OSPF instance is not running" in ospf_interfaces: 
                print("OSPF n'est pas configuré sur ce routeur.")
                file.write("OSPF n'est pas configure sur ce routeur.\n")
            else:
                print("Interfaces OSPF actives :")
                file.write("Interfaces OSPF actives :\n")
                print(ospf_interfaces)
                file.write(ospf_interfaces + "\n")
        except Exception as e:
            print(f"Erreur lors de la vérification du protocole OSPF : {e}")
            file.write(f"Erreur lors de la verification du protocole OSPF : {e}")  

        # Vérifier le protocol ISIS
        try:
            print("\nProtocole IS-IS :")
            file.write("\nProtocole IS-IS :\n")
            isis_adjacency = connection.send_command("show isis adjacency")
            if "IS-IS instance is not running" in isis_adjacency: 
                    print("IS-IS n'est pas configuré sur ce routeur.")
                    file.write("IS-IS n'est pas configure sur ce routeur.\n")
            else: 
                    print("Interfaces isis actives :")
                    file.write("Interfaces isis actives :\n")
                    print(isis_adjacency)
                    file.write(isis_adjacency + "\n")
        except Exception as e:
            print(f"Erreur lors de la vérification du protocole IS-IS : {e}")
            file.write(f"Erreur lors de la verification du protocole IS-IS : {e}")  

        # Vérifier le protocol MPLS
        try:
            print("\nProtocole MPLS :")
            file.write("\nProtocole MPLS :\n")
            mpls_interface = connection.send_command("show mpls interface")
            if "MPLS not configured" in mpls_interface: 
                    print("MPLS n'est pas configuré sur ce routeur.")
                    file.write("MPLS n'est pas configure sur ce routeur.\n")
            else: 
                    print("les interfaces  MPLS est activés. :")
                    file.write("les interfaces  MPLS  actives. :\n")
                    print(mpls_interface)
                    file.write(mpls_interface + "\n")
        except Exception as e:
            print(f"Erreur lors de la vérification du protocole MPLS : {e}")
            file.write(f"Erreur lors de la verification du protocole MPLS : {e}")  

        # verefier le protocol LDP
        try:
            print("\nProtcole LDP :")
            file.write("\nProtocole LDP :\n")
            ldp_session = connection.send_command("show ldp session")
            if "LDP instance is not running" in ldp_session: 
              print("LDP n'est pas configuré sur ce routeur.")
              file.write("LDP n'est pas configure sur ce routeur.\n")
            else :
                lignes = ldp_session.split('\n')
                resultat_filtre = []
                for ligne in lignes:
                    colonnes = ligne.split()
                    if len(colonnes) >= 5:  
                        ligne_filtree = f"{colonnes[0]:<15} {colonnes[1]:<12} {colonnes[2]:<12} {''.join(colonnes[4:])}"
                        resultat_filtre.append(ligne_filtree)
                    else:
                        resultat_filtre.append(ligne)
                output_final = "\n".join(resultat_filtre)
                print("Sessions LDP actives  :")
                file.write("Sessions LDP actives :\n")
                print(output_final)
                file.write(output_final + "\n")
        except Exception as e:
            print(f"Erreur lors de la vérification du protocole LDP : {e}")
            file.write(f"Erreur lors de la verification du protocole LDP : {e}\n")

        # Vérifier le protocol RSVP
        try:
            print("\nProtocole RSVP :")
            file.write("\nProtocole RSVP :\n")
            rsvp_interface = connection.send_command("show rsvp interface")
            if "RSVP not configured" in rsvp_interface: 
                    print("RSVP n'est pas configuré sur ce routeur.")
                    file.write("RSVP n'est pas configure sur ce routeur.\n")
            else: 
                    file.write("Interfaces configurees avec RSVP :\n")
                    print(rsvp_interface)
                    file.write(rsvp_interface + "\n")
        except Exception as e:
            print(f"Erreur lors de la vérification du protocole RSVP : {e}")
            file.write(f"Erreur lors de la verification du protocole RSVP : {e}")  
                                           
        # Vérifier le de protocol LLDP
        try:
            print("\nProtocole LLDP :")
            file.write("\nProtocole LLDP :\n")
            lldp_neigbors = connection.send_command("show lldp neighbor")
            if not lldp_neigbors.strip():  # Si la sortie est vide
                    print("LLDP n'est pas configuré ou aucun voisin n'a été détecté.")
                    file.write("LLDP n'est pas configure ou aucun voisin n'a ete detecte.\n")
            else:  # Si la sortie n'est pas vide
                    print("Voisins LLDP découverts :")
                    file.write("Voisins LLDP decouverts :\n")
                    print(lldp_neigbors)
                    file.write(lldp_neigbors + "\n")
        except Exception as e:
            print(f"Erreur lors de la vérification du protocole LLDP : {e}")
            file.write(f"Erreur lors de la verification du protocole LLDP : {e}")

        # Vérifier l'état des LSP
        try:
            print("\nProtocole LSP :")
            file.write("\nProtocole LSP :\n")
            mpls_lsp = connection.send_command("show mpls lsp")
            if "MPLS not configured" in mpls_lsp: 
                    print("Aucune session lsp trouvé.")
                    file.write("Aucune session lsp trouve.\n")
            else: 
                    print("statut des LSP :")
                    file.write("statut des LSP :\n")
                    print(mpls_lsp)
                    file.write(mpls_lsp + "\n")
        except Exception as e:
            print(f"Erreur lors de la vérification du protocole LSP : {e}")
            file.write(f"Erreur lors de la verification du protocole LSP : {e}")

        # Vérifier la base de protocol BGP
        try:
            print("\nProtocole BGP :")
            file.write("\nProtocole BGP :\n")
            bgp_summary= connection.send_command("show bgp summary ")
            if "BGP is not running" in bgp_summary: 
                    print("BGP n'est pas configuré sur ce routeur.")
                    file.write("BGP n'est pas configure sur ce routeur.\n")
            else:  
                    print(bgp_summary)
                    file.write(bgp_summary + "\n")
        except Exception as e:
            print(f"Erreur lors de la vérification du protocole BGP : {e}")
            file.write(f"Erreur lors de la verification du protocole BGP : {e}") 

        # Afficher les services configurés
        try:
            print("\nServices configurés :")
            file.write("\nServices configures :\n")
            output_services = connection.send_command("show configuration system services")
            services = set()  # Utiliser un ensemble pour éviter les doublons
            for line in output_services.splitlines():
                if line.strip().endswith(";"):  # Les services se terminent par un point-virgule
                    service_name = line.strip().rstrip(";")
                    services.add(service_name)
            for service in sorted(services):  # Trier les services par ordre alphabétique
                print(service)
                file.write(service + "\n")
        except Exception as e:
            print(f"Erreur lors de la récupération des services configurés : {e}")
            file.write(f"Erreur lors de la recuperation des services configures : {e}")  

        # Afficher les protocoles configurés
        try:
            print("\nProtocoles configurés :")
            file.write("\nProtocoles configures :\n")
            output_protocols = connection.send_command("show configuration protocols")
            protocols = set()  # Utiliser un ensemble pour éviter les doublons
            for line in output_protocols.splitlines():
                if "{" in line and not line.strip().startswith("}"):  # Les protocoles commencent par "{"
                    protocol_name = line.split("{")[0].strip()
                    protocols.add(protocol_name)
            for protocol in sorted(protocols):  # Trier les protocoles par ordre alphabétique
                print(protocol)
                file.write(protocol + "\n")
        except Exception as e:
            print(f"Erreur lors de la récupération des protocoles configurés : {e}")
            file.write(f"Erreur lors de la recuperation des protocoles configures : {e}")  


        # Vérifier les ACL configurées
        try:
            print("\nListes de Contrôle d'Accès (ACL) :")
            file.write("\nListes de Controle d'Acces (ACL) :\n")
            # Récupérer la configuration complète des filtres de pare-feu
            acl_output = connection.send_command("show configuration firewall")
            # Afficher et stocker la réponse brute de la commande
            if acl_output.strip():  # Vérifier si la sortie n'est pas vide
                print("Réponse de la commande 'show configuration firewall' :")
                file.write("Reponse de la commande 'show configuration firewall' :\n")
                print(acl_output)
                file.write(acl_output + "\n")
            else:
                print("Aucune ACL configurée trouvée.")
                file.write("Aucune ACL configuree trouvee.\n")
        except Exception as e:
            print(f"Erreur lors de la vérification des ACL configurées : {e}")
            file.write(f"Erreur lors de la verification des ACL configurees : {e}")  

        # Vérifier les logs des erreurs critiques
        try:
            if not verifier_connexion(connection):
                raise Exception("Connexion perdue avec le routeur")
            print("\nLogs des erreurs critiques :")
            file.write("\nLogs des erreurs critiques :\n")
            print("Logs des erreurs critiques dans 'messages' :")
            file.write("Logs des erreurs critiques dans 'messages' :\n")
            logs_messages = connection.send_command('show log messages | match "error|warning|critical" | last 10')
            # Filtrer les lignes indésirables
            filtered_logs = [line for line in logs_messages.splitlines() if not line.strip().startswith("---(more")]
            filtered_logs_str = "\n".join(filtered_logs)
            print(filtered_logs_str)
            file.write(filtered_logs_str + "\n")
        except Exception as e:
            print(f"Erreur lors de la récupération des logs des erreurs critiques dans 'messages' : {e}")
            file.write(f"Erreur lors de la recuperation des logs des erreurs critiques dans 'messages' : {e}")
            raise 
        try:
            if not verifier_connexion(connection):
                raise Exception("Connexion perdue avec le routeur")
            print("Logs des erreurs critiques dans 'chassisd' :")
            file.write("Logs des erreurs critiques dans 'chassisd' :\n")
            logs_chassisd = connection.send_command('show log chassisd | match "error|warning|critical" | last 10')
            # Filtrer les lignes indésirables
            filtered_logs = [line for line in logs_chassisd.splitlines() if not line.strip().startswith("---(more")]
            filtered_logs_str = "\n".join(filtered_logs)
            print(filtered_logs_str)
            file.write(filtered_logs_str + "\n")
        except Exception as e:
            print(f"Erreur lors de la récupération des logs des erreurs critiques dans 'chassisd' : {e}")
            file.write(f"Erreur lors de la recuperation des logs des erreurs critiques dans 'chassisd' : {e}")
            raise

        # Exécuter la commande pour afficher la configuration 
        try:
            if not verifier_connexion(connection):
                raise Exception("Connexion perdue avec le routeur")
            print("\nLa configuration totale :")
            file.write("\nLa configuration totale :\n")
            output = connection.send_command("show configuration | display set")
            print(output)
            file.write(output + "\n")
        except Exception as e:
            print(f"Erreur lors de la récupération de la configuration totale : {e}")
            file.write(f"Erreur lors de la recuperation de la configuration totale : {e}")
            raise  
    
    # Suppression du fichier d'identification
    try:
        if 'selected_file' in locals() and os.path.exists(selected_file):
            os.remove(selected_file)
    except Exception as e:
        print(f"\nErreur suppression fichier identification: {str(e)}")

    # Afficher des messages de confirmation
    try: 
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        file_path_txt = os.path.abspath(APRES)
        print(f"\nLes résultats des vérifications ont été enregistrés dans le fichier '{APRES}' à l'emplacement suivant : {file_path_txt}.")
    except Exception as e:
        print(f"\nErreur lors de l'affichage des chemins des fichiers : {e}")
        raise  

except Exception as e:
    print(f"\nUne erreur est survenue lors de l'exécution du script : {str(e)}")
    if "Socket is closed" in str(e) or "Connexion perdue" in str(e):
        print("La connexion au routeur a été interrompue.")
    # Nettoyage
    if 'fichiers_crees' in locals() and fichiers_crees:
        nettoyer_fichiers(fichiers_crees)
    if connection:
        connection.disconnect()
    # relancer le script
    while True:
        python_exec = sys.executable
        script_path = os.path.abspath(__file__)
        if ' ' in script_path:
            script_path = f'"{script_path}"'
        os.system(f"{python_exec} {script_path}")
        sys.exit(0)

finally:
    # Nettoyage final
    if connection:
        connection.disconnect() 

    # Comparaison
    # Utilisation de générateurs pour lire les fichiers ligne par ligne
    content_avant = read_file_by_line(AVANT)
    content_apres = read_file_by_line(APRES)
    # Extraction des sections avec traitement ligne par ligne
    sections_avant = extract_sections(content_avant)
    sections_apres = extract_sections(content_apres)
    if not sections_avant or not sections_apres:
        print("Erreur lors de la lecture des fichiers. Veuillez vérifier les fichiers d'entrée.", file=sys.stderr)
        sys.exit(1)
    differences = compare_sections(sections_avant, sections_apres)
    display_differences(differences)
    # Enregistrer les différences dans un fichier
    comparaison = f"COMPARAISON_{username}_{router_hostname}.txt"
    compteur = 1
    while os.path.exists(comparaison):
        comparaison = f"COMPARAISON_{username}_{router_hostname}_{compteur}.txt"
        compteur += 1
    write_differences_to_file(differences, comparaison)

    # Gestion des fichiers (AVANT, APRES, comparaison)
    print("\nPour libérer de l'espace, vous pouvez supprimer les fichiers générés. Confirmez pour chaque fichier :")
    fichiers_a_supprimer = []
    # Demande pour AVANT
    if 'AVANT' in locals() and AVANT and os.path.exists(AVANT):
        reponse = input(f"Souhaitez-vous supprimer le fichier ({AVANT}) ? (oui/non) : ").lower()
        if reponse in ['o', 'oui', 'y', 'yes']:
            fichiers_a_supprimer.append(AVANT)
    # Demande pour APRES
    if 'APRES' in locals() and APRES and os.path.exists(APRES):
        reponse = input(f"Souhaitez-vous supprimer le fichier  ({APRES}) ? (oui/non) : ").lower()
        if reponse in ['o', 'oui', 'y', 'yes']:
            fichiers_a_supprimer.append(APRES)
    # Demande pour le fichier de comparaison
    if 'comparaison' in locals() and comparaison and os.path.exists(comparaison):
        reponse = input(f"Souhaitez-vous supprimer le fichier ({comparaison}) ? (oui/non) : ").lower()
        if reponse in ['o', 'oui', 'y', 'yes']:
            fichiers_a_supprimer.append(comparaison)
    # Demande pour le fichier de configuration 
    if 'config_filename' in locals() and config_filename and os.path.exists(config_filename):
        reponse = input(f"Souhaitez-vous supprimer le fichier ({config_filename}) ? (oui/non) : ").lower()
        if reponse in ['o', 'oui', 'y', 'yes']:
            fichiers_a_supprimer.append(config_filename)
    # Suppression effective des fichiers
    if fichiers_a_supprimer:
        print("\nSuppression des fichiers :")
        for fichier in fichiers_a_supprimer:
            try:
                os.remove(fichier)
                print(f"- Le fichier {fichier} a été supprimé")
            except Exception as e:
                print(f"Erreur : Impossible de supprimer le fichier {fichier} : {e}.")