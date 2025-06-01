import os
import sys
import json
import time
import warnings
from pathlib import Path
from getpass import getpass
from netmiko import ConnectHandler
import ipaddress
import tempfile
import portalocker
import subprocess

# Fonction pour verrouiller le routeur
def verrouiller_routeur(ip):
    warnings.filterwarnings("ignore", category=UserWarning, module="portalocker.utils")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    LOCK_DIR = os.path.join(script_dir, "router_locks")
    Path(LOCK_DIR).mkdir(exist_ok=True, parents=True)
    ip_normalisee = ip.replace('.', '_')
    lock_file = os.path.join(LOCK_DIR, f"{ip_normalisee}.lock")
    # Vérifier si le verrou est déjà actif
    if os.path.exists(lock_file):
        try:
            test_lock = portalocker.Lock(lock_file, flags=portalocker.LOCK_EX | portalocker.LOCK_NB)
            test_lock.acquire()
            test_lock.release()  # Si acquis = le verrou était inactif
        except (portalocker.LockException, BlockingIOError):
            # Le verrou est déjà actif
            print(f"Le routeur {ip} est déjà verrouillé par un autre processus.")
            return None, None
        except Exception as e:
            print(f"Erreur lors du test du verrou : {e}")
            return None, None
    # Créer un nouveau verrou
    try:
        lock = portalocker.Lock(lock_file, flags=portalocker.LOCK_EX)
        lock.acquire(timeout=5)  # Timeout pour éviter un blocage infini
        return lock, lock_file
    except portalocker.LockException:
        print(f"Impossible de verrouiller le routeur {ip} (verrou occupé).")
        return None, None
    except Exception as e:
        print(f"Erreur lors du verrouillage : {e}")
        if os.path.exists(lock_file):
            os.remove(lock_file)  # Nettoyer le fichier orphelin
        return None, None
    
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
    
# Fonction pour lancer APRES.py
def lancer_apres(fichier_identifiants, max_tentatives=3):
    tentatives = 0
    python_exec = sys.executable
    script_apres = os.path.join(os.path.dirname(__file__), "APRES.py")
    while tentatives < max_tentatives:
        try:
            print(f"\nLancement de APRES.py")
            result = subprocess.run(
                [python_exec, "APRES.py", fichier_identifiants],
                check=True,
            )
            return True 
        except subprocess.CalledProcessError as e:
            tentatives += 1
            print(f"Erreur lors de l'exécution (Code {e.returncode}): {e.stderr.strip()}")
            if tentatives < max_tentatives:
                print("Nouvelle tentative...")
            else:
                print("Échec après plusieurs tentatives.")
                return False

# Boucle pour la connexion SSH
lock = None
lock_file = None
connection = None
fichiers_crees = [] 
AVANT = None
fichier_identifiants = None
try:
    while True:
        # Demander les informations de connexion
        ip = input("Veuillez entrer l'adresse IP du routeur : ")
        if not valider_ip(ip):
            print("Adresse IP invalide. Veuillez réessayer.")
            continue
        username = input("Veuillez entrer votre nom d'utilisateur : ")
        password = getpass("Veuillez entrer votre mot de passe : ")
        # Vérifier si le routeur est déjà verrouillé
        lock, lock_file = verrouiller_routeur(ip)
        if not lock:
            continue  # Redemander les informations si verrou échoué
        # Configuration du périphérique
        device = {
            'device_type': 'juniper',
            'host': ip,
            'username': username,
            'password': password,
            'timeout': 30, 
        } 
        try:
            # Établir la connexion
            connection = ConnectHandler(**device)
            # Vérification de la connexion
            if verifier_connexion(connection):
                print(f"\nConnecté avec succès au routeur {ip}")
                break
            else:
                print("Erreur de connexion. Veuillez réessayer.")
                connection.disconnect()
        except Exception as e:
            print(f"Erreur inattendue lors de la connexion : {str(e)}")
            if lock: lock.release()
            if lock_file and os.path.exists(lock_file): os.remove(lock_file)
            continue
        
    # Création du fichier temporaire
    temp_file = tempfile.NamedTemporaryFile(
        mode='w+',
        prefix='AVANT_',
        suffix='.txt',
        delete=False, 
        encoding='utf-8'
    )
    fichier_temporaire = temp_file.name
    fichiers_crees.append(fichier_temporaire)
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
    base_AVANT = f"AVANT_{username}_{router_hostname}.txt"
    AVANT = base_AVANT
    # Vérifier si le fichier final existe déjà et trouver un nom disponible
    compteur = 1
    while os.path.exists(AVANT):
        AVANT = f"AVANT_{username}_{router_hostname}_{compteur}.txt"
        compteur += 1
    try:
        # Vérifier que le fichier source existe
        if os.path.exists(fichier_temporaire):
            # Fermer explicitement le fichier s'il est ouvert
            if 'file' in locals() and not file.closed:
                file.close()
            # Renommer de manière atomique
            os.replace(fichier_temporaire, AVANT)
            # Mettre à jour la liste des fichiers créés
            fichiers_crees.remove(fichier_temporaire)
            fichiers_crees.append(AVANT)
        else:
            print("Avertissement : Le fichier temporaire a disparu")
            AVANT = fichier_temporaire
    except Exception as e:
        print(f"Erreur lors du renommage : {e}. Le fichier reste {fichier_temporaire}")
        AVANT = fichier_temporaire
        # Ajouter le fichier temporaire à la liste s'il n'y est pas déjà
        if fichier_temporaire not in fichiers_crees:
            fichiers_crees.append(fichier_temporaire)

    with open(AVANT, 'a', encoding='utf-8') as file:
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

        # Vérifier le protocol BGP
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


        # Vérifier filtrage de pare-feu 
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
            # Créer un fichier séparé pour la configuration avec gestion des doublons
            base_config_filename = f"CONFIGURATION_{username}_{router_hostname}.txt"
            config_filename = base_config_filename
            compteur_config = 1
            # Vérifier si le fichier existe déjà et trouver un nom disponible
            while os.path.exists(config_filename):
                config_filename = f"CONFIGURATION_{username}_{router_hostname}_{compteur_config}.txt"
                compteur_config += 1
            with open(config_filename, 'w', encoding='utf-8') as config_file:
                config_file.write(output)
            fichiers_crees.append(config_filename)
        except Exception as e:
            print(f"Erreur lors de la récupération de la configuration totale : {e}")
            file.write(f"Erreur lors de la recuperation de la configuration totale : {e}")
            raise
    
    # Sauvegarde des identifiants dans un fichier JSON (version sécurisée base64)
    fichier_identifiants = f"identifiants_{username}_{router_hostname}.json"
    try:
        data = {
            "ip":ip,
            "username": username,
            "lock_file": lock_file,
            "AVANT": AVANT,
            "config_filename": config_filename
        }
        with open(fichier_identifiants, "w") as f:
            json.dump(data, f, indent=2)
        fichiers_crees.append(fichier_identifiants)
    except Exception as e:
        print(f"Erreur lors de la sauvegarde sécurisée des identifiants: {e}")
        # Fallback vers fichier texte non sécurisé si JSON échoue
        fichier_identifiants = f"identifiants_{username}_{router_hostname}.txt"
        try:
            with open(fichier_identifiants, "w") as f:
                f.write("ATTENTION: Fichier non sécurisé (fallback)\n")
                f.write(f"IP: {ip}\n")
                f.write(f"Username: {username}\n")
                f.write(f"Fichier AVANT: {AVANT}\n")
                f.write(f"Lock file: {lock_file}\n")
                f.write(f"config file: {config_filename}\n")
            fichiers_crees.append(fichier_identifiants)
        except Exception as e:
            print(f"Échec complet de la sauvegarde des identifiants: {e}")

    # Afficher des messages de confirmation
    try: 
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        file_path_txt = os.path.abspath(AVANT)
        print(f"\nToutes les vérifications ont été stockées dans le fichier '{AVANT}' à l'emplacement suivant : {file_path_txt}.")
        file_path_json = os.path.abspath(fichier_identifiants)
        print(f"\nLes identifiants de connexion ont été sauvegardés dans le fichier '{fichier_identifiants}' à l'emplacement suivant : {file_path_json} pour référence future.")
        file_path_txt = os.path.abspath(config_filename)
        print(f"\nConfiguration complète sauvegardée dans le fichier: {config_filename}")
    except Exception as e:
        print(f"\nErreur lors de l'affichage des chemins des fichiers : {e}")
        raise   

    # MISE À JOUR
    if confirmation_box("Voulez-vous poursuivre la procédure de mise à jour ?"):
        #CONFIGURATION INITIALE DE LA MISE À JOUR
        while True:
            # Saisie et validation du nom du package
            image_file = input("Veuillez saisir le nom complet du package logiciel (format attendu : jinstall-ppc-<VERSION>-signed.tgz) : ").strip()
            if not image_file:
                print("Erreur: Vous devez spécifier un nom de package.")
                continue
            prefix = "jinstall-ppc-"
            suffix = "-signed.tgz"
            if prefix not in image_file or suffix not in image_file:
                print("Format de fichier incorrect. Attendu: jinstall-ppc-<VERSION>-signed.tgz")
                continue
            # Vérification de la présence du package sur le routeur
            print(f"\nVérification de la présence du package {image_file} sur le routeur...")
            try:
                output_re0 = connection.send_command(f"file list re0:/var/tmp/{image_file}")
                output_re1 = connection.send_command(f"file list re1:/var/tmp/{image_file}")
                if "No such file or directory" in output_re0 or "No such file or directory" in output_re1:
                    print(f"\nLe package {image_file} est introuvable !")
                    print("Veuillez choisir parmi les alternatives suivantes :")
                    print("1. Entrer un nouveau nom de package")
                    print("2. Abandonner la procédure de mise à jour")
                    choice = input("Votre choix (1/2): ").strip()
                    if choice == '2':
                        print("Interruption de la procédure à la demande de l'utilisateur")
                        sys.exit(0)
                    continue
                # Confirmation de l'utilisation du package
                confirm = input(f"Confirmez-vous l'utilisation de {image_file} pour la mise à jour? (oui/non): ").lower()
                if confirm not in ['oui']:
                    print("Saisie non confirmée, veuillez réessayer")
                    continue
                break
            except Exception as e:
                print(F"\nUne erreur est survenue pendant la vérification : {str(e)}")
                print("Veuillez choisir parmi les alternatives suivantes :")
                print("1. Recommencer la procédure de mise à jour")
                print("2. Abandonner la procédure")
                choice = input("Votre choix (1/2): ").strip()
                if choice == '2':
                    print("Interruption de la procédure à la demande de l'utilisateur")
                    sys.exit(0)
                continue
        # DÉSACTIVATION DES FONCTIONNALITÉS HA 
        print("\nDésactivation des fonctionnalités de haute disponibilité...")
        try:
            connection.config_mode()
            commands = [
                "deactivate chassis redundancy",
                "deactivate routing-options nonstop-routing",
                "deactivate system commit synchronize",
                "set system processes clksyncd-service disable"
            ]
            for cmd in commands:
                output = connection.send_command(cmd, read_timeout=30)
                if "error" in output.lower() or "unknown command" in output.lower():
                    print(f"UPDATE ERREUR: Commande HA '{cmd}' échouée: {output}")
                    try: connection.exit_config_mode()
                    except: pass
            commit_output = connection.commit(comment="HA features update via API", read_timeout=300, and_quit=False)
            commit_output = connection.send_command("commit synchronize", read_timeout=300)
            if "commit complete" not in commit_output.lower(): 
                print(f"'commit synchronize' pour HA a échoué ou a eu une réponse inattendue: {commit_output}")
                try: connection.exit_config_mode()
                except: pass
            connection.exit_config_mode()
            print("✓ Configuration de haute disponibilité désactivée avec succès")
        except Exception as e:
            print(f"✗ Erreur lors de la désactivation des fonctionnalités HA: {str(e)}")
            raise
        # MISE À JOUR DE RE1
        print("\nMise à jour de RE1...")
        try:
            print("Établissement de la connexion à RE1...")
            connection.write_channel("request routing-engine login other-routing-engine\n")
            time.sleep(30)
            print("✓ Connexion à RE1 établie avec succès")
            print("Installation du nouveau logiciel sur RE1...")
            connection.write_channel(f"request system software add /var/tmp/{image_file} no-validate\n") 
            time.sleep(30)
            # REDÉMARRAGE DE RE1
            print("Lancement du redémarrage de RE1...")
            connection.write_channel("request system reboot\n")
            time.sleep(10)
            connection.write_channel("yes\n")
            time.sleep(60)
            print("✓ Redémarrage de RE1 initié avec succès")
        except Exception as e:
            print(f"✗ Erreur lors de la mise à jour de RE1: {str(e)}")
            raise
        # VÉRIFICATION DU REDÉMARRAGE DE RE1
        print("\n Validation du redémarrage de RE1")
        start_time = time.time()
        timeout = 900  # 15 minutes en secondes
        re1_ready = False
        connection.remote_conn.settimeout(15)  # Timeout de lecture plus long
        output_buffer = ""
        try:
            connection.write_channel("show chassis routing-engine |refresh | match Current\n")
            while (time.time() - start_time) < timeout:
                # Lire le flux de sortie
                chunk = connection.read_channel()
                if chunk:
                    output_buffer += chunk
                    # Afficher en temps réel
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                    # Vérifier les états attendus
                    if "Backup" in output_buffer:
                        re1_ready = True
                        connection.write_channel(chr(3)) 
                        time.sleep(1)
                        connection.clear_buffer()
                        print("\n✓ RE1 a terminé son redémarrage.")
                        break
                else:
                    time.sleep(1)  # Pause courte si pas de données
            if not re1_ready:
                raise Exception("15 minutes dépassé - RE1 n'a pas restauré son état opérationnel")
        except Exception as e:
            print(f"\n✗ Erreur lors de la vérification du redémarrage de RE1: {str(e)}")
            connection.write_channel(chr(3))
            time.sleep(1)
            connection.clear_buffer()
            raise
        # VÉRIFICATION DE LA VERSION SUR RE1
        print("\nVérification de la version sur RE1...")
        try:
            # Récupérer la version sur RE1
            version_output = connection.send_command("show version invoke-on other-routing-engine | match \"Junos:\"")
            # Extraire la version 
            current_version = version_output.split("Junos:")[1].strip()
            # Extraire la version attendue du nom du package 
            prefix = "jinstall-ppc-"
            suffix = "-signed.tgz"
            expected_version = image_file.split(prefix)[1].split(suffix)[0]
            print(f"\nVersion actuelle sur RE1: {current_version}")
            print(f"Version attendue: {expected_version}")
            if current_version == expected_version:
                print("✓ La version sur RE1 correspond à la version attendue")
            else:
                raise Exception(f"ERREUR: La version sur RE1 ({current_version}) ne correspond pas à la version attendue ({expected_version})")
        except Exception as e:
            print(f"\n✗ Erreur lors de la vérification de version: {str(e)}")
            raise
        # BASCULEMENT VERS RE1
        print("\nBasculement vers RE1...")
        try:
            # Envoyer la commande de basculement
            switch_q_out = connection.send_command("request chassis routing-engine master switch", expect_string=r"Toggle mastership between routing engines", strip_prompt=False, strip_command=False, read_timeout=30)
            connection.write_channel("yes\n")
            time.sleep(10)
            # Fermer proprement la connexion actuelle
            connection.disconnect()
            # Attendre que le basculement soit effectif (temps estimé)
            print("Basculement en cours - attente de 5 minutes...")
            time.sleep(300)
            # Reconnexion au routeur
            print("Tentative de reconnexion après basculement...")
            for attempt in range(1, 6):  # 5 tentatives max
                try:
                    # Réétablir la connexion directe au routeur
                    connection = ConnectHandler(**device)
                    # Vérifier le nouvel état
                    re_status = connection.send_command("show chassis routing-engine")
                    lines = re_status.split('\n')
                    slot1_index = None
                    for i, line in enumerate(lines):
                        if "Slot 1" in line:
                            slot1_index = i
                            break
                    if slot1_index is not None and slot1_index + 1 < len(lines):
                        next_line = lines[slot1_index + 1]
                        if "Current state" in next_line and "Master" in next_line:
                            print("✓ Basculement vers RE1 réussi")
                            break
                        else:
                            raise Exception("RE1 n'est pas dans l'état Master")
                    else:
                        raise Exception("Slot 1 non trouvé dans la sortie")
                except Exception as e:
                    print(f"Tentative {attempt}/5 échouée: {str(e)}")
                    if attempt < 5:
                        print("Nouvelle tentative dans 1 minute...")
                        time.sleep(60)
                    else:
                        raise Exception("Échec de reconnexion après basculement")
        except Exception as e:
            print(f"\n✗ Erreur lors du basculement vers RE1: {str(e)}")
            raise
        # MISE À JOUR DE RE0 
        print("\nMise à jour de RE0...")
        try:
            print("Établissement de la connexion à RE0...")
            connection.write_channel("request routing-engine login other-routing-engine\n")
            time.sleep(30)
            print("✓ Connexion à RE0 établie avec succès")
            print("Installation du nouveau logiciel sur RE0...")
            connection.write_channel(f"request system software add /var/tmp/{image_file} no-validate\n") 
            time.sleep(30)
            print("✓ Logiciel installé avec succès sur RE0")
            # REDÉMARRAGE DE RE1
            print("Lancement du redémarrage de RE0...")
            connection.write_channel("request system reboot\n")
            time.sleep(10)
            connection.write_channel("yes\n")
            time.sleep(60)
            print("✓ Redémarrage de RE0 initié avec succès")
        except Exception as e:
            print(f"✗ Erreur lors de la mise à jour de RE0: {str(e)}")
            raise
        # VÉRIFICATION DU REDÉMARRAGE DE RE0 
        print("\nValidation du redémarrage de RE0")
        start_time = time.time()
        timeout = 900  # 15 minutes en secondes
        re0_ready = False
        connection.remote_conn.settimeout(15)  # Timeout de lecture plus long
        output_buffer = ""
        try:
            # Envoyer la commande de vérification
            connection.write_channel("show chassis routing-engine |refresh | match Current\n")
            while (time.time() - start_time) < timeout:
                # Lire le flux de sortie
                chunk = connection.read_channel()
                if chunk:
                    output_buffer += chunk
                    # Afficher en temps réel
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                    # Vérifier si on a les deux états (Master et Backup)
                    if "Backup" in output_buffer:
                        re0_ready = True
                        connection.write_channel(chr(3)) 
                        time.sleep(1)
                        connection.clear_buffer()
                        print("\n✓ RE0 a terminé son redémarrage.")
                        break
                else:
                    time.sleep(1)  # Pause courte si pas de données
            if not re0_ready:
                raise Exception("15 minutes dépassé - RE0 n'a pas restauré son état opérationnel")   
        except Exception as e:
            print(f"\n✗ Erreur lors de la vérification du redémarrage de RE0: {str(e)}")
            connection.write_channel(chr(3))
            time.sleep(1)
            connection.clear_buffer()
            raise
        # VÉRIFICATION DE LA VERSION SUR RE0
        print("\nVérification de la version sur RE0...")
        try:
            # Récupérer la version sur RE0 (maintenant que RE1 est master)
            version_output = connection.send_command("show version invoke-on other-routing-engine | match \"Junos:\"")
            # Extraire la version 
            current_version = version_output.split("Junos:")[1].strip()
            # Extraire la version attendue du nom du package 
            prefix = "jinstall-ppc-"
            suffix = "-signed.tgz"
            expected_version = image_file.split(prefix)[1].split(suffix)[0]
            print(f"\nVersion actuelle sur RE0: {current_version}")
            print(f"Version attendue: {expected_version}")
            if current_version == expected_version:
                print("✓ La version sur RE0 correspond à la version attendue")
            else:
                raise Exception(f"ERREUR: La version sur RE0 ({current_version}) ne correspond pas à la version attendue ({expected_version})")
        except Exception as e:
            print(f"\n✗ Erreur lors de la vérification de version: {str(e)}")
            raise
        # RÉACTIVATION HA 
        print("\nRéactivation des fonctionnalités de haute disponibilité...")
        try:
            connection.config_mode()
            commands = [
                "activate chassis redundancy",
                "activate routing-options nonstop-routing",
                "activate system commit synchronize",
                "delete system processes clksyncd-service disable"
            ]
            for cmd in commands:
                output = connection.send_command(cmd, read_timeout=30)
                if "error" in output.lower() or "unknown command" in output.lower():
                    print(f"UPDATE ERREUR: Commande HA '{cmd}' échouée: {output}")
                    try: connection.exit_config_mode()
                    except: pass
            commit_output = connection.commit(comment="HA features update via API", read_timeout=300, and_quit=False)
            commit_output = connection.send_command("commit synchronize", read_timeout=300)
            if "commit complete" not in commit_output.lower(): 
                print(f"'commit synchronize' pour HA a échoué ou a eu une réponse inattendue: {commit_output}")
                try: connection.exit_config_mode()
                except: pass
            connection.exit_config_mode()
            print("✓ Configuration de haute disponibilité activée avec succès")
        except Exception as e:
            print(f"✗ Erreur lors de la réactivation des fonctionnalités HA: {str(e)}")
            raise
        # BASCULEMENT FINAL VERS RE0
        print("\nRetour à la configuration d'origine : basculement final vers RE0...")
        try:
            # Envoyer la commande de basculement
            switch_q_out = connection.send_command("request chassis routing-engine master switch", expect_string=r"Toggle mastership between routing engines", strip_prompt=False, strip_command=False, read_timeout=30)
            connection.write_channel("yes\n")
            time.sleep(10)
            # Fermer proprement la connexion actuelle
            connection.disconnect()
            # Attendre que le basculement soit effectif (temps estimé)
            print("Basculement en cours - attente de 5 minutes...")
            time.sleep(300)
            # Reconnexion au routeur
            print("Tentative de reconnexion après basculement final...")
            for attempt in range(1, 6):  # 5 tentatives max
                try:
                    # Réétablir la connexion directe au routeur
                    connection = ConnectHandler(**device)
                    # Vérifier le nouvel état
                    re_status = connection.send_command("show chassis routing-engine")
                    lines = re_status.split('\n')
                    slot1_index = None
                    for i, line in enumerate(lines):
                        if "Slot 0" in line:
                            slot1_index = i
                            break
                    if slot1_index is not None and slot1_index + 1 < len(lines):
                        next_line = lines[slot1_index + 1]
                        if "Current state" in next_line and "Master" in next_line:
                            print("✓ Basculement vers REO réussi")
                            break
                        else:
                            raise Exception("RE0 n'est pas dans l'état Master")
                    else:
                        raise Exception("Slot 0 non trouvé dans la sortie")
                except Exception as e:
                    print(f"Tentative {attempt}/5 échouée: {str(e)}")
                    if attempt < 5:
                        print("Nouvelle tentative dans 1 minute...")
                        time.sleep(60)
                    else:
                        raise Exception("Échec de reconnexion après basculement final")
        except Exception as e:
            print(f"\n✗ Erreur lors du basculement final vers RE0: {str(e)}")
            raise
        print("✓ Procédure de mise à jour terminée avec succès")
    else:
        print("Interruption de la procédure à la demande de l'utilisateur")
        sys.exit(0)
    
except Exception as e:
    print(f"\nUne erreur s'est produite pendant l'exécution du script : {str(e)}")
    if "Socket is closed" in str(e) or "Connexion perdue" in str(e):
        print("La connexion avec le routeur a été interrompue.")
    # Nettoyage avant relance
    if 'fichiers_crees' in locals() and fichiers_crees:
        nettoyer_fichiers(fichiers_crees, lock, lock_file)
    if connection:
        connection.disconnect()
    # Demander si l'utilisateur veut relancer le script
    if confirmation_box("Voulez-vous relancer la partie avant?"):
        # Solution robuste pour relancer le script
        python_exec = sys.executable
        script_path = os.path.abspath(__file__)
        if ' ' in script_path:
            script_path = f'"{script_path}"'
        os.system(f"{python_exec} {script_path}")
        sys.exit(0)

finally:
    # Lancer APRES.py
    if confirmation_box("Voulez-vous lancer la partie aprés?"):
        try: 
            lancer_apres(fichier_identifiants)
        except Exception as e:
            print(f"Échec critique. Exécutez APRES.py manuellement avec : APRES.py {fichier_identifiants}") 
    else:
        if 'fichiers_crees' in locals() and fichiers_crees:
            nettoyer_fichiers(fichiers_crees, lock, lock_file)
    # Statut du verrou
    if lock:
        try:
            lock.release()
            print("Verrou libere avec succes")
        except Exception as e:
            print(f"Probleme lors de la liberation du verrou : {e}")
    # Suppression du fichier de verrou
    if lock_file and os.path.exists(lock_file):
        try:
            os.remove(lock_file)
            print(f"Fichier de verrou supprime avec succes")
        except Exception as e:
            print(f"Impossible de supprimer le fichier de verrou : {e}")
    else:
        print("Aucun fichier de verrou trouve")
    # Nettoyage final
    if connection:
        connection.disconnect()