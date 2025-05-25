from common_utils import verifier_connexion # Assuming verifier_connexion is in common_utils
import os

# Each function will:
# 1. Verify connection.
# 2. Print section header to console and write to file_handle.
# 3. Send command(s).
# 4. Process output, print to console, write to file_handle.
# 5. Handle specific errors, print to console, write to file_handle, and raise Exception for critical errors.

def collect_basic_info(connection, file_handle):
    junos_version = "inconnu"
    router_model = "inconnu"
    router_hostname = "inconnu"
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur avant récupération des infos de base")
        
        print("\nInformations de base du routeur :")
        file_handle.write("Informations de base du routeur :\n")
        output = connection.send_command('show version', read_timeout=20)

        for line in output.splitlines():
            if line.startswith("Hostname:"):
                router_hostname = line.split("Hostname:", 1)[1].strip()
                print(f"Le hostname du routeur est : {router_hostname}")
                file_handle.write(f"Le hostname du routeur est : {router_hostname}\n")
            elif line.startswith("Model:"):
                router_model = line.split("Model:", 1)[1].strip()
                print(f"Le modèle du routeur est : {router_model}")
                file_handle.write(f"Le modele du routeur est : {router_model}\n")
            elif "Junos:" in line and not line.strip().startswith("JUNOS "): # Avoid "JUNOS Base OS boot"
                # More robustly find Junos version line
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "Junos:":
                        if i + 1 < len(parts):
                            junos_version = parts[i+1].strip().split('[')[0] # Get version before brackets
                            break
                if junos_version != "inconnu":
                    print(f"La version du système Junos est : {junos_version}")
                    file_handle.write(f"La version du systeme Junos est : {junos_version}\n")
        
        if router_hostname == "inconnu" and router_model == "inconnu" and junos_version == "inconnu":
             file_handle.write("Impossible de parser les informations de base du routeur à partir de la sortie.\n")
             print("Avertissement: Impossible de parser les informations de base du routeur.")


    except Exception as e:
        error_msg = f"Erreur lors de la récupération des informations de base du routeur : {str(e)}"
        print(error_msg)
        file_handle.write(f"\n{error_msg}\n")
        junos_version = "inconnu"
        router_model = "inconnu"
        router_hostname = "inconnu"
        # Do not raise here if we want to attempt other collections, but hostname is critical
        if router_hostname == "":
             raise Exception("Récupération du hostname échouée, critique pour la suite.") from e
    return router_hostname, router_model, junos_version


def collect_routing_engine_info(connection, file_handle):
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        print("\nInformations du moteur de routage :")
        file_handle.write("\nInformations du moteur de routage :\n")
        routing_engine_output = connection.send_command("show chassis routing-engine", read_timeout=20)
        print(routing_engine_output)
        file_handle.write(routing_engine_output + "\n")
    except Exception as e:
        msg = f"Erreur lors de la récupération des informations du moteur de routage : {e}"
        print(msg)
        file_handle.write(msg + "\n")
        raise

def collect_interface_info(connection, file_handle):
    try:
        if not verifier_connexion(connection):
                raise Exception("Connexion perdue avec le routeur")
        print("\nInformations sur les interfaces :")
        file_handle.write("\nInformations sur les interfaces :\n")
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
        file_handle.write("Les Interfaces up :\n")
        if interfaces_up:
            for intf in interfaces_up:
                speed = interfaces_info.get(intf, "Indisponible")
                ip_address = interfaces_ip.get(intf, "Aucune IP")
                mac_address = interfaces_mac.get(intf)
                output = f"{intf} - Vitesse: {speed} - IP: {ip_address}"
                if mac_address: 
                    output += f" - MAC: {mac_address}"
                print(output)
                file_handle.write(output + "\n")
        else:
            print("Aucune interface active trouvée.")
            file_handle.write("Aucune interface active trouvee.\n")
        # Affichage des interfaces down
        print("Les Interfaces down :")
        file_handle.write("Les Interfaces down :\n")
        if interfaces_down:
            for intf in interfaces_down:
                speed = interfaces_info.get(intf, "Indisponible")
                ip_address = interfaces_ip.get(intf, "Aucune IP")
                mac_address = interfaces_mac.get(intf)
                output = f"{intf} - Vitesse: {speed} - IP: {ip_address}"
                if mac_address:  
                    output += f" - MAC: {mac_address}"
                print(output)
                file_handle.write(output + "\n")
        else:
            print("Aucune interface inactive trouvée.")
            file_handle.write("Aucune interface inactive trouvee.\n")
            
    except Exception as e:
        msg = f"Erreur lors de la récupération des informations des interfaces : {e}"
        print(msg)
        file_handle.write(msg + "\n")
        raise

def collect_arp_info(connection, file_handle):
    try:
        print("\nInformations ARP :")
        file_handle.write("\nInformations ARP :\n")
        # Exécuter la commande show arp
        arp_output = connection.send_command("show arp")
        # Afficher le résultat brut directement
        print(arp_output)
        file_handle.write(arp_output + "\n")   
    except Exception as e:
        print(f"Erreur lors de la récupération des informations ARP : {e}")
        file_handle.write(f"Erreur lors de la recuperation des informations ARP : {e}\n")

def collect_route_summary(connection, file_handle):
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        print("\nInformations sur les routes :")
        file_handle.write("\nInformations sur les routes :\n")
        print("Résumé des routes :")
        file_handle.write("Resume des routes :\n")
        route_summary = connection.send_command("show route summary")
        if route_summary.strip():  # Vérifier si la sortie n'est pas vide
            print(route_summary)
            file_handle.write(route_summary + "\n")
        else:
            print("Aucun résumé de route trouvé.")
            file_handle.write("Aucun resume de route trouve.\n")
    except Exception as e:
        print(f"Erreur lors de la récupération des informations sur les routes : {e}")
        file_handle.write(f"Erreur lors de la recuperation des informations sur les routes : {e}")
        raise 

def collect_ospf_info(connection, file_handle):
    try:
            print("\nProtocole OSPF :")
            file_handle.write("\nProtocole OSPF :\n")
            ospf_interfaces = connection.send_command("show ospf interface brief")
            if "OSPF instance is not running" in ospf_interfaces: 
                print("OSPF n'est pas configuré sur ce routeur.")
                file_handle.write("OSPF n'est pas configure sur ce routeur.\n")
            else:
                print("Interfaces OSPF actives :")
                file_handle.write("Interfaces OSPF actives :\n")
                print(ospf_interfaces)
                file_handle.write(ospf_interfaces + "\n")
    except Exception as e:
        print(f"Erreur lors de la vérification du protocole OSPF : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole OSPF : {e}")
        # Non-critical

def collect_isis_info(connection, file_handle):
    try:
        print("\nProtocole IS-IS :")
        file_handle.write("\nProtocole IS-IS :\n")
        isis_adjacency = connection.send_command("show isis adjacency")
        if "IS-IS instance is not running" in isis_adjacency: 
            print("IS-IS n'est pas configuré sur ce routeur.")
            file_handle.write("IS-IS n'est pas configure sur ce routeur.\n")
        else: 
            print("Interfaces isis actives :")
            file_handle.write("Interfaces isis actives :\n")
            print(isis_adjacency)
            file_handle.write(isis_adjacency + "\n")
    except Exception as e:
        print(f"Erreur lors de la vérification du protocole IS-IS : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole IS-IS : {e}")
        # Non-critical

def collect_mpls_info(connection, file_handle):
    try:
        print("\nProtocole MPLS :")
        file_handle.write("\nProtocole MPLS :\n")
        mpls_interface = connection.send_command("show mpls interface")
        if "MPLS not configured" in mpls_interface: 
            print("MPLS n'est pas configuré sur ce routeur.")
            file_handle.write("MPLS n'est pas configure sur ce routeur.\n")
        else: 
            print("les interfaces  MPLS est activés. :")
            file_handle.write("les interfaces  MPLS  actives. :\n")
            print(mpls_interface)
            file_handle.write(mpls_interface + "\n")
    except Exception as e:
        print(f"Erreur lors de la vérification du protocole MPLS : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole MPLS : {e}") 
    # Non-critical

def collect_ldp_info(connection, file_handle):
    try:
        print("\nProtcole LDP :")
        file_handle.write("\nProtocole LDP :\n")
        ldp_session = connection.send_command("show ldp session")
        if "LDP instance is not running" in ldp_session: 
            print("LDP n'est pas configuré sur ce routeur.")
            file_handle.write("LDP n'est pas configure sur ce routeur.\n")
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
            file_handle.write("Sessions LDP actives :\n")
            print(output_final)
            file_handle.write(output_final + "\n")
    except Exception as e:
        print(f"Erreur lors de la vérification du protocole LDP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole LDP : {e}\n")

def collect_rsvp_info(connection, file_handle):
    try:
        print("\nProtocole RSVP :")
        file_handle.write("\nProtocole RSVP :\n")
        rsvp_interface = connection.send_command("show rsvp interface")
        if "RSVP not configured" in rsvp_interface: 
            print("RSVP n'est pas configuré sur ce routeur.")
            file_handle.write("RSVP n'est pas configure sur ce routeur.\n")
        else: 
            file_handle.write("Interfaces configurees avec RSVP :\n")
            print(rsvp_interface)
            file_handle.write(rsvp_interface + "\n")
    except Exception as e:
        print(f"Erreur lors de la vérification du protocole RSVP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole RSVP : {e}")

def collect_lldp_info(connection, file_handle):
    try:
        print("\nProtocole LLDP :")
        file_handle.write("\nProtocole LLDP :\n")
        lldp_neigbors = connection.send_command("show lldp neighbor")
        if not lldp_neigbors.strip():  # Si la sortie est vide
            print("LLDP n'est pas configuré ou aucun voisin n'a été détecté.")
            file_handle.write("LLDP n'est pas configure ou aucun voisin n'a ete detecte.\n")
        else:  # Si la sortie n'est pas vide
            print("Voisins LLDP découverts :")
            file_handle.write("Voisins LLDP decouverts :\n")
            print(lldp_neigbors)
            file_handle.write(lldp_neigbors + "\n")
    except Exception as e:
        print(f"Erreur lors de la vérification du protocole LLDP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole LLDP : {e}")
    # Non-critical

def collect_lsp_info(connection, file_handle):
    try:
        print("\nProtocole LSP :")
        file_handle.write("\nProtocole LSP :\n")
        mpls_lsp = connection.send_command("show mpls lsp")
        if "MPLS not configured" in mpls_lsp: 
            print("Aucune session lsp trouvé.")
            file_handle.write("Aucune session lsp trouve.\n")
        else: 
            print("statut des LSP :")
            file_handle.write("statut des LSP :\n")
            print(mpls_lsp)
            file_handle.write(mpls_lsp + "\n")
    except Exception as e:
        print(f"Erreur lors de la vérification du protocole LSP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole LSP : {e}")
    # Non-critical

def collect_bgp_info(connection, file_handle):
    try:
        print("\nProtocole BGP :")
        file_handle.write("\nProtocole BGP :\n")
        bgp_summary= connection.send_command("show bgp summary ")
        if "BGP is not running" in bgp_summary: 
            print("BGP n'est pas configuré sur ce routeur.")
            file_handle.write("BGP n'est pas configure sur ce routeur.\n")
        else:  
            print(bgp_summary)
            file_handle.write(bgp_summary + "\n")
    except Exception as e:
        print(f"Erreur lors de la vérification du protocole BGP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole BGP : {e}") 
    # Non-critical

def collect_system_services(connection, file_handle):
    try:
        print("\nServices configurés :")
        file_handle.write("\nServices configures :\n")
        output_services = connection.send_command("show configuration system services")
        services = set()  # Utiliser un ensemble pour éviter les doublons
        for line in output_services.splitlines():
            if line.strip().endswith(";"):  # Les services se terminent par un point-virgule
                service_name = line.strip().rstrip(";")
            services.add(service_name)
        for service in sorted(services):  # Trier les services par ordre alphabétique
            print(service)
            file_handle.write(service + "\n")
    except Exception as e:
        print(f"Erreur lors de la récupération des services configurés : {e}")
        file_handle.write(f"Erreur lors de la recuperation des services configures : {e}")
    

def collect_configured_protocols(connection, file_handle):
    try:
        print("\nProtocoles configurés :")
        file_handle.write("\nProtocoles configures :\n")
        output_protocols = connection.send_command("show configuration protocols")
        protocols = set()  # Utiliser un ensemble pour éviter les doublons
        for line in output_protocols.splitlines():
            if "{" in line and not line.strip().startswith("}"):  # Les protocoles commencent par "{"
                protocol_name = line.split("{")[0].strip()
                protocols.add(protocol_name)
        for protocol in sorted(protocols):  # Trier les protocoles par ordre alphabétique
            print(protocol)
            file_handle.write(protocol + "\n")
    except Exception as e:
        print(f"Erreur lors de la récupération des protocoles configurés : {e}")
        file_handle.write(f"Erreur lors de la recuperation des protocoles configures : {e}") 


def collect_firewall_acls(connection, file_handle):
    try:
        print("\nListes de Contrôle d'Accès (ACL) :")
        file_handle.write("\nListes de Controle d'Acces (ACL) :\n")
        # Récupérer la configuration complète des filtres de pare-feu
        acl_output = connection.send_command("show configuration firewall")
        # Afficher et stocker la réponse brute de la commande
        if acl_output.strip():  # Vérifier si la sortie n'est pas vide
            print("Réponse de la commande 'show configuration firewall' :")
            file_handle.write("Reponse de la commande 'show configuration firewall' :\n")
            print(acl_output)
            file_handle.write(acl_output + "\n")
        else:
            print("Aucune ACL configurée trouvée.")
            file_handle.write("Aucune ACL configuree trouvee.\n")
    except Exception as e:
        print(f"Erreur lors de la vérification des ACL configurées : {e}")
        file_handle.write(f"Erreur lors de la verification des ACL configurees : {e}")


def collect_critical_logs(connection, file_handle):
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        print("\nLogs des erreurs critiques :")
        file_handle.write("\nLogs des erreurs critiques :\n")
        print("Logs des erreurs critiques dans 'messages' :")
        file_handle.write("Logs des erreurs critiques dans 'messages' :\n")
        logs_messages = connection.send_command('show log messages | match "error|warning|critical" | last 10')
        # Filtrer les lignes indésirables
        filtered_logs = [line for line in logs_messages.splitlines() if not line.strip().startswith("---(more")]
        filtered_logs_str = "\n".join(filtered_logs)
        print(filtered_logs_str)
        file_handle.write(filtered_logs_str + "\n")
    except Exception as e:
        print(f"Erreur lors de la récupération des logs des erreurs critiques dans 'messages' : {e}")
        file_handle.write(f"Erreur lors de la recuperation des logs des erreurs critiques dans 'messages' : {e}")
        raise 
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        print("Logs des erreurs critiques dans 'chassisd' :")
        file_handle.write("Logs des erreurs critiques dans 'chassisd' :\n")
        logs_chassisd = connection.send_command('show log chassisd | match "error|warning|critical" | last 10')
        # Filtrer les lignes indésirables
        filtered_logs = [line for line in logs_chassisd.splitlines() if not line.strip().startswith("---(more")]
        filtered_logs_str = "\n".join(filtered_logs)
        print(filtered_logs_str)
        file_handle.write(filtered_logs_str + "\n")
    except Exception as e:
        print(f"Erreur lors de la récupération des logs des erreurs critiques dans 'chassisd' : {e}")
        file_handle.write(f"Erreur lors de la recuperation des logs des erreurs critiques dans 'chassisd' : {e}")
        raise

def collect_full_configuration(connection, file_handle, username, router_hostname_for_filename):
    config_filename = None # Initialize
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        print("\nLa configuration totale :")
        file_handle.write("\nLa configuration totale :\n")
        output = connection.send_command("show configuration | display set")
        print(output)
        file_handle.write(output + "\n")
        
        base_config_filename = f"CONFIGURATION_{username}_{router_hostname_for_filename}.txt"
        config_filename = base_config_filename
        compteur_config = 1
        while os.path.exists(config_filename):
            config_filename = f"CONFIGURATION_{username}_{router_hostname_for_filename}_{compteur_config}.txt"
            compteur_config += 1
        
        with open(config_filename, 'w', encoding='utf-8') as config_file_handle:
            config_file_handle.write(output)
        print(f"Configuration complète sauvegardée dans : {config_filename}")
        return config_filename # Return the name of the created config file
        
    except Exception as e:
        msg = f"Erreur lors de la récupération de la configuration totale : {e}"
        print(msg)
        file_handle.write(msg + "\n")
        # This is a critical collection, so re-raise
        raise