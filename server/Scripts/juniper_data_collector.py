from common_utils import verifier_connexion, fetch_and_store
import parsers
import os

logs = []  # Global log list to collect logs from all functions

# Each function will:
# 1. Verify connection.
# 2. Print section header to console and write to file_handle.
# 3. Send command(s).
# 4. Process output, logs.append to console, write to file_handle.
# 5. Handle specific errors, logs.append to console, write to file_handle, and raise Exception for critical errors.




def collect_basic_info(connection, file_handle, structured_output_data, logs):
    key = 'basic_info'
    cmd = 'show version'
    junos_version = "inconnu"
    router_model = "inconnu"
    router_hostname = "inconnu"
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur avant récupération des infos de base")
        
        logs.append("\nInformations de base du routeur :")
        file_handle.write("Informations de base du routeur :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_basic_info)
        for line in output.splitlines():
            if line.startswith("Hostname:"):
                router_hostname = line.split("Hostname:")[1].strip()
                logs.append(f"Le hostname du routeur est : {router_hostname}")
                file_handle.write(f"Le hostname du routeur est : {router_hostname}\n")
            elif line.startswith("Model:"):
                router_model = line.split("Model:")[1].strip()
                logs.append(f"Le modèle du routeur est : {router_model}")
                file_handle.write(f"Le modele du routeur est : {router_model}\n")
            elif line.startswith("Junos:"):
                junos_version = line.split("Junos:")[1].strip()
                logs.append(f"La version du système Junos est : {junos_version}")
                file_handle.write(f"La version du systeme Junos est : {junos_version}\n")
        if router_hostname == "inconnu" and router_model == "inconnu" and junos_version == "inconnu":
            file_handle.write("Impossible de parser les informations de base du routeur à partir de la sortie.\n")
            logs.append("Avertissement: Impossible de parser les informations de base du routeur.")
    except Exception as e:
        error_msg = f"Erreur lors de la récupération des informations de base du routeur : {str(e)}"
        logs.append(error_msg)
        file_handle.write(f"\n{error_msg}\n")
        structured_output_data[key] = error_msg
        junos_version = "inconnu"
        router_model = "inconnu"
        router_hostname = "inconnu"
        # Do not raise here if we want to attempt other collections, but hostname is critical
        if router_hostname == "":
             raise Exception("Récupération du hostname échouée, critique pour la suite.") from e
    return router_hostname, router_model, junos_version


def collect_routing_engine_info(connection, file_handle, structured_output_data, logs):
    key = 'routing_engine'
    cmd = 'show chassis routing-engine'
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        logs.append("\nInformations du moteur de routage :")
        file_handle.write("\nInformations du moteur de routage :\n")
        routing_engine_output = fetch_and_store(connection, structured_output_data, key, cmd)
        logs.append(routing_engine_output)
        file_handle.write(routing_engine_output + "\n")
    except Exception as e:
        msg = f"Erreur lors de la récupération des informations du moteur de routage : {e}"
        logs.append(msg)
        file_handle.write(msg + "\n")
        structured_output_data[key] = msg
        raise

def collect_interface_info(connection, file_handle, structured_output_data, logs):
    key_terse = 'interfaces_terse'
    cmd_terse = 'show interfaces terse'
    key_detail = 'interfaces_detail'
    cmd_detail = 'show interfaces detail'
    try:
        if not verifier_connexion(connection):
                raise Exception("Connexion perdue avec le routeur")
        logs.append("\nInformations sur les interfaces :")
        file_handle.write("\nInformations sur les interfaces :\n")
       # output_terse = fetch_and_store(connection, structured_output_data, key_terse, cmd_terse)
       # output_detail = fetch_and_store(connection, structured_output_data, key_detail, cmd_detail)
        output_terse = connection.send_command(cmd_terse, read_timeout=90)
        output_detail = connection.send_command(cmd_detail, read_timeout=90)
        interfaces_up, interfaces_down = parsers.parse_interfaces(output_terse, output_detail)
        structured_output_data['interfaces_up'] = interfaces_up
        structured_output_data['interfaces_down'] = interfaces_down
        # Log up interfaces
        logs.append("Les Interfaces up :")
        file_handle.write("Les Interfaces up :\n")
        if interfaces_up:
            for intf in interfaces_up:
                if isinstance(intf, dict):
                    output = ", ".join(f"{k}: {v}" for k, v in intf.items())
                else:
                    output = str(intf)
                logs.append(output)
                file_handle.write(output + "\n")
        else:
            logs.append("Aucune interface active trouvée.")
            file_handle.write("Aucune interface active trouvee.\n")
        # Log down interfaces
        logs.append("Les Interfaces down :")
        file_handle.write("Les Interfaces down :\n")
        if interfaces_down:
            for intf in interfaces_down:
                if isinstance(intf, dict):
                    output = ", ".join(f"{k}: {v}" for k, v in intf.items())
                else:
                    output = str(intf)
                logs.append(output)
                file_handle.write(output + "\n")
        else:
            logs.append("Aucune interface inactive trouvée.")
            file_handle.write("Aucune interface inactive trouvee.\n")
    except Exception as e:
        msg = f"Erreur lors de la récupération des informations des interfaces : {e}"
        logs.append(msg)
        file_handle.write(msg + "\n")
        structured_output_data['interfaces'] = msg
        raise

def collect_arp_info(connection, file_handle, structured_output_data, logs):
    key = 'arp_table'
    cmd = 'show arp'
    try:
        logs.append("\nInformations ARP :")
        file_handle.write("\nInformations ARP :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd)
        logs.append(output)
        file_handle.write(output + "\n")   
    except Exception as e:
        logs.append(f"Erreur lors de la récupération des informations ARP : {e}")
        file_handle.write(f"Erreur lors de la recuperation des informations ARP : {e}\n")
        structured_output_data[key] = f"Erreur lors de la récupération des informations ARP : {e}"

def collect_route_summary(connection, file_handle, structured_output_data, logs):
    key = 'route_summary'
    cmd = 'show route summary'
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        logs.append("\nInformations sur les routes :")
        file_handle.write("\nInformations sur les routes :\n")
        logs.append("Résumé des routes :")
        file_handle.write("Resume des routes :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_route_summary)
        if output.strip():
            logs.append(output)
            file_handle.write(output + "\n")
        else:
            logs.append("Aucun résumé de route trouvé.")
            file_handle.write("Aucun resume de route trouve.\n")
    except Exception as e:
        logs.append(f"Erreur lors de la récupération des informations sur les routes : {e}")
        file_handle.write(f"Erreur lors de la recuperation des informations sur les routes : {e}")
        structured_output_data[key] = f"Erreur lors de la récupération des informations sur les routes : {e}"
        raise 

def collect_ospf_info(connection, file_handle, structured_output_data, logs):
    key = 'ospf_info'
    cmd = 'show ospf interface brief'
    try:
        logs.append("\nProtocole OSPF :")
        file_handle.write("\nProtocole OSPF :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_ospf_info)
        if "OSPF instance is not running" in output:
            logs.append("OSPF n'est pas configuré sur ce routeur.")
            file_handle.write("OSPF n'est pas configure sur ce routeur.\n")
        else:
            logs.append("Interfaces OSPF actives :")
            file_handle.write("Interfaces OSPF actives :\n")
            logs.append(output)
            file_handle.write(output + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la vérification du protocole OSPF : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole OSPF : {e}")
        structured_output_data[key] = f"Erreur lors de la vérification du protocole OSPF : {e}"

def collect_isis_info(connection, file_handle, structured_output_data, logs):
    key = 'isis_info'
    cmd = 'show isis adjacency'
    try:
        logs.append("\nProtocole IS-IS :")
        file_handle.write("\nProtocole IS-IS :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_isis_info)
        if "IS-IS instance is not running" in output:
            logs.append("IS-IS n'est pas configuré sur ce routeur.")
            file_handle.write("IS-IS n'est pas configure sur ce routeur.\n")
        else: 
            logs.append("Interfaces isis actives :")
            file_handle.write("Interfaces isis actives :\n")
            logs.append(output)
            file_handle.write(output + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la vérification du protocole IS-IS : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole IS-IS : {e}")
        structured_output_data[key] = f"Erreur lors de la vérification du protocole IS-IS : {e}"

def collect_mpls_info(connection, file_handle, structured_output_data, logs):
    key = 'mpls_info'
    cmd = 'show mpls interface'
    try:
        logs.append("\nProtocole MPLS :")
        file_handle.write("\nProtocole MPLS :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_mpls_info)
        if "MPLS not configured" in output:
            logs.append("MPLS n'est pas configuré sur ce routeur.")
            file_handle.write("MPLS n'est pas configure sur ce routeur.\n")
        else: 
            logs.append("les interfaces  MPLS est activés. :")
            file_handle.write("les interfaces  MPLS  actives. :\n")
            logs.append(output)
            file_handle.write(output + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la vérification du protocole MPLS : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole MPLS : {e}")
        structured_output_data[key] = f"Erreur lors de la vérification du protocole MPLS : {e}"

def collect_ldp_info(connection, file_handle, structured_output_data, logs):
    key = 'ldp_info'
    cmd = 'show ldp session'
    try:
        logs.append("\nProtcole LDP :")
        file_handle.write("\nProtocole LDP :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_ldp_info)
        if "LDP instance is not running" in output:
            logs.append("LDP n'est pas configuré sur ce routeur.")
            file_handle.write("LDP n'est pas configure sur ce routeur.\n")
        else :
            lignes = output.split('\n')
            resultat_filtre = []
            for ligne in lignes:
                colonnes = ligne.split()
                if len(colonnes) >= 5:  
                    ligne_filtree = f"{colonnes[0]:<15} {colonnes[1]:<12} {colonnes[2]:<12} {''.join(colonnes[4:])}"
                    resultat_filtre.append(ligne_filtree)
                else:
                    resultat_filtre.append(ligne)
            output_final = "\n".join(resultat_filtre)
            logs.append("Sessions LDP actives  :")
            file_handle.write("Sessions LDP actives :\n")
            logs.append(output_final)
            file_handle.write(output_final + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la vérification du protocole LDP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole LDP : {e}\n")
        structured_output_data[key] = f"Erreur lors de la vérification du protocole LDP : {e}"

def collect_rsvp_info(connection, file_handle, structured_output_data, logs):
    key = 'rsvp_info'
    cmd = 'show rsvp interface'
    try:
        logs.append("\nProtocole RSVP :")
        file_handle.write("\nProtocole RSVP :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_rsvp_info)
        if "RSVP not configured" in output:
            logs.append("RSVP n'est pas configuré sur ce routeur.")
            file_handle.write("RSVP n'est pas configure sur ce routeur.\n")
        else: 
            file_handle.write("Interfaces configurees avec RSVP :\n")
            logs.append(output)
            file_handle.write(output + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la vérification du protocole RSVP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole RSVP : {e}")
        structured_output_data[key] = f"Erreur lors de la vérification du protocole RSVP : {e}"

def collect_lldp_info(connection, file_handle, structured_output_data, logs):
    key = 'lldp_info'
    cmd = 'show lldp neighbor'
    try:
        logs.append("\nProtocole LLDP :")
        file_handle.write("\nProtocole LLDP :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_lldp_info)
        if not output.strip():
            logs.append("LLDP n'est pas configuré ou aucun voisin n'a été détecté.")
            file_handle.write("LLDP n'est pas configure ou aucun voisin n'a ete detecte.\n")
        else:
            logs.append("Voisins LLDP découverts :")
            file_handle.write("Voisins LLDP decouverts :\n")
            logs.append(output)
            file_handle.write(output + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la vérification du protocole LLDP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole LLDP : {e}")
        structured_output_data[key] = f"Erreur lors de la vérification du protocole LLDP : {e}"

def collect_lsp_info(connection, file_handle, structured_output_data, logs):
    key = 'lsp_info'
    cmd = 'show mpls lsp'
    try:
        logs.append("\nProtocole LSP :")
        file_handle.write("\nProtocole LSP :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_lsp_info)
        if "MPLS not configured" in output:
            logs.append("Aucune session lsp trouvé.")
            file_handle.write("Aucune session lsp trouve.\n")
        else:
            logs.append("statut des LSP :")
            file_handle.write("statut des LSP :\n")
            logs.append(output)
            file_handle.write(output + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la vérification du protocole LSP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole LSP : {e}")
        structured_output_data[key] = f"Erreur lors de la vérification du protocole LSP : {e}"

def collect_bgp_info(connection, file_handle, structured_output_data, logs):
    key = 'bgp_summary'
    cmd = 'show bgp summary'
    try:
        logs.append("\nProtocole BGP :")
        file_handle.write("\nProtocole BGP :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_bgp_info)
        if "BGP is not running" in output:
            logs.append("BGP n'est pas configuré sur ce routeur.")
            file_handle.write("BGP n'est pas configure sur ce routeur.\n")
        else:  
            logs.append(output)
            file_handle.write(output + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la vérification du protocole BGP : {e}")
        file_handle.write(f"Erreur lors de la verification du protocole BGP : {e}")
        structured_output_data[key] = f"Erreur lors de la vérification du protocole BGP : {e}"
    # Non-critical

def collect_system_services(connection, file_handle, structured_output_data, logs):
    key = 'system_services'
    cmd = 'show configuration system services'
    try:
        logs.append("\nServices configurés :")
        file_handle.write("\nServices configures :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_system_services)
        # output is a list
        for service in output:
            logs.append(service)
            file_handle.write(service + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la récupération des services configurés : {e}")
        file_handle.write(f"Erreur lors de la recuperation des services configures : {e}")
        structured_output_data[key] = f"Erreur lors de la récupération des services configurés : {e}"

def collect_configured_protocols(connection, file_handle, structured_output_data, logs):
    key = 'configured_protocols'
    cmd = 'show configuration protocols'
    try:
        logs.append("\nProtocoles configurés :")
        file_handle.write("\nProtocoles configures :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_configured_protocols)
        if isinstance(output, str):
            logs.append(output)
            file_handle.write(output + "\n")
        else:
            for protocol in output:
                logs.append(protocol)
                file_handle.write(protocol + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la récupération des protocoles configurés : {e}")
        file_handle.write(f"Erreur lors de la recuperation des protocoles configures : {e}")
        structured_output_data[key] = f"Erreur lors de la récupération des protocoles configurés : {e}"

def collect_firewall_acls(connection, file_handle, structured_output_data, logs):
    key = 'firewall_config'
    cmd = 'show configuration firewall'
    try:
        logs.append("\nListes de Contrôle d'Accès (ACL) :")
        file_handle.write("\nListes de Controle d'Acces (ACL) :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd, parser_func=parsers.parse_firewall_acls)
        if output.strip():
            logs.append("Réponse de la commande 'show configuration firewall' :")
            file_handle.write("Reponse de la commande 'show configuration firewall' :\n")
            logs.append(output)
            file_handle.write(output + "\n")
        else:
            logs.append("Aucune ACL configurée trouvée.")
            file_handle.write("Aucune ACL configuree trouvee.\n")
    except Exception as e:
        logs.append(f"Erreur lors de la vérification des ACL configurées : {e}")
        file_handle.write(f"Erreur lors de la verification des ACL configurees : {e}")
        structured_output_data[key] = f"Erreur lors de la vérification des ACL configurées : {e}"

def collect_critical_logs(connection, file_handle, structured_output_data, logs):
    key_msg = 'critical_logs_messages'
    cmd_msg = 'show log messages | match "error|warning|critical" | last 10'
    key_chassisd = 'critical_logs_chassisd'
    cmd_chassisd = 'show log chassisd | match "error|warning|critical" | last 10'
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        logs.append("\nLogs des erreurs critiques :")
        file_handle.write("\nLogs des erreurs critiques :\n")
        logs.append("Logs des erreurs critiques dans 'messages' :")
        file_handle.write("Logs des erreurs critiques dans 'messages' :\n")
        output_msg = fetch_and_store(connection, structured_output_data, key_msg, cmd_msg, parser_func=parsers.parse_critical_logs)
        filtered_logs = [line for line in output_msg.splitlines() if not line.strip().startswith("---(more")]
        filtered_logs_str = "\n".join(filtered_logs)
        logs.append(filtered_logs_str)
        file_handle.write(filtered_logs_str + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la récupération des logs des erreurs critiques dans 'messages' : {e}")
        file_handle.write(f"Erreur lors de la recuperation des logs des erreurs critiques dans 'messages' : {e}")
        structured_output_data[key_msg] = f"Erreur lors de la récupération des logs des erreurs critiques dans 'messages' : {e}"
        raise 
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        logs.append("Logs des erreurs critiques dans 'chassisd' :")
        file_handle.write("Logs des erreurs critiques dans 'chassisd' :\n")
        output_chassisd = fetch_and_store(connection, structured_output_data, key_chassisd, cmd_chassisd, parser_func=parsers.parse_critical_logs)
        filtered_logs = [line for line in output_chassisd.splitlines() if not line.strip().startswith("---(more")]
        filtered_logs_str = "\n".join(filtered_logs)
        logs.append(filtered_logs_str)
        file_handle.write(filtered_logs_str + "\n")
    except Exception as e:
        logs.append(f"Erreur lors de la récupération des logs des erreurs critiques dans 'chassisd' : {e}")
        file_handle.write(f"Erreur lors de la recuperation des logs des erreurs critiques dans 'chassisd' : {e}")
        structured_output_data[key_chassisd] = f"Erreur lors de la récupération des logs des erreurs critiques dans 'chassisd' : {e}"
        raise

def collect_full_configuration(connection, file_handle, structured_output_data, logs, username, router_hostname_for_filename):
    key = 'full_config_set'
    cmd = 'show configuration | display set'
    config_filename = None
    try:
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        logs.append("\nLa configuration totale :")
        file_handle.write("\nLa configuration totale :\n")
        output = fetch_and_store(connection, structured_output_data, key, cmd)
        logs.append(output)
        file_handle.write(output + "\n")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        GENERATED_FILES_DIR = os.path.join(script_dir, "generated_files")
        os.makedirs(GENERATED_FILES_DIR, exist_ok=True)
        base_config_filename = f"CONFIGURATION_{username}_{router_hostname_for_filename}.txt"
        config_filename = os.path.join(GENERATED_FILES_DIR, base_config_filename)
        compteur_config = 1
        while os.path.exists(config_filename):
            config_filename = os.path.join(GENERATED_FILES_DIR, f"CONFIGURATION_{username}_{router_hostname_for_filename}_{compteur_config}.txt")
            compteur_config += 1
        with open(config_filename, 'w', encoding='utf-8') as config_file_handle:
            config_file_handle.write(output)
        logs.append(f"Configuration complète sauvegardée dans : {config_filename}")
        return config_filename
    except Exception as e:
        msg = f"Erreur lors de la récupération de la configuration totale : {e}"
        logs.append(msg)
        file_handle.write(msg + "\n")
        structured_output_data[key] = msg
        raise