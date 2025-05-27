import re

def parse_basic_info(output):
    # Extract model, version, and hostname from show version output
    router_version = "inconnu"
    router_model = "inconnu"
    router_hostname = "inconnu"
    result = {}
    for line in output.splitlines():
        if line.startswith("Hostname:"):
            router_hostname = line.split("Hostname:")[1].strip()
            result['hostname'] = router_hostname if router_hostname else "inconnu"
        elif line.startswith("Model:"):
            router_model = line.split("Model:")[1].strip()
            result['model'] = router_model if router_model else "inconnu"
        elif line.startswith("Junos:"):
            router_version = line.split("Junos:")[1].strip()
            result['version'] = router_version if router_version else "inconnu"
    # Ensure all keys are present and set to 'inconnu' if missing or empty
    for key in ['hostname', 'model', 'version']:
        if key not in result or not result[key]:
            result[key] = "inconnu"
    return result

def parse_interfaces(output_terse, output_detail):
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
        mac_address = None
        for line in lines:
            if "Speed:" in line:
                speed = line.split("Speed:")[1].split(",")[0].strip()
            if "Current address:" in line:
                mac_address = line.split("Current address:")[1].strip().split()[0]
        interfaces_info[interface_name] = speed
        interfaces_mac[interface_name] = mac_address
        # Traitement des interfaces logiques
        logical_interfaces = interface.split("Logical interface")[1:]
        for logical_interface in logical_interfaces:
            logical_lines = logical_interface.split("\n")
            logical_name = logical_lines[0].strip().split()[0]
            interfaces_info[logical_name] = speed
            interfaces_mac[logical_name] = mac_address
            for line in logical_lines:
                if "Local:" in line and "Destination:" in line:
                    logical_ip = line.split("Local:")[1].split(",")[0].strip()
                    interfaces_ip[logical_name] = logical_ip
    # Construction des listes up/down enrichies (JSON tables)
    up_list = []
    down_list = []
    for intf in interfaces_up:
        row = {
            "name": intf,
            "ip_address": interfaces_ip.get(intf, "Aucune IP"),
            "mac_address": interfaces_mac.get(intf),
            "speed": interfaces_info.get(intf, "Indisponible"),
        }
        # Remove mac_address if None
        if row["mac_address"] is None:
            row.pop("mac_address")
        up_list.append(row)
    for intf in interfaces_down:
        row = {
            "name": intf,
            "ip_address": interfaces_ip.get(intf, "Aucune IP"),
            "mac_address": interfaces_mac.get(intf),
            "speed": interfaces_info.get(intf, "Indisponible"),
        }
        if row["mac_address"] is None:
            row.pop("mac_address")
        down_list.append(row)
    if not up_list:
        up_list.append({"message": "Aucune interface active trouvée."})
    if not down_list:
        down_list.append({"message": "Aucune interface inactive trouvée."})
    return up_list, down_list


def parse_route_summary(output):
    routes = []
    # Each non-empty line is a route
    if output.strip():
        return output
    else:
        empty_msg = "Aucun résumé de route trouvé."
        return empty_msg

def parse_ospf_info(output):
    if "OSPF instance is not running" in output:
        empty_msg ="OSPF n'est pas configuré sur ce routeur."
        return empty_msg
    else:
       return output
def parse_isis_info(output):
    if "IS-IS instance is not running" in output:
        empty_msg = "ISIS n'est pas configuré sur ce routeur."
        return empty_msg
    else:
        return output

def parse_mpls_info(output):
    if "MPLS is not configured" in output:
        empty_msg = "MPLS n'est pas configuré sur ce routeur."
        return empty_msg
    else:
        return output

def parse_ldp_info(output):
    if "LDP is not configured" in output:
        empty_msg = "LDP n'est pas configuré sur ce routeur."
        return empty_msg
    else:
        lignes = output.split('\n')
        resultat_filtre = []
        for ligne in lignes:
            colonnes = ligne.split()
            if len(colonnes) >= 5:  
                ligne_filtree = f"{colonnes[0]:<15} {colonnes[1]:<12} {colonnes[2]:<12} {''.join(colonnes[4:])}"
                resultat_filtre.append(ligne_filtree)
            else:
                resultat_filtre.append(ligne)
        return resultat_filtre

def parse_rsvp_info(output):
    if "RSVP is not configured" in output:
        empty_msg = "RSVP n'est pas configuré sur ce routeur."
        return empty_msg
    else:
        return output
    
def parse_lldp_info(output):
    if not output.strip():
        empty_msg = "LLDP n'est pas configuré sur ce routeur."
        return empty_msg
    else:
        return output

def parse_lsp_info(output):
    if "MPLS not configured" in output:
        empty_msg = "Aucune session lsp trouvé."
        return empty_msg
    else:
        return output
    
def parse_bgp_info(output):
    if "BGP is not running" in output:
        empty_msg = "BGP n'est pas configuré sur ce routeur."
        return empty_msg
    else:
        return output



def parse_system_services(output):
    services = []
    # Each non-empty line is a service
    for line in output.splitlines():
        if line.strip().endswith(";"):
            service_name = line.strip().rstrip(";")
            services.append(service_name)
    return services

def parse_configured_protocols(output):
    # Each non-empty line is a protocol
    protocols = []
    if output.strip():
        for line in output.splitlines():
            if "{" in line and not line.strip().startswith("}"):
                protocol_name = line.split("{")[0].strip()
                protocols.append(protocol_name)
        if not protocols:
            empty_msg = "Aucun protocole configuré trouvé."
            return empty_msg
        return protocols
    empty_msg = "Aucun protocole configuré trouvé."
    return empty_msg


def parse_firewall_acls(output):
    if output.strip():
        return output
    else:
        empty_msg = "Aucune ACL configurée trouvée."
        return empty_msg
    
def parse_critical_logs(output):
    filtered_logs = [line for line in output.splitlines() if not line.strip().startswith("---(more")]
    filtered_logs_str = "\n".join(filtered_logs)

    return filtered_logs_str