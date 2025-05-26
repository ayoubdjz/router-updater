import re

def parse_basic_info(output):
    # Extract model and version from show version output
    result = {}
    for line in output.splitlines():
        if 'Model:' in line:
            result['model'] = line.split('Model:')[-1].strip()
        elif 'JUNOS' in line and 'Release' in line:
            # Try to extract version
            match = re.search(r'JUNOS[\w\s\-]*([0-9.]+[RZ][0-9.]+)', line)
            if match:
                result['version'] = match.group(1)
    return result

def parse_interfaces(output_terse, output_detail):
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
                ip_index = columns.index("inet") + 1
                if ip_index < len(columns):
                    interface_ip_map[interface_name] = columns[ip_index]
    all_interface_details = {}

    physical_interface_sections = output_detail.split("Physical interface:")
    if len(physical_interface_sections) > 1:
        physical_interface_sections = physical_interface_sections[1:]

    for section in physical_interface_sections:
        lines = section.split("\n")
        if not lines: continue

        physical_name_line = lines[0].strip()
        physical_interface_name = physical_name_line.split(",")[0].strip()

        phys_speed = "Indisponible"
        phys_mac = "N/A"

        for line_idx, line in enumerate(lines):
            if "Speed:" in line:
                phys_speed = line.split("Speed:")[1].split(",")[0].strip()
            if "Current address:" in line or "Hardware address:" in line:
                key = "Current address:" if "Current address:" in line else "Hardware address:"
                phys_mac = line.split(key)[1].strip().split(",")[0].split()[0]

        all_interface_details[physical_interface_name] = {
            "name": physical_interface_name,
            "speed": phys_speed,
            "mac_address": phys_mac,
            "ip_address": interface_ip_map.get(physical_interface_name, "N/A (Physical)")
        }

        logical_interface_sections = section.split("Logical interface ")
        if len(logical_interface_sections) > 1:
            logical_interface_sections = logical_interface_sections[1:]

        for logical_section in logical_interface_sections:
            logical_lines = logical_section.split("\n")
            if not logical_lines: continue

            logical_name_line = logical_lines[0].strip()
            logical_interface_name = logical_name_line.split()[0].strip()

            log_ip = interface_ip_map.get(logical_interface_name, "N/A")

            if log_ip == "N/A":
                for log_line in logical_lines:
                    if "Local:" in log_line and "inet" in logical_section.lower():
                        parsed_log_ip_match = re.search(r"Local:\s*([\d\.]+)", log_line)
                        if parsed_log_ip_match:
                            parsed_log_ip = parsed_log_ip_match.group(1)
                            if parsed_log_ip:
                                log_ip = parsed_log_ip
                                interface_ip_map[logical_interface_name] = log_ip
                                break

            all_interface_details[logical_interface_name] = {
                "name": logical_interface_name,
                "speed": phys_speed,
                "ip_address": log_ip,
                "mac_address": phys_mac
            }

    for name, status_val in interface_status_map.items():
        details = all_interface_details.get(name,
            {"name": name, "speed": "N/A", "ip_address": interface_ip_map.get(name, "N/A"), "mac_address": "N/A"}
        )
        details["status"] = status_val
        if status_val == "up":
            up_interfaces.append(details)
        else:
            down_interfaces.append(details)

    return up_interfaces, down_interfaces
    return 

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
        return
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
    for line in output.splitlines():
        if "{" in line and not line.strip().startswith("}"):
            protocol_name = line.split("{")[0].strip()
            protocols.append(protocol_name)

    return protocols


def parse_firewall_acls(output):
    if output.strip():
        return output
    else:
        empty_msg = "Aucune ACL configurée trouvée."
$        return empty_msg