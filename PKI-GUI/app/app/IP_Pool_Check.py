import ipaddress

def is_valid_ip(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(ip_str)
            return True
        except ipaddress.AddressValueError:
            return False

def are_all_ips(ip_list):
    for ip_str in ip_list:
        if not is_valid_ip(ip_str):
            return False
    return True

def is_valid_port(port_str):
    try:
        port = int(port_str)
        return 0 <= port <= 65535
    except ValueError:
        return False

def are_all_ports(port_list):
    for port_str in port_list:
        if not is_valid_port(port_str):
            return False
    return True