try:
    # For Python 3,3+
    from ipaddress import ip_address as ip_addr, ip_network as ip_net
except ImportError:
    # Use netaddr
    from netaddr import IPAddress as ip_addr, IPNetwork as ip_net


def check_if_trusted(ip, trusted_list):
    try:
        _ip = ip_addr(ip)
        for trusted in trusted_list:
            if _ip in ip_net(trusted):
                return True
        else:
            return False
    except:
        return False


def get_from_X_FORWARDED_FOR(header, trusted_list):
    if not header:
        # If header is empty
        return None

    real_ips = header.split(',')
    # Read from right
    real_ips.reverse()
    for ip in real_ips:
        ip = ip.strip()
        if not check_if_trusted(ip, trusted_list):
            # The first one which is not in trusted list is client ip
            return ip
    else:
        return None
        

def get_from_X_REAL_IP(header):
    if not header:
        # If header is empty
        return None

    return header
