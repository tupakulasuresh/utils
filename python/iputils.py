'''
apis to fetch/validate ip address
'''

import os
import logging
import socket


# logging.basicConfig(format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)-4d %(message)-80s', datefmt='%m/%d/%Y %T')
logging.basicConfig(format='%(levelname)s: %(message)s')
LOG = logging.getLogger(__name__)


def is_ip_reachable(ip, count=1, wait=3):
    if is_valid_ipv4(ip):
        cmd = 'ping'
    elif is_valid_ipv6(ip):
        cmd = 'ping6'
    else:
        raise ValueError("Invalid ip %s" % ip)

    ret_val = os.system('%s -c %d -w %d -q %s > /dev/null 2>&1'
                        % (cmd, count, wait, ip)
                       )
    return ret_val == 0

def is_local_ip(ip):
    return ip == '127.0.0.1' or ip == socket.gethostbyname(socket.gethostname())

def get_ip_from_name(node_name, dns_suffix=None, searchin=None):
    ip = get_ip_using_nslookup(node_name, dns_suffix, searchin)
    LOG.debug('ip = %s', ip)
    return ip

def name_to_ip(node_name, dns_suffix=None, searchin=None):
    ip = get_ip_using_nslookup(node_name, dns_suffix, searchin)
    LOG.debug('ip = %s', ip)
    return ip

def get_dns_suffixs(node_name, searchin=None):
    '''
    searchin is expected to be dict with prefix as key and nameserver as value
    '''
    for prefix in searchin.keys():
        if node_name.startswith(prefix):
            nameservers = searchin.get(prefix)
            break
    else:
        nameservers = []
        for entry in searchin.values():
            if isinstance(entry, list):
                nameservers.extend(entry)
            else:
                nameservers.append(entry)
        nameservers = list(set(nameservers))

    return nameservers

def get_ip_using_nslookup(node_name, dns_suffixs=None, searchin=None):
    def lookup_fqdn(fqdn):
        LOG.debug('ip = nslookup %s', fqdn)
        ip_list = []
        try:
            for line in socket.getaddrinfo(fqdn, 0, 0):
                ip_list.append(line[-1][0])
            return list(set(ip_list))[0]
        except socket.gaierror:
            pass

    node_name = node_name.strip('.').strip()
    if not dns_suffixs:
        if searchin:
            dns_suffixs = get_dns_suffixs(node_name, searchin=searchin)
        else:
            dns_suffixs = []


    if not isinstance(dns_suffixs, list):
        dns_suffixs = dns_suffixs.split(' ')

    if '.' not in node_name and dns_suffixs:
        for dns_suffix in dns_suffixs:
            fqdn = node_name + '.' + dns_suffix
            ip = lookup_fqdn(fqdn)
            if ip is not None:
                return ip
    else:
        ip = lookup_fqdn(node_name)
        if ip is not None:
            return ip

    LOG.error('unable to resolve dns for %s', node_name)

def ip_to_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.gaierror:
        return "UNKNOWN"

def is_valid_ipv4(ip):
    if ip:
        try:
            return bool(socket.inet_pton(socket.AF_INET, ip))
        except socket.error:
            pass
    return False

def is_valid_ipv6(ip):
    if ip:
        try:
            return bool(socket.inet_pton(socket.AF_INET6, ip))
        except socket.error:
            pass
    return False

def is_valid_ip(ip):
    if ip:
        LOG.debug('validate ip %s', ip)
        if is_valid_ipv4(ip) is True or is_valid_ipv6(ip) is True:
            return True
    LOG.debug('%s: not a valid ip.', ip)
    return False

def is_valid_port(port):
    port = str(port)
    LOG.debug('validate port %s', port)
    if not (port.isdigit() or port.upper() in ['IPMI']):
        LOG.warning('Port \"%s\" is not a digit|IPMI', port)
        return False

    return True
