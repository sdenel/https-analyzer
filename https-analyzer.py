#!/usr/bin/env python3
import argparse
import ipaddress
import json
import logging
import os
import re
import ssl
import subprocess
import http.client
import sys
from copy import deepcopy
from typing import List

import requests
from OpenSSL import crypto
from OpenSSL.crypto import X509
from jinja2 import Template

logging.getLogger().setLevel(logging.INFO)


def components_to_str(components):
    s = ''
    for c in components:
        s += f'{c[0].decode()}={c[1].decode()}, '
    return s.strip().strip(',')


def get_response(
        ip_address: ipaddress.ip_address,
        hostname: str,
        port: int = 443,
        is_tls: bool = None
) -> (http.client.HTTPResponse, str):
    """
    >>> get_response(dns_resolve('google.com'), 'google.com')[0].status
    301
    """

    def get_proxy_host_port(proxy: str):
        """
        >>> get_proxy_host_port('http://toto.com:3128')
        ('toto.com', 3128)
        """
        proxy = proxy.strip('/')
        port = proxy.split(':')[-1]
        host = proxy.split('/')[-1].split(':')[0]
        # TODO check host validity
        assert port.isdigit(), port
        return host, int(port)

    def get_response_inner(http_connection: http.client.HTTPConnection) -> (http.client.HTTPResponse, str):
        http_connection.putrequest('GET', '/')
        http_connection.putheader('Host', hostname)
        http_connection.endheaders()

        if isinstance(http_connection, http.client.HTTPSConnection):
            pem_cert = ssl.DER_cert_to_PEM_cert(http_connection.sock.getpeercert(True))
            x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert.encode())
        else:
            x509_cert = None

        return http_connection.getresponse(), x509_cert

    if is_tls is None:
        is_tls = port % 1000 == 443
    if is_tls:
        context: ssl.SSLContext = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if 'HTTPS_PROXY' in os.environ:
            proxy_host, proxy_port = get_proxy_host_port(os.environ['HTTPS_PROXY'])
            conn = http.client.HTTPSConnection(proxy_host, proxy_port, context=context)
            conn.set_tunnel(str(ip_address), port=port)
        else:
            conn = http.client.HTTPSConnection(str(ip_address), port, context=context)
    else:
        if 'HTTP_PROXY' in os.environ:
            proxy_host, proxy_port = get_proxy_host_port(os.environ['HTTP_PROXY'])
            conn = http.client.HTTPConnection(proxy_host, proxy_port)
            conn.set_tunnel(str(ip_address), port=port)
        else:
            conn = http.client.HTTPConnection(str(ip_address), port)
    return get_response_inner(conn)


def is_valid_hostname(hostname):
    """
    Taken from https://stackoverflow.com/a/33214423/1795027
    """
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)


def dns_resolve(
        hostname: str,
        dns_server: str = None
) -> ipaddress.ip_address:
    """
    >>> ip = dns_resolve('www.akamai.com')
    >>> ip.is_private
    False
    >>> ip = dns_resolve('www.akamai.com', 'dns-over-https')
    >>> ip.is_private
    False
    """

    if dns_server == 'dns-over-https':
        ret = requests.get(f'https://cloudflare-dns.com/dns-query?name={hostname}', headers={'accept': 'application/dns-json'})
        answer = ret.json()['Answer']
        type1_data = [a['data'] for a in answer if a['type'] == 1]
        assert len(type1_data) == 1
        return ipaddress.ip_address(type1_data[0])

    cmd = f"dig +short {hostname}"
    if dns_server:
        dns_server = dns_server.strip()
        assert is_valid_hostname(dns_server) or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", dns_server), f"{dns_server} is not an IP not a hostname!"
        cmd += f" @{dns_server}"
    ip_as_str = subprocess.check_output(cmd, shell=True).strip().decode('utf-8').split('\n')[-1]
    return ipaddress.ip_address(ip_as_str)


def get_certificate_san_domains(x509cert: X509) -> List[str]:
    """
    From: https://stackoverflow.com/a/50894566/1795027
    """
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    return [v.split(':')[1] for v in san.split(', ')]


if __name__ == '__main__':
    # Parsing optional arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--dns-server", help="DNS server to use")
    args = parser.parse_args()

    if args.dns_server is not None:
        logging.info(f"Using DNS server: {args.dns_server}")
        sys.stderr.flush()

    # Parsing stdin
    stdin_lines = [l.split("#")[0].split(' ') for l in sys.stdin.readlines()]
    domains = [d.strip() for d in sum(stdin_lines, []) if len(d) > 0]

    print("{")

    for domain_idx, domain in enumerate(domains):
        logging.info(f"Parsing {domain}")

        assert is_valid_hostname(domain), f"{domain} is not a valid hostname!"
        ip = dns_resolve(domain, args.dns_server)
        http_response = get_response(ip, domain, 80)
        https_response = get_response(ip, domain, 443)
        r = {
            'ip': str(ip),
            'http': {
                'status': http_response[0].status,
                'headerLocation': http_response[0].getheader('location')
            }, 'https': {
                'status': https_response[0].status,
                'headerLocation': https_response[0].getheader('location'),
                'certificate': {
                    'issuer': components_to_str(https_response[1].get_issuer().get_components()),
                    'subject': components_to_str(https_response[1].get_subject().get_components()),
                    'san_domains': get_certificate_san_domains(https_response[1])
                    # TODO: is domain is certif alternate names ?
                }
            }
        }

        sys.stdout.write(f'{"," if domain_idx > 0 else ""}"{domain}": ')
        print(json.dumps(r, sort_keys=True, indent=4, separators=(',', ': ')))
    print("}")
