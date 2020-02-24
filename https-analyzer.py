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

from OpenSSL import crypto
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

        response = http_connection.getresponse()

        if isinstance(http_connection, http.client.HTTPSConnection):
            x: http.client.HTTPSConnection = http_connection
            pem_cert = ssl.DER_cert_to_PEM_cert(x.sock.getpeercert(True))
            x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert.encode())
        else:
            x509_cert = None

        return response, x509_cert

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
    ip = dns_resolve('www.akamai.com')
    ip.is_private
    False

    """

    cmd = f"dig +short {hostname}"
    if dns_server:
        dns_server = dns_server.strip()
        assert is_valid_hostname(dns_server) or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", dns_server), f"{dns_server} is not an IP not a hostname!"
        cmd += f" @{dns_server}"
    ip_as_str = subprocess.check_output(cmd, shell=True).strip().decode('utf-8').split('\n')[-1]
    return ipaddress.ip_address(ip_as_str)


if __name__ == '__main__':
    # Parsing optional arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--dns-server", help="DNS server to use")
    parser.add_argument("--generate-html-from-json", action="store_true")
    args = parser.parse_args()
    if args.generate_html_from_json:
        stdin_json = json.loads('\n'.join(sys.stdin.readlines()))
        # print(stdin_json)
        assert args.dns_server is None, "--dns-server isn't processed when using --generate-html-from-json mode!"
        jinja_context = {
            'domains': []
        }
        for d in stdin_json:
            ctx = deepcopy(stdin_json[d])
            ctx['domain'] = d
            for t in 'http', 'https':
                s = ctx[t]['status']
                if 200 <= s < 300:
                    c = 'green'
                elif 300 <= s < 400:
                    c = 'blue'
                elif 400 <= s < 500:
                    c = 'red'
                else:
                    c = 'black'
                ctx[t]['message'] = f'<span style="background: {c}">{s}</span> '

                if ctx[t]['headerLocation'] is not None:
                    loc = ctx[t]['headerLocation']
                    if t == 'http' and ctx['http']['status'] in (301, 302) and loc == f'https://{d}/':
                        ctx[t]['message'] += '⬆ redirects to https'
                    else:
                        ctx[t]['message'] += f'<a href ="{loc}" target="_blank" style="color: white">{loc}</a>'

            if stdin_json[d]['http'] == stdin_json[d]['https']:
                ctx['http']['message'] = '//'
            # if ctx['header']

            jinja_context['domains'].append(ctx)
        with open('template.j2.html', 'r') as template_file:
            template = template_file.read()
            print(Template(template).render(jinja_context))
    else:
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
                        'subject': components_to_str(https_response[1].get_subject().get_components())
                        # TODO: is domain is certif alternate names ?
                    }
                }
            }

            sys.stdout.write(f'{"," if domain_idx > 0 else ""}"{domain}": ')
            print(json.dumps(r, sort_keys=True, indent=4, separators=(',', ': ')))
        print("}")
