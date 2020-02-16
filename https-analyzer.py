#!/usr/bin/env python3
import argparse
import ipaddress
import json
import logging
import re
import ssl
import subprocess
import http.client
import sys

from jinja2 import Template

logging.getLogger().setLevel(logging.INFO)


def get_response(
        ip_address: ipaddress.ip_address,
        hostname: str,
        port: int = 443,
        is_tls: bool = None
) -> http.client.HTTPResponse:
    """
    >>> get_response(dns_resolve('google.com'), 'google.com').status
    301
    """

    def get_response_inner(http_connection: http.client.HTTPConnection) -> http.client.HTTPResponse:
        http_connection.putrequest('GET', '/', skip_host=True)
        http_connection.putheader('Host', hostname)
        http_connection.endheaders()
        return http_connection.getresponse()

    if is_tls is None:
        is_tls = port % 1000 == 443
    if is_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = False
        return get_response_inner(http.client.HTTPSConnection(str(ip_address), port, context=context))
    else:
        return get_response_inner(http.client.HTTPConnection(str(ip_address), port))


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
    parser.add_argument("--output", help="Output format (json or html")  # TODO default + check
    args = parser.parse_args()
    if args.dns_server is not None:
        logging.info(f"Using DNS server: {args.dns_server}")
        sys.stderr.flush()
    output_html = args.output == 'html'

    # Parsing stdin
    stdin_lines = [l.split("#")[0].split(' ') for l in sys.stdin.readlines()]
    domains = [d.strip() for d in sum(stdin_lines, []) if len(d) > 0]

    if output_html:
        with open('template.j2.html', 'r') as template_file:
            template = template_file.read()
        print("<table>")
    else:
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
                'status': http_response.status,
                'headerLocation': http_response.getheader('location')
            }, 'https': {
                'status': https_response.status,
                'headerLocation': https_response.getheader('location')
            }
        }

        if output_html:
            r['domain'] = domain
            for t in 'http', 'https':
                s = r[t]['status']
                if 200 <= s < 300:
                    c = 'green'
                elif 300 <= s < 400:
                    c = 'blue'
                elif 400 <= s < 500:
                    c = 'red'
                else:
                    c = 'black'
                r[t]['status_color'] = c
            html = Template(template).render(r)
            print(html)
        else:
            sys.stdout.write(f'{"," if domain_idx > 0 else ""}"{domain}": ')
            print(json.dumps(r, sort_keys=True, indent=4, separators=(',', ': ')))

    if output_html:
        print("</table>")
    else:
        print("}")
