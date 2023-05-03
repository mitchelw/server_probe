#!/usr/bin/python
import cgi
from jinja2 import Template
import subprocess
import requests
import json
import re
import threading


API_KEY = open("/home/ubuntu/ipgeolocation_apikey.txt", 'r').read()[:-1]

def render_page():
    print("Content-type: text/html\n")

    args = cgi.parse()
    addr_param = args.get("addr")

    stylesheet = open("../html/stylesheet.css", 'r').read()

    # debug
    if addr_param is None or len(addr_param) == 0:
        addr_param = ['case.edu']

    addr = addr_param[0]    


    # Run nmap and traceroute in parallel
    def nmap_helper(addr, ret):
        ip, ports, not_shown = nmap(addr)
        ret[0] = ip
        ret[1] = ports
        ret[2] = not_shown
    def traceroute_helper(addr, ret):
        ret[3] = traceroute(addr)
    results = [None] * 4
    nmap_thread = threading.Thread(target=nmap_helper, args=([addr, results]))
    traceroute_thread = threading.Thread(target=traceroute_helper, args=([addr, results]))

    nmap_thread.start()
    traceroute_thread.start()
    nmap_thread.join()
    traceroute_thread.join()
    ip, ports, not_shown, tr_lines = results

    dest_query_json = query_ip(ip)
    dest_cc = dest_query_json.get("country_code2") if dest_query_json.get("country_code2") is not None else '?'
        

    tr_cc = []       # country codes for each hop
    # List of (lat, long) pairs for resolvable hops. Begins with datacenter coords and ends with desination
    hop_coords = [("39.96199", "-83.00275")]
    for l in tr_lines:
        if re.match(r"[0-9]+\s\s\*\s\*\s\*", l):
            tr_cc.append('!')
            continue
        tr_ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', l)
        if tr_ip is not None:
            hop_json = query_ip(tr_ip.group())
            resolved_ip = hop_json.get("country_code2") or hop_json.get("latitude") or hop_json.get("longitude")
            if hop_json.get("country_code2") is not None:
                tr_cc.append(hop_json["country_code2"].lower())
            # Don't append consecutive duplicates
            if hop_json.get("latitude") is not None and hop_json.get("longitude") is not None and \
               hop_coords[-1] != (hop_json["latitude"], hop_json["longitude"]):
                hop_coords.append((hop_json["latitude"], hop_json["longitude"]))
            if resolved_ip:
                continue
        tr_cc.append('?')
    
    # Append the destination to the end of the hop chain
    if dest_query_json.get("latitude") is not None and dest_query_json.get("longitude") is not None:
        # Don't append the destination is the last hop is an exact match
        # This prevents a green node from obscuring a red desination node
        if len(hop_coords) == 0 or hop_coords[-1] != (dest_query_json["latitude"], dest_query_json["longitude"]):
            hop_coords.append((dest_query_json["latitude"], dest_query_json["longitude"]))
    
    
    # consolidate array for simpler iteration
    tr_hops = list(zip(tr_cc, tr_lines))

    template = Template(open("server_probe.html", 'r').read())
    html = template.render(addr=addr, ip=ip, ports=ports, not_shown=not_shown,
                           country_code=dest_cc.lower(),
                           tr_hops=tr_hops, hop_coords=hop_coords,
                           stylesheet=stylesheet) 
    print(html)


def nmap(addr):
    # subprocess.run escapes whitespace and shell metacharacters mitigating command injections
    stdout = subprocess.run(['nmap', addr], capture_output=True, text=True).stdout

    nmap_lines = stdout.split('\n')

    if '(' in nmap_lines[0]:
        ip = nmap_lines[1][nmap_lines[1].find("(")+1:nmap_lines[1].find(")")]
    else:
        ip = None
    
    ports_lines = nmap_lines[6:-3]
    # Creates an list of posts ex: [['21/tcp', 'open', 'ftp'], ['22/tcp', 'open', 'ssh']]
    # ' '.join(p.split()) consolidates whitespace within the line p from the 6th to 3rd to last
    ports = [' '.join(p.split()).split(' ') for p in nmap_lines[6:-3]]

    not_shown = nmap_lines[4]
    return ip, ports, not_shown


def traceroute(addr):
    # subprocess.run escapes whitespace and shell metacharacters mitigating command injections
    stdout = subprocess.run(['traceroute', addr], capture_output=True, text=True).stdout

    tr_lines = stdout.split('\n')
    return tr_lines[1:-1]
    


def query_ip(ip):
    params = {"apiKey": API_KEY, "ip": ip}
    r = requests.get(url="https://api.ipgeolocation.io/ipgeo", params=params)
    return r.json()


if __name__ == "__main__":
    render_page()
