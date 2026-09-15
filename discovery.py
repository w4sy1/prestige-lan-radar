"""Bounded, explicitly authorized ICMP discovery on RFC1918 IPv4 networks."""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import os
import re
import subprocess
import sys
from runtime import read_json, run


def targets(cidr):
    network=ipaddress.ip_network(cidr,strict=False)
    private=[ipaddress.ip_network(value) for value in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    if network.version!=4 or network.num_addresses>256 or not any(network.subnet_of(value) for value in private):
        raise ValueError('Discovery wymaga prywatnego IPv4 CIDR, maksymalnie 256 adresów.')
    return [str(address) for address in network.hosts()]


def ping(address):
    command=['ping','-n','1','-w','700',address] if os.name=='nt' else ['ping','-c','1','-W','1',address]
    try:
        output=run(command,timeout=3)
        return bool(re.search(r'(?i)ttl[=\s]',output))
    except (OSError,RuntimeError,subprocess.TimeoutExpired):
        return False

def hostname(address):
    try:
        value=run([sys.executable,'-c','import socket,sys;print(socket.gethostbyaddr(sys.argv[1])[0])',str(ipaddress.ip_address(address))],timeout=3).strip()
        return value[:253]
    except (OSError,RuntimeError,subprocess.TimeoutExpired):return ''


def vendors(path):
    if not path:return {}
    data=read_json(path)
    if not isinstance(data,dict):raise ValueError('Baza OUI musi być obiektem JSON prefix -> vendor.')
    normalized={}
    for key,value in data.items():
        prefix=key.replace(':','').replace('-','').upper()
        if not re.fullmatch('[0-9A-F]{6}',prefix) or not isinstance(value,str):raise ValueError('Nieprawidłowy wpis OUI.')
        normalized[prefix]=value[:200]
    return normalized


def enrich(rows,oui=None):
    result=[]
    for row in rows:
        row=dict(row);mac=row['mac'].replace(':','').replace('-','')
        local=bool(int(mac[:2],16)&2)
        row['vendor']='Adres lokalny/losowy — producent nieznany' if local else (oui or {}).get(mac[:6].upper(),row.get('vendor',''))
        result.append(row)
    return result


def discover(cidr,authorized,neighbor_provider,oui=None,probe=ping,resolve_names=False):
    addresses=targets(cidr)
    if not authorized:raise ValueError('Potwierdź uprawnienie do własnej sieci opcją --authorized.')
    with ThreadPoolExecutor(max_workers=16) as executor:
        alive={address for address,success in zip(addresses,executor.map(probe,addresses)) if success}
    observed=[]
    for row in neighbor_provider():
        for address in row.get('ips',[row['ip']]):
            if address in alive:observed.append(dict(row,ip=address,ips=[address],status='online'))
    if resolve_names:
        with ThreadPoolExecutor(max_workers=8) as executor:
            observed=[dict(row,hostname=name) for row,name in zip(observed,executor.map(hostname,[row['ip'] for row in observed]))]
    known={row['ip'] for row in observed}
    return {'rows':enrich(observed,oui),'responsive_without_mac':sorted(alive-known),
        'probed':len(addresses),'responsive':len(alive),'complete':False,
        'note':'Brak odpowiedzi ICMP nie dowodzi offline. MAC pochodzi z lokalnej tablicy sąsiadów; routing może uniemożliwić jego odczyt.'}
