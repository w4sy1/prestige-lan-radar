import ipaddress
import re


def normalize(rows):
    if not isinstance(rows,list):raise ValueError('Wymagana lista hostów.')
    hosts={}
    for row in rows:
        if not isinstance(row,dict):raise ValueError('Nieprawidłowy host.')
        mac=str(row['mac']).lower().replace('-',':')
        if not re.fullmatch(r'(?:[a-f0-9]{2}:){5}[a-f0-9]{2}',mac) or int(mac[:2],16)&1 or mac=='00:00:00:00:00:00':raise ValueError('Wymagany unicast MAC.')
        values=row.get('ips',[row.get('ip')])
        if not isinstance(values,list) or not values:raise ValueError('Wymagana lista adresów IP.')
        ips={str(ipaddress.ip_address(value)) for value in values}
        current=hosts.setdefault(mac,{'mac':mac,'ips':[],'hostname':'','vendor':'','status':'unknown'})
        current['ips']=sorted(set(current['ips'])|ips,key=lambda value:(ipaddress.ip_address(value).version,int(ipaddress.ip_address(value))))
        current['ip']=current['ips'][0]
        for name in ('hostname','vendor','status'):
            if row.get(name):current[name]=str(row[name])[:253]
    return list(hosts.values())
