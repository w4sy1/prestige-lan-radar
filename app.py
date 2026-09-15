from hosts import normalize
from discovery import discover,enrich,vendors
import ipaddress
from contextlib import contextmanager
import json
import os
import re
import sqlite3
import sys
from runtime import entry,now,parser,powershell,read_json,run

CATEGORIES=['Moje','Rodzina','IoT','Router','Nieznane']


def neighbors():
    if os.name=='nt':
        rows=powershell("@(Get-NetNeighbor | Where-Object {$_.State -in @('Reachable','Stale','Delay','Probe','Permanent')} | Select-Object IPAddress,LinkLayerAddress) | ConvertTo-Json") or []
        if isinstance(rows,dict):rows=[rows]
        data=[{'ip':r['IPAddress'],'mac':r['LinkLayerAddress']} for r in rows if ':' not in r['IPAddress']]
    else:
        rows=json.loads(run(['ip','-j','neigh']));data=[{'ip':r['dst'],'mac':r['lladdr']} for r in rows if 'lladdr' in r and ':' not in r['dst']]
    # Cache bywa powielony na wielu interfejsach. Wybór pierwszego wpisu jest jawnie ograniczeniem MVP.
    valid=[]
    for row in data:
        try:valid.extend(normalize([row]))
        except ValueError:continue
    return normalize(valid)

@contextmanager
def connect(path):
    db=sqlite3.connect(path);db.row_factory=sqlite3.Row
    db.executescript('''CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY,ip TEXT,hostname TEXT,vendor TEXT,first_seen TEXT,last_seen TEXT,status TEXT,category TEXT);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, timestamp TEXT,mac TEXT,event TEXT,details TEXT);''')
    if 'ips' not in {row[1] for row in db.execute('PRAGMA table_info(devices)')}:db.execute("ALTER TABLE devices ADD COLUMN ips TEXT NOT NULL DEFAULT '[]'")
    try:
        with db:yield db
    finally:db.close()

def observe(path,rows,complete=False):
    rows=normalize(rows);events=[];stamp=now()
    with connect(path) as db:
        previous={r['mac']:dict(r) for r in db.execute('SELECT * FROM devices')}
        for row in rows:
            old=previous.get(row['mac']);changes=[]
            if not old:changes.append('NEW_DEVICE')
            else:
                if set(json.loads(old['ips']) or [old['ip']])!=set(row['ips']):changes.append('IP_CHANGE')
                if old['hostname']!=row['hostname'] and row['hostname']:changes.append('HOSTNAME_CHANGE')
                if old['status']=='offline':changes.append('RETURNED')
            if any(p['ip']==row['ip'] and p['mac']!=row['mac'] for p in previous.values()):changes.append('POSSIBLE_MAC_CHANGE')
            db.execute('INSERT INTO devices(mac,ip,hostname,vendor,first_seen,last_seen,status,category,ips) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,ips=excluded.ips,hostname=CASE WHEN excluded.hostname="" THEN devices.hostname ELSE excluded.hostname END,vendor=CASE WHEN excluded.vendor="" THEN devices.vendor ELSE excluded.vendor END,last_seen=excluded.last_seen,status=excluded.status',
                       (row['mac'],row['ip'],row['hostname'],row['vendor'],stamp,stamp,'online','Nieznane',json.dumps(row['ips'])))
            events.extend({'mac':row['mac'],'event':c,'details':row['ip']} for c in changes)
        if complete:
            current={r['mac'] for r in rows}
            for mac,old in previous.items():
                if mac not in current and old['status']!='offline':
                    db.execute('UPDATE devices SET status="offline" WHERE mac=?',(mac,));events.append({'mac':mac,'event':'DISAPPEARED','details':'Nieobecny w oznaczonej kompletnej obserwacji.'})
        for e in events:db.execute('INSERT INTO events(timestamp,mac,event,details) VALUES(?,?,?,?)',(stamp,e['mac'],e['event'],e['details']))
    return {'events':events,'observed':len(rows),'complete':complete,'note':'online oznacza zaobserwowanie wpisu; cache ARP nie dowodzi aktualnej dostępności.'}

def build():
    p=parser('Lokalny rejestr LAN w SQLite.')
    p.add_argument('command',nargs='?',choices=['observe','discover','list','history','tag'])
    p.add_argument('--database',default='lan.sqlite');p.add_argument('--input',help='Lista JSON ip/mac/hostname/vendor')
    p.add_argument('--complete',action='store_true',help='Import jest pełną obserwacją; nieobecne urządzenia oznacz offline')
    p.add_argument('--mac');p.add_argument('--category',choices=CATEGORIES)
    p.add_argument('--cidr',help='Własny RFC1918 IPv4 CIDR, do 256 adresów')
    p.add_argument('--authorized',action='store_true')
    p.add_argument('--oui',help='Lokalna baza JSON: prefix OUI -> producent')
    p.add_argument('--resolve-names',action='store_true',help='Opcjonalne reverse DNS wykrytych adresów')
    return p

def handle(a):
    if a.command=='discover':
        if not a.cidr:raise ValueError('Podaj --cidr własnej sieci.')
        result=discover(a.cidr,a.authorized,neighbors,vendors(a.oui),resolve_names=a.resolve_names)
        result['observation']=observe(a.database,result['rows'],False)
        return result
    if a.command=='observe':
        if a.complete and not a.input:raise ValueError('Cache sąsiadów nie jest pełnym wykryciem LAN.')
        return observe(a.database,enrich(read_json(a.input) if a.input else neighbors(),vendors(a.oui)),a.complete)
    with connect(a.database) as db:
        if a.command=='list':return [dict(r,ips=json.loads(r['ips']) or [r['ip']]) for r in db.execute('SELECT * FROM devices ORDER BY ip')]
        if a.command=='history':return [dict(r) for r in db.execute('SELECT * FROM events ORDER BY id DESC LIMIT 500')]
        if a.command=='tag' and a.mac and a.category:
            cursor=db.execute('UPDATE devices SET category=? WHERE mac=?',(a.category,a.mac.lower().replace('-',':')))
            if cursor.rowcount!=1:raise ValueError('Nieznane urządzenie.')
            return {'updated':True}
    raise ValueError('Wybierz poprawne polecenie.')

if __name__=='__main__':sys.exit(entry(build,handle))
