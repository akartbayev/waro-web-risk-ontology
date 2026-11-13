"""Knowledge base loader: NVD (CVE/CPE), CWE, CAPEC, EPSS, KEV."""
import pickle, json, gzip, csv, collections
import xml.etree.ElementTree as ET
D = 'data/'; W = 'work/'
def load_nvd(): return pickle.load(open(W + 'nvd.pkl', 'rb'))
def load_cfg(): return pickle.load(open(W + 'cfg.pkl', 'rb'))
def load_kev():
    k = json.load(open(D + 'kev.json'))
    return {v['cveID']: v['dateAdded'] for v in k['vulnerabilities']}
def load_epss(date):
    out = {}
    with gzip.open(D + f'epss_{date}.csv.gz', 'rt') as f:
        f.readline(); r = csv.reader(f); next(r)
        for row in r: out[row[0]] = float(row[1])
    return out
LIK = {'High': 0.9, 'Medium': 0.5, 'Low': 0.1}
SEV = {'Very High': 9.5, 'High': 8.0, 'Medium': 5.5, 'Low': 3.0, 'Very Low': 1.0}
def load_cwe():
    ns = {'c': 'http://cwe.mitre.org/cwe-8'}
    t = ET.parse(D + 'cwec_v5.0.xml').getroot(); cw = {}
    for w in t.find('c:Weaknesses', ns):
        if w.get('Status') == 'Deprecated': continue
        i = 'CWE-' + w.get('ID')
        rel = collections.defaultdict(set)
        for r in w.findall('c:Related_Weaknesses/c:Related_Weakness', ns):
            if r.get('Nature') == 'ChildOf' and r.get('View_ID') != '1000': continue
            rel[r.get('Nature')].add('CWE-' + r.get('CWE_ID'))
        le = w.find('c:Likelihood_Of_Exploit', ns)
        caps = ['CAPEC-' + a.get('CAPEC_ID') for a in w.findall('c:Related_Attack_Patterns/c:Related_Attack_Pattern', ns)]
        imps = set()
        for c in w.findall('c:Common_Consequences/c:Consequence', ns):
            for im in c.findall('c:Impact', ns): imps.add(im.text)
        cw[i] = dict(name=w.get('Name'), abstraction=w.get('Abstraction'), rel={k: sorted(v) for k, v in rel.items()},
                     likelihood=le.text if le is not None else None, capec=caps, impacts=sorted(imps))
    views = {}
    for v in t.find('c:Views', ns):
        views['CWE-' + v.get('ID')] = v.get('Name')
    cats = {}
    for c in t.find('c:Groupings', ns):
        hm = [m for m in c.iter() if m.tag.endswith('Has_Member')]
        mem = ['CWE-' + m.get('CWE_ID') for m in hm]
        views_in = {m.get('View_ID') for m in hm}
        cats['CWE-' + c.get('ID')] = dict(name=c.get('Name'), members=mem, views=views_in)
    return cw, cats, views
def load_capec():
    ns = {'a': 'http://capec.mitre.org/capec-3'}
    t = ET.parse(D + 'capec.xml').getroot(); ap = {}
    for a in t.find('a:Attack_Patterns', ns):
        if a.get('Status') == 'Deprecated': continue
        i = 'CAPEC-' + a.get('ID'); rel = collections.defaultdict(set)
        for r in a.findall('a:Related_Attack_Patterns/a:Related_Attack_Pattern', ns):
            rel[r.get('Nature')].add('CAPEC-' + r.get('CAPEC_ID'))
        lk = a.find('a:Likelihood_Of_Attack', ns); sv = a.find('a:Typical_Severity', ns)
        cw = ['CWE-' + w.get('CWE_ID') for w in a.findall('a:Related_Weaknesses/a:Related_Weakness', ns)]
        ap[i] = dict(name=a.get('Name'), abstraction=a.get('Abstraction'), rel={k: sorted(v) for k, v in rel.items()},
                     likelihood=lk.text if lk is not None else None, severity=sv.text if sv is not None else None, cwe=cw)
    return ap
def ancestors(cw, i, memo={}):
    if i in memo: return memo[i]
    out = []; seen = set(); frontier = [i]
    while frontier:
        nxt = []
        for x in frontier:
            for p in cw.get(x, {}).get('rel', {}).get('ChildOf', []):
                if p not in seen: seen.add(p); out.append(p); nxt.append(p)
        frontier = nxt
    memo[i] = out; return out
