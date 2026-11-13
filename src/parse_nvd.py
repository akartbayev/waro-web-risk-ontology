import gzip, json, pickle, sys, glob, collections
rows = {}; cfg = collections.defaultdict(list)
def pick(metrics, key):
    ms = metrics.get(key, [])
    if not ms: return None
    ms = sorted(ms, key=lambda m: 0 if m.get('type') == 'Primary' else 1)
    return ms[0]
for f in sorted(glob.glob('data/nvd/*.json.gz')):
    d = json.load(gzip.open(f))
    for it in d['vulnerabilities']:
        c = it['cve']; cid = c['id']
        if c.get('vulnStatus') == 'Rejected': continue
        m = c.get('metrics', {})
        v31 = pick(m, 'cvssMetricV31') or pick(m, 'cvssMetricV30')
        v2 = pick(m, 'cvssMetricV2'); v4 = pick(m, 'cvssMetricV40')
        cwes = []
        for w in c.get('weaknesses', []):
            for dsc in w.get('description', []):
                v = dsc['value']
                if v.startswith('CWE-') and v not in cwes: cwes.append(v)
        prods = set()
        for conf in c.get('configurations', []):
            for node in conf.get('nodes', []):
                for cm in node.get('cpeMatch', []):
                    if not cm.get('vulnerable'): continue
                    p = cm['criteria'].split(':')
                    part, vendor, product, version, update = p[2], p[3], p[4], p[5], p[6]
                    prods.add((part, vendor, product))
                    cfg[(vendor, product)].append((cid, version, update, cm.get('versionStartIncluding'), cm.get('versionStartExcluding'), cm.get('versionEndIncluding'), cm.get('versionEndExcluding')))
        rows[cid] = dict(pub=c['published'][:10], status=c.get('vulnStatus'),
            v3=v31['cvssData']['baseScore'] if v31 else None, v3vec=v31['cvssData']['vectorString'] if v31 else None,
            v3src=v31.get('type') if v31 else None,
            v2=v2['cvssData']['baseScore'] if v2 else None, v2vec=v2['cvssData']['vectorString'] if v2 else None,
            v4=v4['cvssData']['baseScore'] if v4 else None,
            cwes=cwes, prods=sorted(prods))
    print(f, len(rows), file=sys.stderr)
pickle.dump(rows, open('work/nvd.pkl', 'wb')); pickle.dump(dict(cfg), open('work/cfg.pkl', 'wb'))
