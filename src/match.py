import re
def vkey(v):
    out = []
    for t in re.findall(r'\d+|[a-zA-Z]+', v or ''):
        out.append((1, int(t)) if t.isdigit() else (0, t.lower()))
    return out
def cmpv(a, b):
    ka, kb_ = vkey(a), vkey(b)
    for x, y in zip(ka, kb_):
        if x != y: return -1 if x < y else 1
    if len(ka) == len(kb_): return 0
    longer, sign = (ka, 1) if len(ka) > len(kb_) else (kb_, -1)
    nxt = longer[min(len(ka), len(kb_))]
    if nxt[0] == 0 and nxt[1] in ('alpha', 'beta', 'rc', 'm', 'milestone', 'pre', 'dev'): return -sign   # pre-release sorts lower
    return sign
def affects(entry, version):
    cid, ver, upd, si, se, ei, ee = entry
    if si or se or ei or ee:
        if si and cmpv(version, si) < 0: return False
        if se and cmpv(version, se) <= 0: return False
        if ei and cmpv(version, ei) > 0: return False
        if ee and cmpv(version, ee) >= 0: return False
        return True
    if ver in ('*', '-'): return ver == '*'
    return cmpv(version, ver) == 0 and upd in ('*', '-', '')
def cves_for(cfg, vendor, product, version):
    return sorted({e[0] for e in cfg.get((vendor, product), []) if affects(e, version)})
