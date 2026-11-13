"""Finding extraction, vulnerability semantics, reference (closure-based) inference, contextual risk model."""
import numpy as np, collections, kb, match, priors
def vsem(r):
    """Normalised exploit semantics from a CVSS v3.x vector (falls back to v2)."""
    v = r['v3vec']
    if v:
        d = dict(x.split(':') for x in v.split('/')[1:])
        return dict(av=d['AV'], pr=d['PR'], ui=d['UI'], c=d['C'], i=d['I'], a=d['A'])
    v = r['v2vec']
    if v:
        d = dict(x.split(':') for x in v.split('/')); m = {'N': 'N', 'P': 'L', 'C': 'H'}
        return dict(av=d['AV'], pr={'N': 'N', 'S': 'L', 'M': 'H'}[d['Au']], ui='N', c=m[d['C']], i=m[d['I']], a=m[d['A']])
    return dict(av='N', pr='N', ui='N', c='L', i='L', a='L')
IMP = {'H': 0.56, 'L': 0.22, 'N': 0.0}
def impact_frac(s): return (1 - (1 - IMP[s['c']]) * (1 - IMP[s['i']]) * (1 - IMP[s['a']])) / 0.914816
def grants_foothold(s): return s['c'] == 'H' and s['i'] == 'H'
def profile(s): return (s['av'], s['pr'], s['ui'], grants_foothold(s))
class Context:
    """Everything known at snapshot date T (no information from after T)."""
    def __init__(self, T, nvd=None, cfg=None):
        self.T = T; self.nvd = nvd or kb.load_nvd(); self.cfg = cfg or kb.load_cfg(); self.kev = kb.load_kev(); self.epss = kb.load_epss(T)
        self.cw, self.cats, _ = kb.load_cwe(); self.ap = kb.load_capec()
        self.sh_k = priors.Shrink(self.cw, m=200.0); self.sh_s = priors.Shrink(self.cw, m=20.0); self.sh_e = priors.Shrink(self.cw, m=20.0)
        pk = collections.Counter(); pn = collections.Counter(); xk = collections.Counter(); xn = collections.Counter()
        for c, r in self.nvd.items():
            if r['pub'] >= T: continue
            z = 1.0 if (c in self.kev and self.kev[c] < T) else 0.0
            self.sh_k.add(r['cwes'], z)
            if r['v3'] is not None: self.sh_s.add(r['cwes'], r['v3'])
            if c in self.epss: self.sh_e.add(r['cwes'], self.epss[c])
            for p in r['prods']: pn[p[1:]] += 1; pk[p[1:]] += z
            x = profile(vsem(r)); xn[x] += 1; xk[x] += z
        self.pk, self.pn, self.g = pk, pn, self.sh_k.glob(); self.xk, self.xn = xk, xn
        # weakness-level chain relations
        self.cp = collections.defaultdict(set)      # CWE CanPrecede (CanFollow inverted)
        for w, d in self.cw.items():
            for x in d['rel'].get('CanPrecede', []): self.cp[w].add(x)
            for x in d['rel'].get('CanFollow', []): self.cp[x].add(w)
        self.acp = collections.defaultdict(set)     # CAPEC CanPrecede
        for a, d in self.ap.items():
            for x in d['rel'].get('CanPrecede', []): self.acp[a].add(x)
            for x in d['rel'].get('CanFollow', []): self.acp[x].add(a)
    def anc(self, w): return [w] + [a for a in kb.ancestors(self.cw, w) if a in self.cw and self.cw[a]['abstraction'] != 'Pillar']
    def severity(self, cve):
        r = self.nvd[cve]
        if r['v3'] is not None: return r['v3'] / 10, False
        if r['v2'] is not None: return r['v2'] / 10, False
        e = self.sh_s.est(r['cwes']); return (e if e is not None else self.sh_s.glob()) / 10, True
    def likelihood(self, cve, mode='full'):
        r = self.nvd[cve]
        if mode != 'epss' and cve in self.kev and self.kev[cve] < self.T: return 1.0
        if cve in self.epss: e = self.epss[cve]
        else:
            e = self.sh_e.est(r['cwes']); e = e if e is not None else self.sh_e.glob()
        if mode == 'epss': return e
        pw = self.sh_k.est(r['cwes']); pw = pw if pw is not None else self.g
        pp = max([(self.pk[p[1:]] + 50 * self.g) / (self.pn[p[1:]] + 50) for p in r['prods']], default=self.g)
        x = profile(vsem(r)); px = (self.xk[x] + 200 * self.g) / (self.xn[x] + 200)
        if mode == 'noprofile': px = 0.0
        return 1 - (1 - e) * (1 - pw) * (1 - pp) * (1 - px)
    def findings(self, app):
        F = []
        for c in app['comps']:
            for cve in match.cves_for(self.cfg, c['vendor'], c['product'], c['version']):
                r = self.nvd[cve]
                if r['pub'] >= self.T: continue
                F.append(dict(comp=c['id'], host=c['host'], role=c['role'], cve=cve, sem=vsem(r), cwes=[w for w in r['cwes'] if w in self.cw]))
        return F
def topology(app):
    hosts = sorted({c['host'] for c in app['comps']}); L = set(app['links']); fw = set(app['forwards'])
    # reverse-proxy forwarding: Internet -> edge, edge forwards to app  =>  Internet reaches app
    ch = True
    while ch:
        ch = False
        for (a, b) in list(L):
            for (x, y) in fw:
                if b == x and (a, y) not in L: L.add((a, y)); ch = True
    exposed = {b for (a, b) in L if a == 'Internet'}
    adj = collections.defaultdict(set)
    for a, b in L:
        if a != 'Internet': adj[a].add(b)
    reach = {h: set() for h in hosts}                      # transitive closure
    for h in hosts:
        st = list(adj[h])
        while st:
            x = st.pop()
            if x not in reach[h]: reach[h].add(x); st += list(adj[x])
    dist = {h: (0 if h in exposed else None) for h in hosts}; fr = list(exposed); d = 0
    while fr:
        d += 1; nx = []
        for h in fr:
            for x in adj[h]:
                if dist[x] is None: dist[x] = d; nx.append(x)
        fr = nx
    return dict(hosts=hosts, exposed=exposed, adj=adj, reach=reach, dist=dist)
def importance(app, topo, w=(0.4, 0.4, 0.2), gamma=0.5):
    I = {}; n = len(topo['hosts'])
    for c in app['comps']:
        h = c['host']; d = topo['dist'][h]
        E = 0.0 if d is None else gamma ** d
        if c['role'] == 'lib': E *= 0.5
        Z = sum(1 for x in topo['hosts'] if h in topo['reach'][x]) / max(n - 1, 1)
        I[c['id']] = dict(E=E, A=c['crit'], Z=Z, I=w[0] * E + w[1] * c['crit'] + w[2] * Z)
    return I
def enables_closure(ctx, F, topo, rules=('weakness', 'pattern', 'privilege', 'pivot')):
    """Reference implementation of the chain rules (used to cross-check the OWL reasoner). Returns set of (i, j, rule)."""
    W = [set(a for w in f['cwes'] for a in ctx.anc(w)) for f in F]
    AP = [set(c for a in W[k] for c in ctx.cw[a]['capec'] if c in ctx.ap) for k in range(len(F))]
    out = set()
    for i, f in enumerate(F):
        for j, g in enumerate(F):
            if i == j or f['cve'] == g['cve']: continue
            same = f['host'] == g['host']; reach = same or g['host'] in topo['reach'][f['host']]
            direct = g['host'] in topo['adj'][f['host']]
            if reach:
                if 'weakness' in rules and any(y in W[j] for x in W[i] for y in ctx.cp.get(x, ())): out.add((i, j, 'weakness'))
                if 'pattern' in rules and any(y in AP[j] for x in AP[i] for y in ctx.acp.get(x, ())): out.add((i, j, 'pattern'))
            if grants_foothold(f['sem']):
                if 'privilege' in rules and same and g['sem']['av'] in ('L', 'P'): out.add((i, j, 'privilege'))
                if 'pivot' in rules and direct and g['sem']['av'] in ('N', 'A'): out.add((i, j, 'pivot'))
    return out
def risk(ctx, app, F, topo, imp, en, mode='full', gamma_c=0.5, depth=3, lik='full', takeover=True):
    """Expected share of the application's asset value put at stake by each finding.
    mode: 'base' = L*S (context-free); 'ctx' = L*E*S*a (exposure and asset share); 'full' = adds host takeover and inferred chains."""
    n = len(F); S = np.array([ctx.severity(f['cve'])[0] for f in F]); L = np.array([ctx.likelihood(f['cve'], lik) for f in F])
    if mode == 'base': return L * S, dict(S=S, L=L, E=np.ones(n), Q=S, K=np.zeros(n), TK=np.zeros(n))
    tot = sum(c['crit'] for c in app['comps']); A = {c['id']: c['crit'] / tot for c in app['comps']}
    E = np.array([imp[f['comp']]['E'] for f in F]); Q = np.array([S[k] * A[f['comp']] for k, f in enumerate(F)])
    if mode == 'ctx': return L * E * Q, dict(S=S, L=L, E=E, Q=Q, K=np.zeros(n), TK=np.zeros(n))
    succ = collections.defaultdict(set)
    for (i, j, _) in en: succ[i].add(j)
    K = np.zeros(n); TK = np.zeros(n)
    for i in range(n):
        seen = {i: 0}; fr = [i]; d = 0
        while fr and d < depth:
            d += 1; nx = []
            for x in fr:
                for y in succ[x]:
                    if y not in seen: seen[y] = d; nx.append(y)
            fr = nx
        K[i] = sum(gamma_c ** d * L[y] * Q[y] for y, d in seen.items() if d > 0)
        if takeover and grants_foothold(F[i]['sem']):          # code execution compromises co-hosted components
            TK[i] = sum(A[c['id']] for c in app['comps'] if c['host'] == F[i]['host'] and c['id'] != F[i]['comp'])
    R = L * E * np.minimum(1.0, Q + TK + K)
    return R, dict(S=S, L=L, E=E, Q=Q, K=K, TK=TK)
