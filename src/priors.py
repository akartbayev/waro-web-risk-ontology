"""Graph-based estimators used to recover missing attributes (hierarchical shrinkage over CWE ChildOf, CAPEC links, product history)."""
import collections, math, numpy as np, kb
class Shrink:
    """Empirical-Bayes style back-off along the CWE hierarchy: est(w) = (sum_w + m*est(parent)) / (n_w + m)."""
    def __init__(self, cw, m=20.0):
        self.cw = cw; self.m = m; self.s = collections.Counter(); self.n = collections.Counter(); self.gs = 0.0; self.gn = 0; self.memo = {}
    def add(self, cwes, y):
        self.gs += y; self.gn += 1
        seen = set()
        for w in cwes:
            for a in [w] + kb.ancestors(self.cw, w):
                if a not in seen: seen.add(a); self.s[a] += y; self.n[a] += 1
    def glob(self): return self.gs / max(self.gn, 1)
    def est1(self, w):
        if w in self.memo: return self.memo[w]
        ps = self.cw.get(w, {}).get('rel', {}).get('ChildOf', [])
        pe = np.mean([self.est1(p) for p in ps]) if ps else self.glob()
        v = (self.s[w] + self.m * pe) / (self.n[w] + self.m); self.memo[w] = v; return v
    def est(self, cwes):
        ws = [w for w in cwes if w in self.cw]
        return float(np.mean([self.est1(w) for w in ws])) if ws else None
def capec_of(cw, cwes):
    out = set()
    for w in cwes:
        for a in [w] + kb.ancestors(cw, w):
            c = cw.get(a, {}).get('capec', [])
            if c: out.update(c); break      # nearest level that has attack patterns
    return out
def capec_sev(cw, ap, cwes):
    v = [kb.SEV[ap[c]['severity']] for c in capec_of(cw, cwes) if c in ap and ap[c]['severity']]
    return float(np.mean(v)) if v else None
def capec_lik(cw, ap, cwes):
    v = [kb.LIK[ap[c]['likelihood']] for c in capec_of(cw, cwes) if c in ap and ap[c]['likelihood']]
    return float(np.mean(v)) if v else None
def cwe_lik(cw, cwes):
    v = []
    for w in cwes:
        for a in [w] + kb.ancestors(cw, w):
            l = cw.get(a, {}).get('likelihood')
            if l in kb.LIK: v.append(kb.LIK[l]); break
    return float(np.mean(v)) if v else None
