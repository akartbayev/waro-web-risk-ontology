import sys; sys.path.insert(0,'.')
import kb, priors, core, numpy as np, collections, json
from sklearn.metrics import roc_auc_score, average_precision_score
nvd=kb.load_nvd(); cw,cats,views=kb.load_cwe(); ap=kb.load_capec(); kev=kb.load_kev()
ow={m for k,c in cats.items() if '1344' in c['views'] for m in c['members']}
def isweb(r):
    vec=r['v3vec'] or r['v2vec'] or ''
    return ('AV:N' in vec) and any(a in ow for w in r['cwes'] for a in [w]+kb.ancestors(cw,w))
def snapshot(T):
    H=f'{int(T[:4])+1}{T[4:]}'; ep=kb.load_epss(T)
    pop=[(c,r) for c,r in nvd.items() if r['pub']<T and not (c in kev and kev[c]<T) and c in ep and (r['v3'] is not None or r['v2'] is not None)]
    sh=priors.Shrink(cw,m=200.0); pk=collections.Counter(); pn=collections.Counter(); xk=collections.Counter(); xn=collections.Counter()
    for c,r in nvd.items():
        if r['pub']<T:
            z=1.0 if (c in kev and kev[c]<T) else 0.0
            sh.add(r['cwes'], z)
            for p in r['prods']: pn[p[1:]]+=1; pk[p[1:]]+=z
            x=core.profile(core.vsem(r)); xn[x]+=1; xk[x]+=z
    g=sh.glob(); m=50.0
    def pprod(r):
        v=[(pk[p[1:]]+m*g)/(pn[p[1:]]+m) for p in r['prods']]
        return max(v) if v else g
    d=dict(y=np.array([1 if (c in kev and T<=kev[c]<H) else 0 for c,r in pop]),
      e=np.array([ep[c] for c,r in pop]), s=np.array([(r['v3'] if r['v3'] is not None else r['v2'])/10 for c,r in pop]),
      pw=np.array([(sh.est(r['cwes']) or g) for c,r in pop]), pp=np.array([pprod(r) for c,r in pop]),
      web=np.array([isweb(r) for c,r in pop]), g=g,
      px=np.array([(xk[x]+200*g)/(xn[x]+200) for x in (core.profile(core.vsem(r)) for c,r in pop)]), prof={str(k):(xk[k],xn[k]) for k in xn})
    return d
def scores(d,eta_w,eta_p,eta_x=1):
    L=1-(1-d['e'])*(1-eta_w*d['pw'])*(1-eta_p*d['pp'])*(1-eta_x*d['px'])
    return L
def cov(y,sc,f):
    o=np.argsort(-sc,kind='stable'); return float(np.cumsum(y[o])[int(f*len(y))-1]/y.sum())
