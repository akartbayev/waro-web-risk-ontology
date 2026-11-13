import sys; sys.path.insert(0,'.')
import kb, priors, numpy as np, collections, json
from sklearn.linear_model import Ridge
nvd=kb.load_nvd(); cw,cats,views=kb.load_cwe(); ap=kb.load_capec()
def band(x): return 0 if x<4 else 1 if x<7 else 2 if x<9 else 3
res={}
for T in ['2023-04-01','2024-04-01','2025-04-01']:
    H=f'{int(T[:4])+1}{T[4:]}'; ep=kb.load_epss(T)
    tr=[(c,r) for c,r in nvd.items() if r['pub']<T and r['v3'] is not None]
    te=[(c,r) for c,r in nvd.items() if T<=r['pub']<H and r['v3'] is not None and any(w in cw for w in r['cwes'])]
    # split train into fit part (priors) and blend part (last 12 months before T) to learn blending weights without leakage
    B=f'{int(T[:4])-1}{T[4:]}'
    def build(rows):
        sh=priors.Shrink(cw); pr=collections.defaultdict(list)
        for c,r in rows:
            sh.add(r['cwes'],r['v3'])
            for p in r['prods']: pr[p[1:]].append(r['v3'])
        return sh,pr
    def feats(rows,sh,pr):
        X=[];g=sh.glob()
        for c,r in rows:
            a=sh.est(r['cwes']); b=priors.capec_sev(cw,ap,r['cwes'])
            pv=[np.mean(pr[p[1:]]) for p in r['prods'] if p[1:] in pr]; pn=sum(len(pr[p[1:]]) for p in r['prods'] if p[1:] in pr)
            pm=np.mean(pv) if pv else None
            wgt=pn/(pn+5.0) if pv else 0
            X.append([a if a is not None else g, b if b is not None else g, (wgt*pm+(1-wgt)*(a if a is not None else g)) if pv else (a if a is not None else g), 1.0 if b is not None else 0.0, 1.0 if pv else 0.0])
        return np.array(X)
    sh0,pr0=build([x for x in tr if x[1]['pub']<B]); blend=[x for x in tr if x[1]['pub']>=B and any(w in cw for w in x[1]['cwes'])]
    Xb=feats(blend,sh0,pr0); yb=np.array([r['v3'] for c,r in blend])
    m_full=Ridge(1.0).fit(Xb,yb); m_cc=Ridge(1.0).fit(Xb[:,[0,1,3]],yb)
    sh,pr=build(tr); Xt=feats(te,sh,pr); y=np.array([r['v3'] for c,r in te])
    ex=collections.defaultdict(list)
    for c,r in tr:
        for w in r['cwes']: ex[w].append(r['v3'])
    exm={w:np.mean(v) for w,v in ex.items()}; g=sh.glob()
    P={'Global mean':np.full(len(y),g),
       'CAPEC typical severity':Xt[:,1],
       'Flat CWE mean':np.array([np.mean([exm.get(w,g) for w in r['cwes'] if w in cw]) for c,r in te]),
       'Hierarchical CWE':Xt[:,0],
       'Hierarchical CWE + CAPEC':np.clip(m_cc.predict(Xt[:,[0,1,3]]),0,10),
       'Full graph (CWE + CAPEC + CPE history)':np.clip(m_full.predict(Xt),0,10)}
    out={}
    for k,p in P.items():
        e=np.abs(p-y); out[k]=dict(mae=float(e.mean()),rmse=float(np.sqrt(((p-y)**2).mean())),within1=float((e<=1).mean()),band=float(np.mean([band(a)==band(b) for a,b in zip(p,y)])))
    out['n_test']=len(y); out['n_train']=len(tr); out['capec_cov']=float(Xt[:,3].mean()); out['cpe_cov']=float(Xt[:,4].mean()); out['coef']=m_full.coef_.tolist()
    res[T]=out; print(T,json.dumps(out,indent=0)[:1500])
json.dump(res,open('work/res_e2.json','w'),indent=1)
