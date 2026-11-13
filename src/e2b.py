import sys; sys.path.insert(0,'.')
import kb, priors, numpy as np, collections, json
from scipy.stats import spearmanr
nvd=kb.load_nvd(); cw,cats,views=kb.load_cwe(); ap=kb.load_capec(); res={}
for T in ['2023-04-01','2024-04-01','2025-04-01']:
    H=f'{int(T[:4])+1}{T[4:]}'; ep=kb.load_epss(T); epH=kb.load_epss(H) if H<='2025-04-01' else kb.load_epss('2026-11-10' if H>'2026-11-01' else '2026-11-01')
    tr=[(c,r) for c,r in nvd.items() if r['pub']<T and r['v3'] is not None]
    te=[(c,r) for c,r in nvd.items() if T<=r['pub']<H and r['v3'] is not None and any(w in cw for w in r['cwes'])]
    sh=priors.Shrink(cw); ex=collections.defaultdict(list)
    for c,r in tr:
        sh.add(r['cwes'],r['v3'])
        for w in r['cwes']: ex[w].append(r['v3'])
    g=sh.glob(); y=np.array([r['v3'] for c,r in te])
    nmin=np.array([min([len(ex.get(w,[])) for w in r['cwes'] if w in cw]) for c,r in te])
    flat=np.array([np.mean([np.mean(ex[w]) if w in ex else g for w in r['cwes'] if w in cw]) for c,r in te]); hier=np.array([sh.est(r['cwes']) for c,r in te])
    out={}
    for lab,m in [('all',nmin>=0),('rare (<30)',nmin<30),('unseen (0)',nmin==0)]:
        out[lab]=dict(n=int(m.sum()),flat=float(np.abs(flat-y)[m].mean()),hier=float(np.abs(hier-y)[m].mean()),glob=float(np.abs(g-y)[m].mean()))
    # likelihood recovery: CVEs published after T have no EPSS at T; estimate from the weakness class, compare with first EPSS available later
    she=priors.Shrink(cw)
    for c,r in nvd.items():
        if r['pub']<T and c in ep: she.add(r['cwes'],np.log10(max(ep[c],1e-5)))
    te2=[(c,r) for c,r in te if c in epH]
    pe=np.array([she.est(r['cwes']) for c,r in te2]); ye=np.array([np.log10(max(epH[c],1e-5)) for c,r in te2])
    cl=np.array([priors.cwe_lik(cw,r['cwes']) or np.nan for c,r in te2]); al=np.array([priors.capec_lik(cw,ap,r['cwes']) or np.nan for c,r in te2])
    out['lik']=dict(n=len(te2),rho_hier=float(spearmanr(pe,ye)[0]),mae_log10=float(np.abs(pe-ye).mean()),mae_glob=float(np.abs(she.glob()-ye).mean()),
        rho_cwe_lik=float(spearmanr(cl[~np.isnan(cl)],ye[~np.isnan(cl)])[0]),cov_cwe_lik=float((~np.isnan(cl)).mean()),rho_capec_lik=float(spearmanr(al[~np.isnan(al)],ye[~np.isnan(al)])[0]),cov_capec_lik=float((~np.isnan(al)).mean()))
    res[T]=out; print(T,json.dumps(out))
json.dump(res,open('work/res_e2b.json','w'),indent=1)
# missingness statistics on the current NVD snapshot
tot=len(nvd); print('total',tot,'no v3',sum(r['v3'] is None for r in nvd.values()),'no cvss any',sum(r['v3'] is None and r['v2'] is None and r['v4'] is None for r in nvd.values()),'no cwe',sum(not any(w in cw for w in r['cwes']) for r in nvd.values()))
r26=[r for r in nvd.values() if r['pub']>='2026-01-01']; print('2026 pubs',len(r26),'no v3',sum(r['v3'] is None for r in r26),'no v3 but v4',sum(r['v3'] is None and r['v4'] is not None for r in r26),'no any',sum(r['v3'] is None and r['v2'] is None and r['v4'] is None for r in r26),'noany with cwe',sum(r['v3'] is None and r['v2'] is None and r['v4'] is None and any(w in cw for w in r['cwes']) for r in r26))
ep=kb.load_epss('2026-11-10'); print('epss cov',sum(c in ep for c in nvd),'missing',sum(c not in ep for c in nvd))
