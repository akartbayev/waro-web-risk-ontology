import sys,json,pickle; sys.path.insert(0,'.'); import kb, core, apps, numpy as np, collections
from scipy.stats import kendalltau
T='2024-04-01'; ctx=core.Context(T)
# reference distribution: context-free R0 = L*S for every CVE published before T
ids=[c for c,r in ctx.nvd.items() if r['pub']<T]
ref=np.sort(np.array([ctx.likelihood(c)*ctx.severity(c)[0] for c in ids]))
def pct(x): return np.searchsorted(ref,x,side='right')/len(ref)
q={p:float(np.quantile(ref,p)) for p in (0.5,0.8,0.9,0.95,0.99,0.999)}; print('ref n',len(ref),q)
def band(p): return 'Critical' if p>=0.95 else 'High' if p>=0.80 else 'Medium' if p>=0.50 else 'Low'
out={'ref_q':q,'ref_n':len(ref),'apps':[]}
for a in apps.reference_apps():
    F=ctx.findings(a); topo=core.topology(a); imp=core.importance(a,topo); en=core.enables_closure(ctx,F,topo)
    R,p=core.risk(ctx,a,F,topo,imp,en); R0,_=core.risk(ctx,a,F,topo,imp,en,'base'); R1,_=core.risk(ctx,a,F,topo,imp,en,'ctx')
    tot=sum(c['crit'] for c in a['comps'])
    # normalised score: percentile of the context-adjusted raw score in the reference distribution (reference context = single exposed component)
    P=np.array([pct(x) for x in R]); S=p['S']; E=np.array([ctx.likelihood(f['cve'],'epss') for f in F])
    o=np.argsort(-R,kind='stable'); oc=np.argsort(-S,kind='stable'); oe=np.argsort(-E,kind='stable'); o0=np.argsort(-R0,kind='stable')
    top=[]
    succ=collections.defaultdict(set)
    for i,j,_ in en: succ[i].add(j)
    for k in o[:10]:
        f=F[k]; top.append(dict(comp=f['comp'],product=[c['product'] for c in a['comps'] if c['id']==f['comp']][0],cve=f['cve'],cwe=f['cwes'][:1],cvss=round(S[k]*10,1),epss=round(float(E[k]),4),L=round(float(p['L'][k]),4),E=round(float(p['E'][k]),2),
            stake=round(float(min(1,p['Q'][k]+p['TK'][k]+p['K'][k])),3),K=round(float(p['K'][k]),4),TK=round(float(p['TK'][k]),3),R=float(R[k]),pct=round(float(P[k])*100,2),band=band(P[k]),kev=bool(f['cve'] in ctx.kev and ctx.kev[f['cve']]<T),
            rank_cvss=int(np.where(oc==k)[0][0])+1,rank_epss=int(np.where(oe==k)[0][0])+1,n_succ=len(succ[k])))
    bands=collections.Counter(band(x) for x in P); cb=collections.Counter('Critical' if s>=0.9 else 'High' if s>=0.7 else 'Medium' if s>=0.4 else 'Low' for s in S)
    # sensitivity: perturb gamma_e, gamma_c, depth, library discount; Kendall tau and top-10 overlap against default
    sens=[]
    rng=np.random.default_rng(5)
    for t in range(200):
        ge=rng.uniform(0.3,0.7); gc=rng.uniform(0.3,0.7); dp=int(rng.integers(1,5)); crit_noise=rng.uniform(0.8,1.25,len(a['comps']))
        a2=dict(a); a2['comps']=[dict(c,crit=min(1.0,c['crit']*crit_noise[i])) for i,c in enumerate(a['comps'])]
        imp2=core.importance(a2,topo,gamma=ge); R2,_=core.risk(ctx,a2,F,topo,imp2,en,gamma_c=gc,depth=dp)
        o2=np.argsort(-R2,kind='stable'); sens.append((kendalltau(R,R2)[0],len(set(o[:10])&set(o2[:10]))/10,len(set(o[:5])&set(o2[:5]))/5))
    sens=np.array(sens)
    d=dict(name=a['name'],n=len(F),comps=[(c['id'],c['role'],c['host'],c['vendor']+':'+c['product'],c['version'],c['crit'],round(imp[c['id']]['E'],2),sum(1 for f in F if f['comp']==c['id'])) for c in a['comps']],
        links=a['links'],top=top,bands=dict(bands),cvss_bands=dict(cb),kev_pre=sum(1 for f in F if f['cve'] in ctx.kev and ctx.kev[f['cve']]<T),
        tau_cvss=float(kendalltau(R,S)[0]),tau_epss=float(kendalltau(R,E)[0]),tau_r0=float(kendalltau(R,R0)[0]),
        top10_cvss=len(set(o[:10])&set(oc[:10])),top10_epss=len(set(o[:10])&set(oe[:10])),top10_r0=len(set(o[:10])&set(o0[:10])),
        sens_tau=[float(sens[:,0].mean()),float(sens[:,0].min())],sens_top10=[float(sens[:,1].mean()),float(sens[:,1].min())],sens_top5=[float(sens[:,2].mean()),float(sens[:,2].min())],
        imputed=sum(1 for f in F if ctx.severity(f['cve'])[1]),P=[float(x) for x in P],S=[float(x) for x in S],Estr=[float(x) for x in E])
    out['apps'].append(d)
    print(a['name'],len(F),d['bands'],d['cvss_bands'],'kevpre',d['kev_pre'],'tau cvss %.2f epss %.2f r0 %.2f'%(d['tau_cvss'],d['tau_epss'],d['tau_r0']),'top10 overlap',d['top10_cvss'],d['top10_epss'],d['top10_r0'],'sens',d['sens_tau'],d['sens_top10'],d['sens_top5'])
    for t in top: print('  ',t['comp'],t['product'],t['cve'],t['cwe'],'cvss',t['cvss'],'epss',t['epss'],'L',t['L'],'E',t['E'],'stake',t['stake'],'K',t['K'],'TK',t['TK'],'pct',t['pct'],t['band'],'kev',t['kev'],'rc',t['rank_cvss'],'re',t['rank_epss'],'succ',t['n_succ'])
json.dump(out,open('work/res_e6.json','w'),indent=1)
