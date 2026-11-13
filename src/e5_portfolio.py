import sys,time,json,pickle; sys.path.insert(0,'.'); import kb, core, sim, apps, numpy as np, collections
T='2024-04-01'; ctx=core.Context(T); hind=kb.load_epss('2026-11-10'); kev=ctx.kev
KS=[0,1,2,3,5,8,10,15,20,30]
SCEN={'confirmed':('kev',1.0),'broad k=1.0':('mix',1.0),'broad k=0.3':('mix',0.3),'broad k=0.1':('mix',0.1)}
def evaluate(a, seed, runs=2000):
    F=ctx.findings(a); topo=core.topology(a); imp=core.importance(a,topo); en=core.enables_closure(ctx,F,topo)
    S=np.array([ctx.severity(f['cve'])[0] for f in F]); E=np.array([ctx.likelihood(f['cve'],'epss') for f in F]); K=np.array([1.0 if (f['cve'] in kev and kev[f['cve']]<T) else 0.0 for f in F])
    rb,_=core.risk(ctx,a,F,topo,imp,en,'base'); rc,_=core.risk(ctx,a,F,topo,imp,en,'ctx'); rf,pf=core.risk(ctx,a,F,topo,imp,en,'full'); rnt,_=core.risk(ctx,a,F,topo,imp,en,'full',takeover=False)
    rnk={'Random':np.random.default_rng(seed+1).random(len(F)),'CVSS':S,'EPSS':E,'CVSS x EPSS':S*E,'KEV then CVSS':K*10+S,'KEV then EPSS':K*10+E,'R0 (L x S)':rb,'R1 (+ importance)':rc,'R2 (full)':rf,'R2 no takeover':rnt}
    en_w={(i,j,r) for (i,j,r) in en if r in('privilege','pivot')}; rnk['R2 w/o weakness+pattern rules']=core.risk(ctx,a,F,topo,imp,en_w,'full')[0]
    en_s={(i,j,r) for (i,j,r) in en if r in('weakness','pattern')}; rnk['R2 w/o privilege+pivot rules']=core.risk(ctx,a,F,topo,imp,en_s,'full')[0]
    out={}
    for sn,(kind,kap) in SCEN.items():
        q=np.array([kap*(0.9 if (f['cve'] in kev) else (hind.get(f['cve'],0.0) if kind=='mix' else 0.0)) for f in F])
        P=sim.prepare(ctx,a,F,topo,q,np.random.default_rng(seed),runs)
        out[sn]={k:[sim.expected_loss(P,np.argsort(-sc,kind='stable')[:kk]) for kk in KS] for k,sc in rnk.items()}
    return dict(n=len(F),n_en=len({(i,j) for i,j,_ in en}),loss=out)
if __name__=='__main__':
    seed=int(sys.argv[2]); N=int(sys.argv[1]); rng=np.random.default_rng(seed); res=[]; t=time.time()
    for i in range(N):
        a=apps.generate(rng,f'G{i:03d}'); r=evaluate(a,1000+i); r['name']=a['name']; res.append(r)
    print('time',time.time()-t); pickle.dump(res,open(sys.argv[3],'wb'))
