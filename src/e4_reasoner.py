import sys,time,json,pickle; sys.path.insert(0,'.'); import core, apps, onto, collections, numpy as np
ctx=core.Context('2024-04-01'); out={'ref':[], 'scal':[]}
for a in apps.reference_apps():
    F=ctx.findings(a); topo=core.topology(a); ref=core.enables_closure(ctx,F,topo)
    r=onto.infer(ctx,a,F)
    tk={(i,c['id']) for i,f in enumerate(F) if core.grants_foothold(f['sem']) for c in a['comps'] if c['host']==f['host']}
    o=r['onto']
    out['ref'].append(dict(name=a['name'],comps=len(a['comps']),findings=len(F),cves=len({f['cve'] for f in F}),triples=r['triples'],time=r['time'],time1=r['time1'],
        edges=len(r['en']),pairs=len({(i,j) for i,j,_ in r['en']}),by=dict(collections.Counter(x for _,_,x in r['en'])),equal=bool(r['en']==ref),takeover_equal=bool(tk==r['comp']),
        exposed=r['cls']['exposed'],entry=len(r['cls']['entry']),foothold=len(r['cls']['foothold']),
        n_cwe=len(list(o.Weakness.instances())),n_capec=len(list(o.AttackPattern.instances())),n_ind=len(list(o.individuals()))))
    print(out['ref'][-1])
    if a['name'].startswith('RA2'): o.save('work/waro_ra2.owl')
# scalability and agreement on generated deployments
rng=np.random.default_rng(99); agree=0
for i in range(40):
    a=apps.generate(rng,f'S{i}'); F=ctx.findings(a); topo=core.topology(a); t=time.time(); ref=core.enables_closure(ctx,F,topo); tp=time.time()-t
    r=onto.infer(ctx,a,F); eq=bool(r['en']==ref); agree+=eq
    out['scal'].append(dict(findings=len(F),triples=r['triples'],time=r['time'],time1=r['time1'],edges=len(r['en']),equal=eq,tpy=tp)); print(i,out['scal'][-1],flush=True)
print('agree',agree)
json.dump(out,open('work/res_e4.json','w'),indent=1)
