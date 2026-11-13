import sys; sys.path.insert(0,'.')
import numpy as np, json, pickle
from sklearn.metrics import roc_auc_score, average_precision_score
from e3_global import snapshot, scores, cov
rng=np.random.default_rng(7); res={}; curves={}
for T in ['2023-04-01','2024-04-01','2025-04-01']:
    d=snapshot(T); y=d['y']; L=scores(d,1,1,1)
    S={'CVSS':d['s'],'EPSS':d['e'],'CVSS x EPSS':d['s']*d['e'],'L (EPSS + weakness prior)':scores(d,1,0,0),'L (EPSS + product prior)':scores(d,0,1,0),'L (EPSS + profile prior)':scores(d,0,0,1),'L (full)':L,'R0 = L x S':L*d['s']}
    out={'n':len(y),'pos':int(y.sum()),'n_web':int(d['web'].sum()),'pos_web':int(y[d['web']].sum()),'base':d['g']}
    pos=np.where(y==1)[0]; neg=np.where(y==0)[0]
    # bootstrap (stratified; negatives subsampled 20k for speed) for AUC CI and paired difference vs EPSS
    B=1000; negs=rng.choice(neg,20000,replace=False); boot={k:[] for k in S}
    for b in range(B):
        ip=rng.choice(pos,len(pos)); ineg=rng.choice(negs,len(negs)); idx=np.concatenate([ip,ineg]); yy=y[idx]
        for k,sc in S.items(): boot[k].append(roc_auc_score(yy,sc[idx]))
    for k,sc in S.items():
        w=d['web']; bb=np.array(boot[k]); dd=bb-np.array(boot['EPSS'])
        out[k]=dict(auc=roc_auc_score(y,sc),lo=float(np.percentile(bb,2.5)),hi=float(np.percentile(bb,97.5)),ap=average_precision_score(y,sc),
            cov1=cov(y,sc,.01),cov5=cov(y,sc,.05),cov10=cov(y,sc,.10),cov20=cov(y,sc,.20),auc_web=roc_auc_score(y[w],sc[w]),cov5_web=cov(y[w],sc[w],.05),cov10_web=cov(y[w],sc[w],.10),
            d_lo=float(np.percentile(dd,2.5)),d_hi=float(np.percentile(dd,97.5)),p_gt=float((dd<=0).mean()))
        o=np.argsort(-sc,kind='stable'); cy=np.cumsum(y[o])/y.sum(); xs=np.unique(np.round(np.logspace(1,np.log10(len(y)),300)).astype(int))-1
        curves[(T,k)]=((xs+1)/len(y),cy[xs])
    res[T]=out; print(T,{k:out[k] for k in ['n','pos','n_web','pos_web']})
    for k in S: print('  %-28s'%k,' '.join('%s=%.3f'%kv for kv in out[k].items()))
json.dump(res,open('work/res_e3.json','w'),indent=1); pickle.dump(curves,open('work/curves_e3.pkl','wb'))
