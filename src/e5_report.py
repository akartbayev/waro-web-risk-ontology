import pickle, sys, numpy as np
from scipy.stats import wilcoxon
res=pickle.load(open(sys.argv[1],'rb')); KS=[0,1,2,3,5,8,10,15,20,30]
print('apps',len(res),'median findings',np.median([r['n'] for r in res]),'median enables',np.median([r['n_en'] for r in res]))
for sn in res[0]['loss']:
    names=list(res[0]['loss'][sn]); base=np.array([r['loss'][sn]['Random'][0] for r in res]); ok=base>0.005
    print('==',sn,'apps with loss',ok.sum(),'mean base loss %.3f'%base[ok].mean()); A={}
    for k in names:
        M=np.array([r['loss'][sn][k] for r in res])[ok]; rel=M/M[:,[0]]; A[k]=np.trapezoid(rel[:,:7],KS[:7],axis=1)/10
        print('  %-32s'%k,' '.join('%.3f'%x for x in rel.mean(0)),' AUC10=%.3f'%A[k].mean())
    for a,b in [('R2 (full)','CVSS'),('R2 (full)','KEV then CVSS'),('R2 (full)','KEV then EPSS'),('R2 (full)','R0 (L x S)'),('R2 (full)','R1 (+ importance)')]:
        d=A[a]-A[b]; print('    ',a,'vs',b,'diff %.4f'%d.mean(),'wins %.2f'%(d<0).mean(),'p=%.2g'%(wilcoxon(A[a],A[b]).pvalue if (d!=0).any() else 1))
