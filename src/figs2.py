import pickle, json, numpy as np, matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
from scipy.stats import wilcoxon
plt.rcParams.update({'font.family':'Liberation Sans','font.size':9,'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':0.6,'savefig.dpi':600,'savefig.bbox':'tight'})
res=pickle.load(open('final_e5.pkl','rb')); KS=[0,1,2,3,5,8,10,15,20,30]
M=['Random','CVSS','EPSS','CVSS x EPSS','KEV then CVSS','KEV then EPSS','R0 (L x S)','R1 (+ importance)','R2 no takeover','R2 (full)','R2 w/o weakness+pattern rules','R2 w/o privilege+pivot rules']
out={'n_apps':len(res),'med_findings':float(np.median([r['n'] for r in res])),'iqr_findings':[float(x) for x in np.percentile([r['n'] for r in res],[25,75])],'med_pairs':float(np.median([r['n_en'] for r in res])),'scen':{}}
A={}
for sn in res[0]['loss']:
    base=np.array([r['loss'][sn]['Random'][0] for r in res]); ok=base>0.005; d={'n':int(ok.sum()),'base':float(base[ok].mean())}
    for k in M:
        X=np.array([r['loss'][sn][k] for r in res])[ok]; rel=X/X[:,[0]]; a=np.trapezoid(rel[:,:7],KS[:7],axis=1)/10; A[(sn,k)]=a
        d[k]=dict(auc=float(a.mean()),k5=float(rel[:,4].mean()),k10=float(rel[:,6].mean()),k20=float(rel[:,8].mean()),curve=[float(x) for x in rel.mean(0)])
    for b in M:
        if b!='R2 (full)':
            dd=A[(sn,'R2 (full)')]-A[(sn,b)]; d[b]['p_vs_R2']=float(wilcoxon(A[(sn,'R2 (full)')],A[(sn,b)]).pvalue) if (dd!=0).any() else 1.0; d[b]['R2_wins']=float((dd<0).mean())
    out['scen'][sn]=d
json.dump(out,open('res_e5.json','w'),indent=1)
main=['CVSS','EPSS','KEV then CVSS','KEV then EPSS','R0 (L x S)','R2 (full)']
for k in M:
    aucs=[out['scen'][s][k]['auc'] for s in out['scen']]; best=[min(out['scen'][s][m]['auc'] for m in M[:10]) for s in out['scen']]
    print('%-32s'%k,' '.join('%.3f'%a for a in aucs),'mean %.3f'%np.mean(aucs),'maxregret %.3f'%max(a-b for a,b in zip(aucs,best)),' p:',' '.join('%.1e'%out['scen'][s][k].get('p_vs_R2',0) for s in out['scen']))
C={'CVSS':'#D55E00','EPSS':'#0072B2','KEV then CVSS':'#E69F00','KEV then EPSS':'#56B4E9','R0 (L x S)':'#009E73','R2 (full)':'#000000'}
LS={'CVSS':':','EPSS':'--','KEV then CVSS':(0,(3,1,1,1)),'KEV then EPSS':'-.','R0 (L x S)':(0,(5,2)),'R2 (full)':'-'}
MK={'CVSS':'s','EPSS':'o','KEV then CVSS':'D','KEV then EPSS':'v','R0 (L x S)':'^','R2 (full)':'o'}
LAB={'CVSS':'CVSS','EPSS':'EPSS','KEV then CVSS':'KEV, then CVSS','KEV then EPSS':'KEV, then EPSS','R0 (L x S)':'Context-free L × S','R2 (full)':'Proposed (full model)'}
fig,ax=plt.subplots(1,3,figsize=(7.2,2.7),sharey=True)
for a,(sn,t) in zip(ax,[('confirmed','(a) Confirmed exploitation'),('broad k=1.0','(b) Broad, κ = 1.0'),('broad k=0.1','(c) Broad, κ = 0.1')]):
    for k in main: a.plot(KS,np.array(out['scen'][sn][k]['curve'])*100,color=C[k],ls=LS[k],marker=MK[k],ms=3,lw=1.8 if k=='R2 (full)' else 1.1,label=LAB[k])
    a.set_title(t,fontsize=9); a.set_xlabel('Findings remediated (k)',fontsize=8); a.grid(True,lw=0.3,color='#cccccc'); a.set_ylim(0,100); a.set_xlim(0,30)
ax[0].set_ylabel('Residual expected loss (%)')
fig.legend(*ax[0].get_legend_handles_labels(),loc='lower center',ncol=6,frameon=False,bbox_to_anchor=(0.5,-0.14),fontsize=7.5,handlelength=2.6,columnspacing=1.0)
fig.savefig('fig/fig_loss.png')
