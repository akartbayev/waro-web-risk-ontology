import pickle, json, numpy as np, matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
plt.rcParams.update({'font.family':'Liberation Sans','font.size':9,'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':0.6,'savefig.dpi':600,'savefig.bbox':'tight'})
C={'CVSS':'#D55E00','EPSS':'#0072B2','CVSS x EPSS':'#56B4E9','L (full)':'#009E73','R0 = L x S':'#000000'}
LS={'CVSS':':','EPSS':'--','CVSS x EPSS':'-.','L (full)':'-','R0 = L x S':'-'}
LAB={'CVSS':'CVSS','EPSS':'EPSS','CVSS x EPSS':'CVSS × EPSS','L (full)':'Graph-adjusted likelihood L','R0 = L x S':'Context-free risk L × S'}
cur=pickle.load(open('curves_e3.pkl','rb')); res=json.load(open('res_e3.json'))
fig,ax=plt.subplots(1,3,figsize=(7.2,2.7),sharey=True)
for a,T,l in zip(ax,['2023-04-01','2024-04-01','2025-04-01'],'abc'):
    for k in C:
        x,y=cur[(T,k)]; a.plot(x*100,y*100,color=C[k],ls=LS[k],lw=1.6 if k in('L (full)','R0 = L x S') else 1.2,label=LAB[k])
    a.set_xscale('log'); a.set_xlim(0.01,100); a.set_ylim(0,100); a.grid(True,lw=0.3,color='#cccccc'); a.set_xlabel('Effort (% of CVEs)',fontsize=8)
    a.set_title(f'({l}) {T}',fontsize=9)
ax[0].set_ylabel('Coverage (% of later KEV entries)')
fig.legend(*ax[0].get_legend_handles_labels(),loc='lower center',ncol=5,frameon=False,bbox_to_anchor=(0.5,-0.2),fontsize=7.5,handlelength=2.2,columnspacing=1.2)
fig.savefig('fig/fig_cov.png'); plt.close()
# reasoner runtime
r=json.load(open('res_e4.json')); s=r['scal']+[dict(findings=x['findings'],time=x['time'],time1=x['time1'],edges=x['edges']) for x in r['ref']]
f=np.array([x['findings'] for x in s]); t=np.array([x['time'] for x in s]); t1=np.array([x['time1'] for x in s]); e=np.array([x['edges'] for x in s])
fig,ax=plt.subplots(1,2,figsize=(6.6,2.6))
ax[0].scatter(f,t,s=16,color='#0072B2',label='Both passes',edgecolor='white',lw=0.4); ax[0].scatter(f,t1,s=16,color='#E69F00',marker='^',label='Pass 1 only',edgecolor='white',lw=0.4)
ax[0].set_xlabel('Findings in the application'); ax[0].set_ylabel('HermiT wall time (s)'); ax[0].legend(frameon=False,fontsize=8); ax[0].set_title('(a)',fontsize=9); ax[0].grid(True,lw=0.3,color='#cccccc')
ax[1].scatter(e,t,s=16,color='#0072B2',edgecolor='white',lw=0.4); ax[1].set_xlabel('Inferred enabling relations'); ax[1].set_ylabel('HermiT wall time (s)'); ax[1].set_title('(b)',fontsize=9); ax[1].grid(True,lw=0.3,color='#cccccc')
fig.tight_layout(); fig.savefig('fig/fig_reasoner.png'); plt.close()
# ---- diagrams
def box(ax,x,y,w,h,text,fc='#ffffff',ec='#333333',fs=8,bold=False):
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.02,rounding_size=0.08',fc=fc,ec=ec,lw=0.8)); ax.text(x+w/2,y+h/2,text,ha='center',va='center',fontsize=fs,fontweight='bold' if bold else 'normal')
def arrow(ax,p,q,text=None,rad=0.0,fs=7,color='#333333',ls='-',off=(0,0.08)):
    ax.add_patch(FancyArrowPatch(p,q,arrowstyle='-|>',mutation_scale=8,lw=0.8,color=color,connectionstyle=f'arc3,rad={rad}',linestyle=ls,shrinkA=2,shrinkB=2))
    if text: ax.text((p[0]+q[0])/2+off[0],(p[1]+q[1])/2+off[1],text,ha='center',va='center',fontsize=fs,color=color,style='italic',bbox=dict(fc='white',ec='none',pad=0.5))
# Fig 1 pipeline
fig,ax=plt.subplots(figsize=(7.2,3.5)); ax.set_xlim(0,14.4); ax.set_ylim(0,7.0); ax.axis('off')
g1='#E8F1FA'; g2='#EAF6EF'; g3='#FDF3E1'; g4='#F3ECF8'; F=7
for i,(t) in enumerate(['NVD (CVE,\nCPE, CVSS)','CWE 5.0','CAPEC 3.9','EPSS scores','CISA KEV']): box(ax,0.1,5.55-i*0.95,2.3,0.75,t,g1,fs=F)
ax.text(1.25,6.6,'Open sources',ha='center',fontsize=F,fontweight='bold')
box(ax,0.1,0.2,2.3,1.0,'Deployment model\n(components,\nhosts, links)',g3,fs=F)
box(ax,3.4,3.6,2.8,2.4,'Knowledge graph,\nWARO ontology\n(OWL 2 TBox,\n7 DL-safe rules)',g2,fs=F)
box(ax,3.4,0.6,2.8,1.9,'Application ABox\n(CPE matching,\nfindings)',g2,fs=F)
box(ax,7.1,3.6,2.9,2.4,'Graph priors and\nrecovery of gaps\n(weakness, product,\nexploit profile)',g4,fs=F)
box(ax,7.1,0.6,2.9,1.9,'HermiT reasoning\n(exposure, footholds,\nenabling chains)',g4,fs=F)
box(ax,10.9,2.3,3.4,2.6,'Contextual risk model\n(likelihood, exposure,\nasset value at stake,\npercentile scale)',g3,fs=F)
box(ax,10.9,0.3,3.4,1.1,'Ranked risk report\nwith attack chains',g1,fs=F)
for i in range(5): arrow(ax,(2.4,5.92-i*0.95),(3.4,4.8))
arrow(ax,(2.4,0.7),(3.4,1.5)); arrow(ax,(4.8,3.6),(4.8,2.5)); arrow(ax,(6.2,4.8),(7.1,4.8)); arrow(ax,(6.2,1.55),(7.1,1.55)); arrow(ax,(10.0,4.8),(10.9,4.0)); arrow(ax,(10.0,1.55),(10.9,3.0)); arrow(ax,(12.6,2.3),(12.6,1.4))
fig.savefig('fig/fig_pipeline.png'); plt.close()
# Fig 2 ontology schema
fig,ax=plt.subplots(figsize=(7.2,4.3)); ax.set_xlim(0,14.4); ax.set_ylim(0,8.6); ax.axis('off')
w,h=2.6,0.75
N={'WebApplication':(0.2,7.6),'Component':(0.2,5.3),'Host':(0.2,3.0),'NetworkZone':(0.2,0.9),'Product':(5.0,7.6),'Finding':(5.0,5.3),'Vulnerability':(9.8,7.6),'Weakness':(9.8,5.3),'AttackPattern':(9.8,3.0)}
col={'WebApplication':g3,'Component':g3,'Host':g3,'NetworkZone':g3,'Product':g1,'Vulnerability':g1,'Weakness':g1,'AttackPattern':g1,'Finding':g2}
for k,(x,y) in N.items(): box(ax,x,y,w,h,k,col[k],bold=True,fs=7.5)
def c(k,side):
    x,y=N[k]; return {'t':(x+w/2,y+h),'b':(x+w/2,y),'l':(x,y+h/2),'r':(x+w,y+h/2)}[side]
L=6.5
arrow(ax,c('WebApplication','b'),c('Component','t'),'hasComponent',off=(0,0),fs=L); arrow(ax,c('Component','b'),c('Host','t'),'hostedOn',off=(0,0),fs=L); arrow(ax,c('NetworkZone','t'),c('Host','b'),'connectsTo',off=(0,0),fs=L)
ax.text(1.75,2.45,'connectsTo, forwardsTo, reaches\n(transitive) between hosts',fontsize=L,style='italic',ha='left',va='center')
arrow(ax,(2.8,6.0),(5.0,7.7),'runsProduct',off=(-0.75,0.0),fs=L); arrow(ax,c('Finding','l'),c('Component','r'),'onComponent',off=(0,0.2),fs=L)
arrow(ax,(5.4,5.3),(2.8,3.7),'onHost*',off=(0.2,-0.3),ls='--',fs=L)
arrow(ax,(5.0,5.45),(2.8,5.45),None,ls='--'); ax.text(3.9,5.2,'compromises*',fontsize=L,style='italic',ha='center',color='#333333')
arrow(ax,c('Vulnerability','l'),c('Product','r'),'affects',off=(0,0.2),fs=L); arrow(ax,(7.6,6.0),(9.8,7.7),'ofVulnerability',off=(-0.9,0.0),fs=L); arrow(ax,c('Vulnerability','b'),c('Weakness','t'),'hasWeakness',off=(0,0),fs=L)
arrow(ax,c('Finding','r'),c('Weakness','l'),'exhibits*',off=(0,0.2),ls='--',fs=L); arrow(ax,(7.2,5.3),(9.8,3.7),'exposedTo*',off=(-0.2,-0.3),ls='--',fs=L); arrow(ax,c('Weakness','b'),c('AttackPattern','t'),'targetedBy',off=(0,0),fs=L)
ax.text(12.55,5.675,'childOf (transitive),\ncanPrecede',fontsize=L,style='italic',va='center'); ax.text(12.55,3.375,'patternPrecedes',fontsize=L,style='italic',va='center')
arrow(ax,(5.9,5.3),(6.9,5.3),None,rad=2.0,ls='--'); ax.text(6.4,3.75,'enables* (byWeakness,\nbyPattern, byPrivilege,\nbyPivot)',fontsize=L,style='italic',ha='center',va='center')
box(ax,3.6,0.5,7.6,1.5,'Defined classes, classified by the reasoner:\nExposedHost, FootholdGranting, LocalVulnerability,\nRemoteVulnerability, FootholdFinding, EntryPointFinding',fc='#F7F7F7',fs=6.5)
ax.text(11.5,1.25,'Solid arrows: asserted\nDashed arrows (*): inferred',fontsize=6.5,va='center')
fig.savefig('fig/fig_onto.png'); plt.close()
