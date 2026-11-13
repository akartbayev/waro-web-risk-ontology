import sys, json, urllib.request, urllib.parse
def q(s, rows=3):
    u='https://api.crossref.org/works?rows=%d&query.bibliographic=%s&select=DOI,title,author,container-title,issued,volume,issue,page,type'%(rows,urllib.parse.quote(s))
    try: d=json.load(urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'paper-check/1.0 (mailto:research@example.org)'}),timeout=40))
    except Exception as e: print('ERR',s,e); return
    print('##',s)
    for it in d['message']['items']:
        au=', '.join((a.get('family','')+' '+''.join(x[0] for x in a.get('given','').replace('-',' ').split())) for a in it.get('author',[])[:7])
        print('  ',au,'|',(it.get('title') or [''])[0],'|',(it.get('container-title') or [''])[0],'|',it.get('issued',{}).get('date-parts',[[None]])[0],'|',it.get('volume'),it.get('issue'),it.get('page'),'|',it['DOI'],'|',it.get('type'))
import time
for s in sys.argv[1:]:
    q(s); time.sleep(2.5)
