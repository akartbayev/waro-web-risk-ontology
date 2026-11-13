"""Deployment model: catalog of web-stack products (CPE vendor:product, versions), generator of architectures, reference applications."""
import numpy as np
CAT = {
 'edge': [('apache','http_server',['2.4.51','2.4.54','2.4.57']), ('f5','nginx',['1.20.1','1.22.0']), ('haproxy','haproxy',['2.4.22','2.6.6']), ('traefik','traefik',['2.9.6','2.10.4']), ('squid-cache','squid',['5.7'])],
 'runtime': {'php': ('php','php',['8.0.25','8.1.12','8.2.5']), 'java': ('apache','tomcat',['9.0.65','9.0.71','10.1.8']), 'java2': ('eclipse','jetty',['10.0.13','11.0.14']), 'java3': ('oracle','weblogic_server',['12.2.1.4.0','14.1.1.0.0']), 'node': ('nodejs','node.js',['16.17.0','18.12.0','18.16.0']), 'python': ('python','python',['3.9.15','3.10.8','3.11.1'])},
 'app': {'php': [('wordpress','wordpress',['6.0.2','6.1.1','6.2']), ('drupal','drupal',['9.4.5','9.5.3']), ('joomla','joomla\\!',['4.2.6','4.3.1']), ('craftcms','craft_cms',['4.3.5']), ('typo3','typo3',['11.5.20']), ('prestashop','prestashop',['8.0.1']), ('mediawiki','mediawiki',['1.39.1']), ('nextcloud','nextcloud_server',['25.0.2']), ('roundcube','webmail',['1.6.0']), ('getgrav','grav',['1.7.40'])],
         'java': [('atlassian','confluence_server',['7.19.5','8.3.0']), ('apache','struts',['2.5.30','6.1.1']), ('vmware','spring_framework',['5.3.20','5.3.24']), ('apache','ofbiz',['18.12.06'])],
         'node': [('strapi','strapi',['4.5.5']), ('openjsf','express',['4.18.2'])],
         'python': [('djangoproject','django',['3.2.15','4.1.5']), ('apache','superset',['2.0.0']), ('apache','airflow',['2.5.0'])]},
 'lib': {'php': [('jquery','jquery',['3.4.1','3.5.1']), ('sensiolabs','symfony',['5.4.16']), ('openssl','openssl',['1.1.1q','3.0.7'])],
         'java': [('apache','log4j',['2.14.1','2.17.0']), ('fasterxml','jackson-databind',['2.13.2']), ('apache','shiro',['1.10.0']), ('snakeyaml_project','snakeyaml',['1.30']), ('apache','commons_text',['1.9']), ('jquery','jquery',['3.4.1'])],
         'node': [('lodash','lodash',['4.17.20']), ('jquery','jquery',['3.4.1']), ('openssl','openssl',['3.0.7'])],
         'python': [('python','pillow',['9.3.0']), ('openssl','openssl',['1.1.1q','3.0.7']), ('jquery','jquery',['3.5.1'])]},
 'db': [('oracle','mysql',['8.0.30','8.0.32']), ('mariadb','mariadb',['10.6.10']), ('postgresql','postgresql',['13.8','14.5']), ('mongodb','mongodb',['5.0.13'])],
 'aux': [('redis','redis',['6.2.7','7.0.5']), ('elastic','elasticsearch',['7.17.6']), ('apache','solr',['8.11.2']), ('memcached','memcached',['1.6.17']), ('apache','couchdb',['3.2.2']), ('apache','activemq',['5.17.2']), ('minio','minio',['2022-12-12t19-27-27z']), ('redhat','keycloak',['20.0.2'])],
 'admin': [('phpmyadmin','phpmyadmin',['5.1.3']), ('jenkins','jenkins',['2.375.1']), ('grafana','grafana',['9.3.1']), ('jetbrains','teamcity',['2022.10.1']), ('zabbix','zabbix',['6.0.12']), ('cacti','cacti',['1.2.22']), ('hashicorp','vault',['1.12.2'])],
}
RT = {'php': ['php'], 'java': ['java', 'java2', 'java3'], 'node': ['node'], 'python': ['python']}
def comp(cid, role, host, prod, version, crit): return dict(id=cid, role=role, host=host, vendor=prod[0], product=prod[1], version=version, crit=crit)
def build(name, edge, runtime, apps, libs, db, aux, admin, admin_exposed, crit):
    """Returns dict(name, comps, links, hosted). Links are host-level directed network reachability; 'forwards' marks reverse-proxy forwarding."""
    comps = []; links = []; fw = []
    comps.append(comp('edge', 'edge', 'h_edge', edge[0], edge[1], crit['edge']))
    comps.append(comp('runtime', 'runtime', 'h_app', runtime[0], runtime[1], crit['app']))
    for i, a in enumerate(apps): comps.append(comp(f'app{i+1}', 'app', 'h_app', a[0], a[1], crit['app']))
    for i, l in enumerate(libs): comps.append(comp(f'lib{i+1}', 'lib', 'h_app', l[0], l[1], crit['app']))
    comps.append(comp('db', 'db', 'h_db', db[0], db[1], crit['db']))
    for i, x in enumerate(aux): comps.append(comp(f'aux{i+1}', 'aux', f'h_aux{i+1}', x[0], x[1], crit['aux'][i]))
    links += [('Internet', 'h_edge'), ('h_edge', 'h_app'), ('h_app', 'h_db')] + [('h_app', f'h_aux{i+1}') for i in range(len(aux))]
    fw.append(('h_edge', 'h_app'))
    if admin:
        comps.append(comp('admin', 'admin', 'h_admin', admin[0], admin[1], crit['admin']))
        links += [('h_admin', 'h_db'), ('h_admin', 'h_app')] + [('h_admin', f'h_aux{i+1}') for i in range(len(aux))]
        if admin_exposed: links.append(('Internet', 'h_admin'))
    return dict(name=name, comps=comps, links=links, forwards=fw)
def generate(rng, name):
    fam = rng.choice(['php', 'java', 'node', 'python'], p=[0.4, 0.3, 0.15, 0.15])
    pick = lambda item: (item, str(rng.choice(item[2])))
    edge = pick(CAT['edge'][rng.integers(len(CAT['edge']))])
    runtime = pick(CAT['runtime'][str(rng.choice(RT[fam]))])
    al = CAT['app'][fam]; na = min(len(al), int(rng.integers(1, 3)))
    apps = [pick(al[i]) for i in rng.choice(len(al), na, replace=False)]
    ll = CAT['lib'][fam]; nl = int(rng.integers(1, len(ll) + 1))
    libs = [pick(ll[i]) for i in rng.choice(len(ll), nl, replace=False)]
    db = pick(CAT['db'][rng.integers(len(CAT['db']))])
    nx = int(rng.integers(0, 4)); aux = [pick(CAT['aux'][i]) for i in rng.choice(len(CAT['aux']), nx, replace=False)]
    admin = pick(CAT['admin'][rng.integers(len(CAT['admin']))]) if rng.random() < 0.6 else None
    lv = [0.25, 0.5, 0.75, 1.0]
    crit = dict(edge=float(rng.choice([0.25, 0.5])), app=float(rng.choice([0.5, 0.75, 1.0])), db=float(rng.choice([0.75, 1.0])), aux=[float(rng.choice(lv)) for _ in aux], admin=float(rng.choice([0.5, 0.75])))
    return build(name, edge, runtime, apps, libs, db, aux, admin, rng.random() < 0.25, crit)
def P(role_key, vendor, product, version, fam=None):
    return ((vendor, product, None), version)
def reference_apps():
    A = []
    A.append(build('RA1 (PHP content portal)', P(0,'apache','http_server','2.4.54'), P(0,'php','php','8.1.12'), [P(0,'wordpress','wordpress','6.1.1')],
        [P(0,'jquery','jquery','3.4.1'), P(0,'openssl','openssl','3.0.7')], P(0,'oracle','mysql','8.0.30'), [P(0,'redis','redis','7.0.5')], P(0,'phpmyadmin','phpmyadmin','5.1.3'), False,
        dict(edge=0.5, app=0.75, db=1.0, aux=[0.5], admin=0.75)))
    A.append(build('RA2 (Java enterprise service)', P(0,'f5','nginx','1.22.0'), P(0,'apache','tomcat','9.0.65'), [P(0,'vmware','spring_framework','5.3.20'), P(0,'apache','struts','2.5.30')],
        [P(0,'apache','log4j','2.14.1'), P(0,'fasterxml','jackson-databind','2.13.2'), P(0,'apache','shiro','1.10.0')], P(0,'postgresql','postgresql','14.5'),
        [P(0,'elastic','elasticsearch','7.17.6'), P(0,'apache','activemq','5.17.2')], P(0,'jenkins','jenkins','2.375.1'), True,
        dict(edge=0.5, app=1.0, db=1.0, aux=[0.5, 0.75], admin=0.75)))
    A.append(build('RA3 (Node.js headless CMS)', P(0,'traefik','traefik','2.9.6'), P(0,'nodejs','node.js','18.12.0'), [P(0,'strapi','strapi','4.5.5')],
        [P(0,'lodash','lodash','4.17.20'), P(0,'openssl','openssl','3.0.7')], P(0,'mongodb','mongodb','5.0.13'), [P(0,'redis','redis','7.0.5'), P(0,'minio','minio','2022-12-12t19-27-27z')], P(0,'grafana','grafana','9.3.1'), False,
        dict(edge=0.5, app=0.75, db=1.0, aux=[0.5, 0.75], admin=0.5)))
    return A
