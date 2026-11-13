"""OWL 2 ontology (TBox + SWRL rules) and per-application ABox; reasoning with HermiT through owlready2."""
import time, types, collections
from owlready2 import *
import core
IRI = 'http://purl.org/waro/waro.owl'
def build_tbox():
    onto = get_ontology(IRI + f'#{time.time_ns()}')  # fresh world per call is handled by caller
    return onto
def make(world):
    onto = world.get_ontology(IRI)
    with onto:
        class Asset(Thing): pass
        class WebApplication(Asset): pass
        class Host(Asset): pass
        class NetworkZone(Thing): pass
        class Component(Asset): pass
        for n in ['EdgeComponent', 'RuntimeComponent', 'ApplicationComponent', 'LibraryComponent', 'DataStoreComponent', 'AuxiliaryService', 'AdminComponent']:
            types.new_class(n, (Component,))
        class Product(Thing): pass
        class Vulnerability(Thing): pass
        class Weakness(Thing): pass
        class AttackPattern(Thing): pass
        class Finding(Thing): pass
        AllDisjoint([Asset, NetworkZone, Product, Vulnerability, Weakness, AttackPattern, Finding])
        class hasComponent(WebApplication >> Component): pass
        class hostedOn(Component >> Host, FunctionalProperty): pass
        class reaches(ObjectProperty, TransitiveProperty): range = [Host]
        class connectsTo(reaches): range = [Host]
        class forwardsTo(Host >> Host): pass
        connectsTo.property_chain.append(PropertyChain([connectsTo, forwardsTo]))
        class runsProduct(Component >> Product): pass
        class affects(Vulnerability >> Product): pass
        class hasWeakness(Vulnerability >> Weakness): pass
        class childOf(Weakness >> Weakness, TransitiveProperty): pass
        class canPrecede(Weakness >> Weakness): pass
        class targetedBy(Weakness >> AttackPattern): pass
        class patternPrecedes(AttackPattern >> AttackPattern): pass
        class onComponent(Finding >> Component, FunctionalProperty): pass
        class ofVulnerability(Finding >> Vulnerability, FunctionalProperty): pass
        class onHost(Finding >> Host): pass
        onHost.property_chain.append(PropertyChain([onComponent, hostedOn]))
        class exhibits(Finding >> Weakness): pass
        exhibits.property_chain.append(PropertyChain([ofVulnerability, hasWeakness]))
        exhibits.property_chain.append(PropertyChain([exhibits, childOf]))
        class exposedTo(Finding >> AttackPattern): pass
        exposedTo.property_chain.append(PropertyChain([exhibits, targetedBy]))
        class enables(Finding >> Finding): pass
        class enablesByWeakness(enables): pass
        class enablesByPattern(enables): pass
        class enablesByPrivilege(enables): pass
        class enablesByPivot(enables): pass
        class compromises(Finding >> Component): pass
        class attackVector(Vulnerability >> str, FunctionalProperty): pass
        class privilegesRequired(Vulnerability >> str, FunctionalProperty): pass
        class userInteraction(Vulnerability >> str, FunctionalProperty): pass
        class confImpact(Vulnerability >> str, FunctionalProperty): pass
        class integImpact(Vulnerability >> str, FunctionalProperty): pass
        class availImpact(Vulnerability >> str, FunctionalProperty): pass
        class cvssBase(Vulnerability >> float, FunctionalProperty): pass
        class epssScore(Vulnerability >> float, FunctionalProperty): pass
        class knownExploited(Vulnerability >> bool, FunctionalProperty): pass
        class assetValue(Component >> float, FunctionalProperty): pass
        class cpeName(Product >> str, FunctionalProperty): pass
        class ExposedHost(Host): equivalent_to = [Host & Inverse(connectsTo).some(NetworkZone)]
        class FootholdGranting(Vulnerability): equivalent_to = [Vulnerability & confImpact.value('H') & integImpact.value('H')]
        class LocalVulnerability(Vulnerability): equivalent_to = [Vulnerability & (attackVector.value('L') | attackVector.value('P'))]
        class RemoteVulnerability(Vulnerability): equivalent_to = [Vulnerability & (attackVector.value('N') | attackVector.value('A'))]
        class FootholdFinding(Finding): equivalent_to = [Finding & ofVulnerability.some(FootholdGranting)]
        class EntryPointFinding(Finding): equivalent_to = [Finding & ofVulnerability.some(RemoteVulnerability) & onHost.some(ExposedHost)]
        rules = [
          'exhibits(?f, ?w1), canPrecede(?w1, ?w2), exhibits(?g, ?w2), onHost(?f, ?h), onHost(?g, ?h) -> enablesByWeakness(?f, ?g)',
          'exhibits(?f, ?w1), canPrecede(?w1, ?w2), exhibits(?g, ?w2), onHost(?f, ?h1), onHost(?g, ?h2), reaches(?h1, ?h2) -> enablesByWeakness(?f, ?g)',
          'exposedTo(?f, ?a1), patternPrecedes(?a1, ?a2), exposedTo(?g, ?a2), onHost(?f, ?h), onHost(?g, ?h) -> enablesByPattern(?f, ?g)',
          'exposedTo(?f, ?a1), patternPrecedes(?a1, ?a2), exposedTo(?g, ?a2), onHost(?f, ?h1), onHost(?g, ?h2), reaches(?h1, ?h2) -> enablesByPattern(?f, ?g)',
          'FootholdFinding(?f), onHost(?f, ?h), onHost(?g, ?h), ofVulnerability(?g, ?v), LocalVulnerability(?v) -> enablesByPrivilege(?f, ?g)',
          'FootholdFinding(?f), onHost(?f, ?h1), connectsTo(?h1, ?h2), onHost(?g, ?h2), ofVulnerability(?g, ?v), RemoteVulnerability(?v) -> enablesByPivot(?f, ?g)',
          'FootholdFinding(?f), onHost(?f, ?h), hostedOn(?c, ?h) -> compromises(?f, ?c)']
        for r in rules: Imp().set_as_rule(r)
    return onto
ROLE = {'edge': 'EdgeComponent', 'runtime': 'RuntimeComponent', 'app': 'ApplicationComponent', 'lib': 'LibraryComponent', 'db': 'DataStoreComponent', 'aux': 'AuxiliaryService', 'admin': 'AdminComponent'}
def populate(onto, ctx, app, F):
    o = onto; ind = {}
    def name(x): return x.replace('-', '_').replace(':', '_').replace('.', '_').replace('\\', '').replace('!', '')
    with onto:
        net = o.NetworkZone('Internet'); webapp = o.WebApplication('app')
        hosts = {h: o.Host(h) for h in sorted({c['host'] for c in app['comps']})}
        for a, b in app['links']:
            (net if a == 'Internet' else hosts[a]).connectsTo.append(hosts[b])
        for a, b in app['forwards']: hosts[a].forwardsTo.append(hosts[b])
        comps = {}
        for c in app['comps']:
            ci = o[ROLE[c['role']]](c['id']); ci.hostedOn = hosts[c['host']]; ci.assetValue = float(c['crit']); webapp.hasComponent.append(ci)
            p = o.Product(name('cpe_' + c['vendor'] + '_' + c['product'] + '_' + c['version'])); p.cpeName = f"cpe:2.3:a:{c['vendor']}:{c['product']}:{c['version']}"; ci.runsProduct.append(p); comps[c['id']] = (ci, p)
        cw_used = set()
        for f in F:
            for w in f['cwes']: cw_used.update(ctx.anc(w))
        W = {w: o.Weakness(name(w)) for w in sorted(cw_used)}
        for w in cw_used:
            for p in ctx.cw[w]['rel'].get('ChildOf', []):
                if p in W and ctx.cw[p]['abstraction'] != 'Pillar': W[w].childOf.append(W[p])
            for x in ctx.cp.get(w, ()):
                if x in W: W[w].canPrecede.append(W[x])
        ap_used = {c for w in cw_used for c in ctx.cw[w]['capec'] if c in ctx.ap}
        AP = {a: o.AttackPattern(name(a)) for a in sorted(ap_used)}
        for w in cw_used:
            for c in ctx.cw[w]['capec']:
                if c in AP: W[w].targetedBy.append(AP[c])
        for a in ap_used:
            for x in ctx.acp.get(a, ()):
                if x in AP: AP[a].patternPrecedes.append(AP[x])
        V = {}; FI = []
        for k, f in enumerate(F):
            cve = f['cve']
            if cve not in V:
                v = o.Vulnerability(name(cve)); s = f['sem']; r = ctx.nvd[cve]
                v.attackVector = s['av']; v.privilegesRequired = s['pr']; v.userInteraction = s['ui']; v.confImpact = s['c']; v.integImpact = s['i']; v.availImpact = s['a']
                v.cvssBase = float(ctx.severity(cve)[0] * 10); v.epssScore = float(ctx.likelihood(cve, 'epss')); v.knownExploited = bool(cve in ctx.kev and ctx.kev[cve] < ctx.T)
                for w in f['cwes']: v.hasWeakness.append(W[w])
                V[cve] = v
            V[cve].affects.append(comps[f['comp']][1])
            fi = o.Finding(f'F{k:04d}'); fi.onComponent = comps[f['comp']][0]; fi.ofVulnerability = V[cve]; FI.append(fi)
    return FI
def infer(ctx, app, F, reasoner='hermit'):
    world = World(); onto = make(world); FI = populate(onto, ctx, app, F)
    n_ax = len(world.graph)
    t = time.time()
    with onto:
        if reasoner == 'hermit':
            sync_reasoner_hermit(world, infer_property_values=True, debug=0)      # pass 1: classification, role chains, transitivity
            t1 = time.time() - t
            sync_reasoner_hermit(world, infer_property_values=True, debug=0)      # pass 2: DL-safe rules over the materialised roles
        else: sync_reasoner_pellet(world, infer_property_values=True, infer_data_property_values=False, debug=0)
    dt = time.time() - t
    idx = {fi.name: k for k, fi in enumerate(FI)}; en = set(); comp = set()
    for prop, lab in [(onto.enablesByWeakness, 'weakness'), (onto.enablesByPattern, 'pattern'), (onto.enablesByPrivilege, 'privilege'), (onto.enablesByPivot, 'pivot')]:
        for a, b in prop.get_relations():
            i, j = idx[a.name], idx[b.name]
            if i != j and F[i]['cve'] != F[j]['cve']: en.add((i, j, lab))
    for a, b in onto.compromises.get_relations(): comp.add((idx[a.name], b.name))
    cls = dict(exposed=sorted(h.name for h in onto.ExposedHost.instances()), foothold=sorted(idx[f.name] for f in onto.FootholdFinding.instances()), entry=sorted(idx[f.name] for f in onto.EntryPointFinding.instances()))
    return dict(en=en, comp=comp, cls=cls, time=dt, time1=t1, triples=n_ax, onto=onto, world=world)
