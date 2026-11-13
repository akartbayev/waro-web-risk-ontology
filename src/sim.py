"""Monte Carlo attack simulation used as an external evaluator of patch orderings (CVSS-vector semantics, hindsight exploitability)."""
import numpy as np, core
def prepare(ctx, app, F, topo, q, rng, runs=2000):
    hosts = topo['hosts']; hi = {h: k for k, h in enumerate(hosts)}; nH = len(hosts); n = len(F)
    fh = np.array([hi[f['host']] for f in F]); exp = np.array([h in topo['exposed'] for h in hosts])
    A = np.zeros((nH, nH), bool)
    for a in hosts:
        for b in topo['adj'][a]: A[hi[a], hi[b]] = True
    mod = np.array([q[k] * (0.5 if f['sem']['ui'] == 'R' else 1.0) * (0.3 if f['role'] == 'lib' else 1.0) for k, f in enumerate(F)])
    prH = np.array([f['sem']['pr'] == 'H' for f in F]); prL = np.array([f['sem']['pr'] == 'L' for f in F])
    U = rng.random((runs, n))
    comps = [c['id'] for c in app['comps']]; ci = {c: k for k, c in enumerate(comps)}
    return dict(n=n, nH=nH, fh=fh, exp=exp, A=A, mod=mod, prH=prH, prL=prL, U=U,
                net=np.array([f['sem']['av'] == 'N' for f in F]), adjv=np.array([f['sem']['av'] == 'A' for f in F]),
                foot=np.array([core.grants_foothold(f['sem']) for f in F]), frac=np.array([core.impact_frac(f['sem']) for f in F]),
                fc=np.array([ci[f['comp']] for f in F]), crit=np.array([c['crit'] for c in app['comps']]), ch=np.array([hi[c['host']] for c in app['comps']]))
def expected_loss(P, patched=None):
    n, nH = P['n'], P['nH']; runs = P['U'].shape[0]
    alive = np.ones(n, bool)
    if patched is not None and len(patched): alive[list(patched)] = False
    foot = np.zeros((runs, nH), bool); done = np.zeros((runs, n), bool)
    # privileges: PR:H needs a foothold on a host that connects to the target (else heavy discount), PR:L mild discount
    for _ in range(nH + 2):
        near = (foot.astype(np.uint8) @ P['A'].astype(np.uint8)) > 0                 # hosts reachable from a foothold
        onhost = foot[:, P['fh']]; fromnet = P['exp'][P['fh']][None, :] | near[:, P['fh']]
        access = np.where(P['net'][None, :], fromnet | onhost, np.where(P['adjv'][None, :], near[:, P['fh']] | onhost, onhost))
        inside = near[:, P['fh']] | onhost
        p = P['mod'][None, :] * np.where(P['prH'][None, :], np.where(inside, 1.0, 0.3), np.where(P['prL'][None, :], np.where(inside, 1.0, 0.7), 1.0))
        new = access & alive[None, :] & (P['U'] < p) & ~done
        if not new.any(): break
        done |= new
        nf = np.zeros_like(foot)
        for k in np.where(P['foot'])[0]: nf[:, P['fh'][k]] |= new[:, k]
        foot |= nf
    nC = len(P['crit']); dmg = np.zeros((runs, nC))
    for k in range(n):
        if done[:, k].any(): dmg[:, P['fc'][k]] = np.maximum(dmg[:, P['fc'][k]], done[:, k] * P['frac'][k])
    full = foot[:, P['ch']]                                                          # a foothold on the host compromises co-hosted components
    dmg = np.maximum(dmg, full * 1.0)
    return float((dmg * P['crit'][None, :]).sum(1).mean() / P['crit'].sum())
