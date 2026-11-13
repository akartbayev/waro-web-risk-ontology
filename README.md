# WARO prototype and experiments

- `src/kb.py`, `parse_nvd.py`: loaders for NVD JSON 2.0 feeds, CWE 5.0, CAPEC 3.9, EPSS, KEV
- `src/onto.py`: WARO ontology (OWL 2 + SWRL) and two-pass HermiT reasoning via owlready2
- `src/core.py`: findings, graph priors, reference rule implementation, risk model
- `src/sim.py`: Monte Carlo attack simulation
- `src/apps.py`: product catalog, deployment generator, reference deployments
- `src/e2_impute.py`, `e2b.py`: recovery of missing scores; `e3_global.py`, `e3_run.py`: KEV prediction
- `src/e4_reasoner.py`: reasoner agreement and timing; `e5_portfolio.py` (args: 300 7 final_e5.pkl): simulation; `e6_case.py`: case study
- `results/`: JSON outputs behind every table; `waro_RA2_example.owl`: ontology with the RA2 ABox

Data are downloaded from nvd.nist.gov, cwe.mitre.org, capec.mitre.org, epss.empiricalsecurity.com and the cisagov/kev-data repository (snapshot of 10 Nov 2026). Run the scripts from the src folder. Raw data are expected in src/data and intermediate files are written to src/work.
