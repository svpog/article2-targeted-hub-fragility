# Metric-Dependent Targeted Fragility of Hub-Based Supply Networks

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24010242.svg)](https://doi.org/10.5281/zenodo.24010242)

Research companion prepared for the article by **Stanislav V. Pohorielov** and **Oleksii V. Yanovskyi**, intended for the *Bulletin of V. N. Karazin Kharkiv National University, series Mathematical Modeling. Information Technology. Automated Control Systems*.

This repository contains the original simulation code, protocols, all **27,800 archived Monte Carlo runs**, the corresponding **2,807,800 observations of Q(t)**, and the numerical audit used to check the article. B2 is a reanalysis of B1 trajectories, not an additional set of independent simulations. The manuscript is not included in this research-data package. Article publication details will be added when available; no article DOI has been assigned here.

## Experiments

| Article label | Archived series | Design | Runs |
|---|---|---|---:|
| B1 | `S3` | h = 1, 2, 3, 5, 8; q = 0.02, 0.05, 0.10, 0.20; random fixed-k vs targeted betweenness | 8,000 |
| B2 | `S3A_early_metrics` | Reanalysis of B1 at horizons 5, 10, 20, 50, 100 | Same 8,000 |
| B3 | `S3B_irreversibility` | h = 1, 3, 8; q = 0.05, 0.10, 0.20; w = 0, 0.10, 0.25; two disruption modes | 10,800 |
| B4 | `S3C_attack_rules` | h = 1, 3, 8; q = 0.05, 0.10, 0.20; random baseline + four targeted rules | 9,000 |

Each experiment cell contains 200 runs. Networks have N = 50 nodes and 30 eligible transit nodes. Each run contains 101 Q(t) observations, t = 0 through 100. Recovery repairs one repairable node per step. Attack rules are degree, betweenness, hub_role, and greedy flow_impact.

## Reproduce the numerical audit

The audit was verified with Python 3.9.6 and the pinned packages below. Use that version to match the recorded environment; other Python versions have not been certified. From this repository directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/verify_release.py
python scripts/recompute_audit.py
python scripts/supplementary_checks.py
python scripts/check_recomputed.py
python scripts/check_rule_identity.py
```

On Windows, activate with `.venv\Scripts\activate` instead. The audit reads `source/` and writes only `generated/audit/`. It recalculates metrics and tests from the archived raw outputs; it does not rerun simulations. Bootstrap confidence intervals use 5,000 resamples, so allow a few minutes. `check_recomputed.py` compares 13 numerical tables with the reviewed reference tables and checks the headline findings.

The exact direct dependency versions tested during preparation are recorded in `requirements.txt`; `audit/environment.json` describes this verification environment, not the original May 2026 simulation environment. A complete historical dependency lock was not available. Results from other Python/library versions should be compared numerically rather than assuming byte-identical output files.

To regenerate the six English figures from the stored results:

```bash
python scripts/reproduce_figures.py
```

The released manuscript figures are in `figures/`; regenerated plots are in `generated/figures/`. Figure 6 uses average ranks for tied values. See [the figure and table map](docs/ARTICLE_MAP.md).

## Optional new simulations

The original source files are unchanged. The wrapper makes a new working copy and keeps the released raw results intact:

```bash
# Smoke run: 40 cells × 1 run, not the published result set
python scripts/run_simulations.py --output generated/smoke --runs-b1 1

# Full B1–B4 reproduction; substantially slower than the audit
python scripts/run_simulations.py --output generated/full --runs-b1 200 --extended
```

Use a new output directory each time. The full wrapper first generates B1, creates its baseline figures, and then runs the original extended script for B2–B4. Do not run simulation scripts directly inside `source/`, since those legacy entry points can overwrite their relative result paths. Historical reports/rankings are retained as provenance; the audit records corrections separately.

## Repository layout

| Directory | Contents |
|---|---|
| `source/` | Unmodified original code subset, YAML configurations, three original DOCX protocol/specification documents, raw CSV/Parquet data, metadata, historical aggregates and reports |
| `audit/reference/` | Reviewed recalculations: paired p-values, multiplicity correction, effects and confidence intervals, vulnerability indices, Jaccard overlaps, realized irreversibility, tied ranks |
| `audit/source_manifest.json` | SHA-256 and size of every unchanged original file included |
| `audit/release_manifest.json` | SHA-256 of the distributed package, excluding this manifest and generated outputs |
| `scripts/` | Portable audit, verification, figure regeneration and isolated simulation entry points |
| `docs/` | English protocol, data dictionary, article mapping, provenance and limits |
| `figures/` | Six English manuscript figures |
| `generated/` | Local recalculations and new simulations; ignored by Git |

## Important interpretation details

- **Time zero differs:** B1/B2 Q(0) is the pre-disruption state, always 1. B3/B4 Q(0) is the immediate post-disruption state. The B2 Q0 tests are technical controls, not evidence of no initial shock.
- **Fixed budget and pairing:** random and targeted modes have the same k and shared paired identifiers/seeds. B1 uses ceil(30q); B3/B4 use half-up rounding. They give the same k on the studied q grid.
- **Nominal w is discretized:** n_irreversible = min(k, floor(wk + 0.5)). Thus w = 0.25 does not mean exactly 25% of damaged nodes in each run. Irreversible sets need not be nested as w increases.
- **Recovery endpoint differs:** B1 R_inf is Q at the first threshold crossing (0.95); it differs from Q(100) in 72 runs. In B3/B4 R_inf is Q(100). All non_recovered flags use Q(100) < 0.95.
- **Statistical effects:** the legacy effect_size is median(paired difference) / sample standard deviation of paired differences; it is not Cohen's d. The audit also supplies the paired rank-biserial effect and paired bootstrap confidence interval.
- **Multiplicity:** B4 originally corrected 27 tests per rule. The audit additionally corrects all 108 tests jointly; all remain significant. See [the protocol](docs/PROTOCOL.md) for the other families.
- **Ties:** the old attack-rule ranking arbitrarily separated equal values. The manuscript's Figure 6 and audited rank table assign average ranks.

## Verified headline findings and scope

The mean B2 early-resilience vulnerability index is 0.3049 at horizon 5 and 0.0181 at horizon 100 under the archived pre-disruption-point convention. Excluding that point gives 0.3667 and 0.0183. At nominal w = 0.25, B3 mean lower-tail vulnerability is 0.8755 and 1,246/1,800 targeted runs are incompletely recovered (0.6922). In B4 the degree, betweenness and hub_role damaged-node sets coincide in every paired comparison. Flow_impact has mean Jaccard overlap 0.8987 with each of those rules.

These results concern synthetic hub networks with N = 50 and h ≤ 8, single-commodity maximum flow, and a random repair baseline. They do not establish equivalence of attack rules, behavior in empirical networks, continuous sensitivity to w, or performance of decentralized recovery algorithms. See [provenance and limitations](docs/PROVENANCE.md).

## Citation and licensing

Author and title metadata are provided in `CITATION.cff`. Cite the repository release v1.0.0: https://github.com/svpog/article2-targeted-hub-fragility/releases/tag/v1.0.0. The exact release archive is preserved in Zenodo: [10.5281/zenodo.24010242](https://doi.org/10.5281/zenodo.24010242). This DOI identifies the software and data companion, not the journal article.

The prepared licensing scheme follows the authors' existing article-1 release: MIT for software, CC BY 4.0 for research data. See `LICENSE` for the scope. Repository: https://github.com/svpog/article2-targeted-hub-fragility. Version 1.0.0 provides the reviewed B1–B4 data and audit.
