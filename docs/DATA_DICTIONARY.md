# Data dictionary

Raw results are CSV (UTF-8); trajectories are Apache Parquet. No identifiable field observations are used: these are synthetic simulations.

| File/field | Meaning |
|---|---|
| `source/results/raw/<series>/raw_results.csv` | One row per simulation |
| `Q_curves.parquet` | Long-form `run_id`, `t`, `Q`; 101 rows per run |
| `run_metadata.json` | Original run counts, timestamps and available protocol metadata |
| `run_id` | Unique run identifier within a series; trajectory join key |
| `paired_id` | Matched random/targeted and rule comparison key within a series |
| `config_id` | Configuration identifier |
| `N`, `h_hubs` | Network size and hub count |
| `attack_fraction`, `candidate_set_size`, `k_attack` | Nominal q, eligible-node count and integer damage budget |
| `disruption_mode`, `attack_rule` | Random fixed-k or targeted disruption and node-selection rule |
| `seed` | B1 paired random seed |
| `network_seed`, `damage_seed`, `recovery_seed`, `irreversible_seed` | Extended protocol random streams |
| `w`, `n_irreversible`, `irreversible_fraction_realized` | Nominal irreversibility, count and realized fraction |
| `F0` | Intact maximum flow used for normalization |
| `rho`, `rho_early_*` | Stored time averages under the series-specific time convention |
| `R_rb`, `R_inf` | Minimum performance and series-specific recovery metric; see PROTOCOL.md |
| `Q0`, `Q_min` | Stored initial and minimum performance |
| `time_to_recovery` | First time crossing the threshold; consult the archived source for non-recovery sentinels |
| `non_recovered` | Endpoint performance below 0.95 |
| `valid`, `invalid_reason` | Run validity and exclusion reason (all released runs are valid) |
| `damaged_nodes`, `irreversible_nodes` | Semicolon-delimited node IDs in B3/B4; empty irreversible list means no such nodes |
| `selection_rule`, `degree_definition`, `betweenness_projection`, `fallback_rule`, `flow_impact_mode` | Available attack implementation metadata |

The original series have different schemas. Do not assume a column present in B3/B4 exists in B1. B2 `run_early_metrics.csv` has 40,000 rows (8,000 original runs × five horizons), not 40,000 independent runs.

`audit/reference/recomputed_paired_tests.csv` contains `family`, `metric`, design coordinates (`h`, `q`, `w`, `T`, `rule` as applicable), `n_pairs`, `n_nonzero`, unadjusted `p_value`, Bonferroni `p_adj`, `median_delta`, its bootstrap `ci_low`/`ci_high`, `rank_biserial`, and `legacy_effect`. NaN coordinates denote fields inapplicable to that family, not missing observations. B2 Q0 rows are controls and should not be pooled with substantive outcome tests.

The original statistical tables in `source/results/` are retained for provenance. Use the audited reference tables for the reviewed paper claims, particularly tied attack ranks and joint B4 correction.
