# Reproduction protocol and audited conventions

The original specifications remain unchanged in `source/docs/`. The baseline YAML is `source/config/series_S3.yaml`, merged with `base_config.yaml`. The extended experiment parameters are constants in `source/_s3_extended_abc.py` (not a separate historical YAML file).

## Performance and metrics

Q(t) is maximum flow at t divided by the intact-network maximum flow F0. `rho` is the arithmetic mean of all 101 stored points. B2 `rho_early(T)` is the mean of t = 0…T inclusive. The sensitivity check instead averages t = 1…T. `R_rb` is the minimum of the stored trajectory. The lower-tail statistic averages the lowest 20 of 200 run-level resilience values (alpha = 0.10); it is a lower-tail empirical CVaR-like resilience statistic, not loss CVaR.

The vulnerability index is 1 − targeted statistic / random statistic. Article summaries average these configuration-level ratios; they are not ratios of pooled run means. B3 median R_inf summaries average the configuration medians; `non_rec` averages cell non-recovery fractions (equal cell sizes make this equal to the pooled fraction in the reported design).

In B1, Q(0)=1 precedes disruption, Q(1) is the immediate shock before repair, and R_inf uses the first 0.95 threshold crossing. In B3/B4, Q(0) is the immediate shock and Q(1) follows one repair; R_inf is the endpoint. The released data preserve both conventions rather than shifting archived trajectories.

## Damage and random streams

Only transit nodes are eligible. Random and targeted modes remove k nodes, with k = ceil(30q) in B1 and k = floor(30q + 0.5) in B3/B4. The actual grid yields k = 1, 2, 3, 6 in B1 and k = 2, 3, 6 in B3/B4.

B1 uses the archived `seed` and `paired_id`; B3/B4 record separate network, damage, recovery and irreversible seeds. Extended seeds are deterministic SHA-256-derived integers, not Python's process-randomized hash. Pairing is within a series and configuration; it does not imply the same network realization between B1 and B3/B4. B3 damaged-node sets remain fixed across w within a disruption mode. Irreversible nodes are selected using the archived generator procedure: the sets are not necessarily nested across w (460 of 3,600 comparisons between w=0.10 and w=0.25 are non-nested; w=0 has an empty set and is trivially nested).

For k = 2, 3, 6 and w = 0.10, n_irreversible is 0, 0, 1; at w = 0.25 it is 1, 1, 2. The latter realized fractions are 1/2, 1/3, 1/3. Use `realized_irreversibility.csv` when interpreting the parameter.

Degree means directed in-degree plus out-degree. Betweenness is computed on an undirected projection. The flow_impact attack greedily recomputes marginal flow impact after each removal. Exact tie-breaking and fallback behavior are preserved in the original source.

## Paired inference

The audit uses one-sided paired Wilcoxon signed-rank tests (`alternative='greater'`, `zero_method='wilcox'`), with random minus targeted differences. All-zero controls receive p=1. Pair joins use `paired_id`, and archived pairing/missingness checks are reported in `audit_summary.json`. Each test has 200 pairs.

| Family | Number of tests | Bonferroni multiplier | Significant at 0.05 |
|---|---:|---:|---:|
| B1: rho | 20 | 20 | 20 |
| B2: 5 horizons × 20 cells × 3 metrics | 300 | 300 | 200 |
| B3: 27 cells × 4 metrics | 108 | 108 | 93 |
| B4: 9 cells × 4 rules × 3 metrics | 108 | 108 in audit | 108 |

The 100 non-significant B2 tests are the pre-disruption Q0 controls. B3 R_inf is significant in 12 of 27 cells. The historical B4 tables used multiplier 27 within each attack rule; both adjustments remain available. Adjusted p-values are capped at 1. P-values are retained at full CSV precision; displayed article values are rounded for presentation. The historical SciPy automatic Wilcoxon method is retained; software versions can affect handling of zeros/ties and should be recorded.

The legacy standardized effect is median(diff)/sd(diff, ddof=1). Paired rank-biserial correlation uses signed ranks of nonzero differences divided by their total rank sum. The 95% percentile confidence interval bootstraps the median paired difference, preserving pairs, with 5,000 resamples and seed 20261105 (initialized for each comparison). It is not a confidence interval for the rank-biserial correlation or the vulnerability index.

Jaccard overlap is |A∩B|/|A∪B| for attacked sets matched by B4 `paired_id`. Each rule pair has 1,800 comparisons. Average tied ranks are computed within each h/q/metric cell, then averaged over nine cells; a smaller rank means lower resilience and therefore greater destructiveness.
