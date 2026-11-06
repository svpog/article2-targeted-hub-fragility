# Article-to-evidence map

The article title is *Metric-Dependent Targeted Fragility of Hub-Based Supply Networks*.

| Article item | Evidence |
|---|---|
| Table 1: design | `source/config/series_S3.yaml`; constants and grid loops in `source/_s3_extended_abc.py`; original metadata |
| Table 2: inference | `audit/reference/recomputed_paired_tests.csv`; family totals in `audit_summary.json` |
| Table 3: B1 vulnerability | `audit/reference/S3_VI.csv`, grouped by attack_fraction and averaged over h |
| Table 4: early horizons | `audit/reference/B2_recomputed_indices.csv`, averaged over h/q within T |
| Table 5: irreversibility vulnerability | `audit/reference/S3B_irreversibility_VI.csv`, averaged over h/q within w |
| Table 6: B3 metrics | `audit/reference/S3B_irreversibility_recomputed_aggregates.csv`, averaged over h/q within w/mode |
| Table 7: attack rules | `audit/reference/S3C_attack_rules_VI.csv`; early VI additionally in original `source/results/aggregated/S3C_attack_rules/rule_vulnerability_indices.csv` |
| Figure 1: Q(t) | B1 raw Q curves and `source/_s3_analysis.py::plot_q_curves` |
| Figure 2: early resilience | B2 `aggregated_early_metrics.csv` |
| Figure 3: robustness VI | B2 `paired_vulnerability_indices.csv`, T_eff=10 |
| Figure 4: lower-tail resilience vs w | B3 `aggregated_results.csv`, targeted mode |
| Figure 5: non-recovery vs w | B3 `aggregated_results.csv`, targeted mode |
| Figure 6: tied attack ranks | `audit/reference/tie_aware_ranks.csv` |
| Pre-disruption sensitivity | `audit/reference/B2_without_predisruption.csv` |
| Jaccard overlap | `audit/reference/jaccard_per_pair.csv`, `jaccard_summary.csv` |
| Realized irreversible fractions | `audit/reference/realized_irreversibility.csv` |

The six released English PNGs are the versions used in the English DOCX prepared for the journal. Regeneration uses stored results and deterministic plotting settings; visual rendering can differ with fonts and library versions. Legacy axis terminology 'irreversible fraction w' refers to the nominal parameter, as clarified in the article and protocol. Regenerated Figures 4–5 explicitly label nominal w. Their points average the three h-level aggregate values for each q/w, and shaded bands use the plotting library's 95% bootstrap interval across those three aggregate values, with a fixed plotting seed. Those bands are descriptive and are not the paired-run confidence intervals reported in the audit tables.

All article values are rounded from underlying tables. In particular, mean B3 targeted non-recovery at w=0.25 is 1246/1800=0.692222…; its mean configuration-level median R_inf is 0.679551…; lower-tail VI is 0.875469…. Do not replace a mean of cell medians with a pooled median.
