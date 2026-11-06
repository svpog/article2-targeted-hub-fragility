# Clarifications from the journal manuscript review

No archived code or data was changed in response to these clarifications.

## Structural and flow-based attack rules

For the 1,800 B4 matched cases, degree, betweenness and hub_role choose identical damaged-node sets. Under the shared repair stream this produces exactly identical Q trajectories (all 101 points) and identical rho, early rho, R_rb and R_inf. Run `python scripts/check_rule_identity.py` to verify the outcome identity directly. The three equal rows in the article table are a consequence of the identical interventions and paired recovery process, not independent evidence that three distinct interventions are equivalent.

Greedy flow_impact differs from these common sets in 362/1800 cases (20.11%). Its mean vulnerability indices compared with the structural baseline are:

| Index | Common structural outcome | flow_impact |
|---|---:|---:|
| VI_rho_med | 0.023228 | 0.023129 |
| VI_lower_tail | 0.011964 | 0.012226 |
| VI_R_rb | 0.962222 | 0.966667 |
| VI_rho_early_10 | 0.214928 | 0.213966 |

Thus flow_impact has slightly larger average robustness and lower-tail vulnerability, but slightly smaller median-integral and early-integral vulnerability. These descriptive results do not show a consistent advantage across metrics. They do not establish statistical equivalence or the absence of any advantage; no dedicated equivalence test is claimed.

## Aggregation and design grids

Article vulnerability tables average configuration-level ratios: mean_c(1 − targeted_c/random_c). They generally differ from 1 − mean_c(targeted_c)/mean_c(random_c). For example, at B3 w=0.10 the lower-tail VI averages to 0.2534, while the rounded means in the metrics table give approximately 0.2105. Neither is an arithmetic error; they summarize different quantities. The manuscript now repeats this definition immediately below its relevant tables.

B2 robustness vulnerability (0.9200) averages 5 hub counts × 4 attack fractions. B3 (0.9644) and B4 (0.9622–0.9667) average 3 hub counts × 3 attack fractions, with separately seeded series and different attack rules. Do not interpret these as one index changing under an otherwise identical experimental design.

## Irreversible-set nesting

The 460 non-nested comparisons out of 3600 concern w=0.10 → 0.25. Both comparisons starting at w=0 have an empty irreversible set and are always nested. The supplementary checker explicitly excludes those trivially nested cases from this denominator.

## Absolute and relative baseline differences

The article's absolute differences and relative vulnerability indices are both retained: VI=absolute_difference/random_statistic. When the random statistic is close to one, the two columns are numerically close. Their meanings remain distinct.
