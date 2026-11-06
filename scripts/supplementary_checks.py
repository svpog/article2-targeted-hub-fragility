"""Recompute time-index sensitivity, irreversible-set nesting and tied ranks."""
from pathlib import Path
import argparse
import itertools
import json
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/audit')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    data = ROOT / 'source/results/raw'
    b1 = pd.read_csv(data / 'S3/raw_results.csv')
    curves = pd.read_parquet(data / 'S3/Q_curves.parquet').pivot(index='run_id', columns='t', values='Q')
    final = curves[100].reindex(b1.run_id).to_numpy()
    # B1 has no stored crossing-time column; recover it from post-disruption points.
    post = curves.loc[b1.run_id, range(1, 101)].to_numpy()
    crossing = post >= .95
    times = np.where(crossing.any(axis=1), crossing.argmax(axis=1) + 1, 100)
    at_recovery = np.array([curves.loc[rid, int(t)] for rid, t in zip(b1.run_id, times)])
    rows = []
    for horizon in [5, 10, 20, 50, 100]:
        d = b1.copy()
        d['post_only'] = curves.loc[d.run_id, range(1, horizon + 1)].mean(axis=1).to_numpy()
        for (h, q), g in d.groupby(['h_hubs', 'attack_fraction']):
            r = g[g.disruption_mode == 'random_fixed_k'].post_only.median()
            t = g[g.disruption_mode == 'targeted'].post_only.median()
            rows.append({'T': horizon, 'h': h, 'q': q, 'VI_post_only': 1 - t / r})
    pd.DataFrame(rows).to_csv(args.output / 'B2_without_predisruption.csv', index=False)
    b3 = pd.read_csv(data / 'S3B_irreversibility/raw_results.csv')
    nesting = []
    parse = lambda value: set() if pd.isna(value) else set(str(value).split(';'))
    for (pid, mode), group in b3.groupby(['paired_id', 'disruption_mode']):
        group = group.set_index('w')
        # Compare positive w levels: the empty w=0 set is trivially nested.
        for left, right in itertools.combinations(sorted(w for w in group.index if w > 0), 2):
            a, b = parse(group.loc[left, 'irreversible_nodes']), parse(group.loc[right, 'irreversible_nodes'])
            nesting.append({'paired_id': pid, 'mode': mode, 'w_left': left, 'w_right': right, 'nested': a <= b})
    pd.DataFrame(nesting).to_csv(args.output / 'irreversible_set_nesting.csv', index=False)
    agg = pd.read_csv(ROOT / 'source/results/aggregated/S3C_attack_rules/aggregated_results.csv')
    rows = []
    metrics = ['R_rb_med', 'rho_CVaR_0.10', 'rho_early_10_med', 'rho_med']
    for (h, q), group in agg[agg.disruption_mode == 'targeted'].groupby(['h_hubs', 'attack_fraction']):
        for metric in metrics:
            ranks = group[metric].rank(method='average', ascending=True)
            for i, row in group.iterrows():
                rows.append({'h': h, 'q': q, 'metric': metric, 'rule': row.attack_rule, 'value': row[metric], 'rank': ranks.loc[i]})
    pd.DataFrame(rows).to_csv(args.output / 'tie_aware_ranks.csv', index=False)
    tests = pd.read_csv(ROOT / 'source/results/aggregated/S3C_attack_rules/statistical_tests.csv')
    tests['p_adj_joint_108'] = (tests.p_value * 108).clip(upper=1)
    tests.to_csv(args.output / 'B4_Bonferroni_families.csv', index=False)
    summary = {
        'B1_Rinf_differs_from_Q100': int((abs(final - b1.R_inf) > 1e-12).sum()),
        'B1_Rinf_max_error_vs_Q_at_recovery': float(np.max(abs(at_recovery - b1.R_inf))),
        'B3_nesting_comparisons': len(nesting),
        'B3_non_nested_comparisons': sum(not x['nested'] for x in nesting),
        'B4_significant_joint_108': int((tests.p_adj_joint_108 < .05).sum()),
    }
    (args.output / 'supplementary_summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
