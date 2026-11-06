"""Verify equality of structural-rule metrics and complete paired Q trajectories."""
from pathlib import Path
import json
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]


def main():
    directory = ROOT / 'source/results/raw/S3C_attack_rules'
    raw = pd.read_csv(directory / 'raw_results.csv')
    curves = pd.read_parquet(directory / 'Q_curves.parquet').pivot(index='run_id', columns='t', values='Q')
    baseline = raw[raw.attack_rule == 'betweenness'].set_index('paired_id')
    metrics = ['rho', 'rho_early_10', 'R_rb', 'R_inf']
    results = {}
    for rule in ['degree', 'hub_role']:
        other = raw[raw.attack_rule == rule].set_index('paired_id').reindex(baseline.index)
        metric_error = float(np.max(abs(other[metrics].to_numpy() - baseline[metrics].to_numpy())))
        curve_error = float(np.max(abs(curves.loc[other.run_id].to_numpy() - curves.loc[baseline.run_id].to_numpy())))
        assert len(other) == 1800 and metric_error == curve_error == 0
        results[rule] = {'n_pairs': len(other), 'max_metric_difference': metric_error, 'max_Q_difference': curve_error}
    output = ROOT / 'generated/audit'
    output.mkdir(parents=True, exist_ok=True)
    (output / 'rule_identity.json').write_text(json.dumps(results, indent=2) + '\n')
    print('PASS: degree and hub_role reproduce all 1,800 betweenness trajectories and metrics exactly.')


if __name__ == '__main__':
    main()
