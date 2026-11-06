"""Compare regenerated numerical tables with the reviewed reference tables."""
from pathlib import Path
import argparse
import json
import pandas as pd
from pandas.testing import assert_frame_equal

ROOT = Path(__file__).resolve().parents[1]
TABLES = [
    'recomputed_paired_tests.csv', 'B2_recomputed_indices.csv',
    'realized_irreversibility.csv', 'jaccard_per_pair.csv', 'jaccard_summary.csv',
    'S3_recomputed_aggregates.csv', 'S3_VI.csv',
    'S3B_irreversibility_recomputed_aggregates.csv', 'S3B_irreversibility_VI.csv',
    'S3C_attack_rules_recomputed_aggregates.csv', 'S3C_attack_rules_VI.csv',
    'B2_without_predisruption.csv', 'tie_aware_ranks.csv',
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/audit')
    args = parser.parse_args()
    for name in TABLES:
        expected = pd.read_csv(ROOT / 'audit/reference' / name)
        actual = pd.read_csv(args.output / name)
        assert_frame_equal(actual, expected, check_dtype=False, check_exact=False, rtol=1e-9, atol=1e-12)
        print(f'PASS: {name}')
    summary = json.loads((args.output / 'audit_summary.json').read_text())
    for series, count in [('S3', 8000), ('S3B_irreversibility', 10800), ('S3C_attack_rules', 9000)]:
        item = summary[series]
        assert item['rows'] == item['valid'] == count
        assert item['points_per_run'] == [101]
        assert item['rho_max_error'] < 1e-12
        assert item['R_rb_max_error'] < 1e-12
        assert item['nonrec_mismatch'] == item['duplicate_rows'] == 0
        assert all(value == 0 for value in item['paired_mismatches'].values())
    assert {key: value['significant'] for key, value in summary['tests'].items()} == {'B1': 20, 'B2': 200, 'B3': 93, 'B4': 108}
    supplemental = json.loads((args.output / 'supplementary_summary.json').read_text())
    assert supplemental['B1_Rinf_differs_from_Q100'] == 72
    assert supplemental['B1_Rinf_max_error_vs_Q_at_recovery'] < 1e-12
    assert supplemental['B3_nesting_comparisons'] == 3600
    assert supplemental['B3_non_nested_comparisons'] == 460
    assert supplemental['B4_significant_joint_108'] == 108
    print('PASS: run counts, trajectory metrics, pairing and supplementary findings.')


if __name__ == '__main__':
    main()
