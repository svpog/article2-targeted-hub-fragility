"""Recreate the six English figures from archived data without modifying source."""
from pathlib import Path
import importlib.util
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'source'
OUT = ROOT / 'generated/figures'


def save(fig, number):
    path = OUT / f'figure{number}_en.png'
    fig.savefig(path, dpi=250, bbox_inches='tight')
    plt.close(fig)
    with Image.open(path) as im:
        im.convert('L').save(path)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('legacy_s3_analysis', SOURCE / '_s3_analysis.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.FIG_DIR = OUT
    raw = pd.read_csv(SOURCE / 'results/raw/S3/raw_results.csv')
    curves = pd.read_parquet(SOURCE / 'results/raw/S3/Q_curves.parquet')
    module.plot_q_curves(raw, curves, 'en')
    original = OUT / 'S3_Q_curves_random_vs_targeted_en.png'
    with Image.open(original) as im:
        im.convert('L').save(OUT / 'figure1_en.png')
    original.unlink()
    base = SOURCE / 'results/derived/S3A_early_metrics'
    early = pd.read_csv(base / 'aggregated_early_metrics.csv')
    summary = early.groupby(['disruption_mode', 'T_eff']).rho_early_med.mean().reset_index()
    fig, ax = plt.subplots(figsize=(8.5, 5))
    for mode, group in summary.groupby('disruption_mode'):
        ax.plot(group.T_eff, group.rho_early_med, marker='o', label=mode)
    ax.set(xlabel='Evaluation horizon T_eff', ylabel='Early resilience', title='Early resilience by evaluation horizon')
    ax.legend(); ax.grid(alpha=.25)
    save(fig, 2)
    vi = pd.read_csv(base / 'paired_vulnerability_indices.csv')
    pivot = vi[vi.T_eff == 10].pivot_table(index='h_hubs', columns='attack_fraction', values='VI_R_rb_med')
    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    sns.heatmap(pivot, annot=True, fmt='.3f', cmap='Greys', ax=ax)
    ax.set(xlabel='Attack fraction q', ylabel='Number of hubs h', title='Robustness vulnerability: targeted vs random')
    save(fig, 3)
    agg = pd.read_csv(SOURCE / 'results/aggregated/S3B_irreversibility/aggregated_results.csv')
    target = agg[agg.disruption_mode == 'targeted']
    for number, metric in [(4, 'rho_CVaR_0.10'), (5, 'non_recovered_rate')]:
        fig, ax = plt.subplots(figsize=(8, 5))
        sns.lineplot(data=target, x='w', y=metric, hue='attack_fraction', marker='o', seed=20261105, ax=ax)
        ax.set(xlabel='Nominal irreversibility parameter w', ylabel=metric, title=f'{metric} by nominal w')
        ax.grid(alpha=.25)
        save(fig, number)
    # Compute tied ranks directly from the original aggregates, not old arbitrary rankings.
    agg = pd.read_csv(SOURCE / 'results/aggregated/S3C_attack_rules/aggregated_results.csv')
    rows = []
    metrics = ['R_rb_med', 'rho_CVaR_0.10', 'rho_early_10_med', 'rho_med']
    for _, group in agg[agg.disruption_mode == 'targeted'].groupby(['h_hubs', 'attack_fraction']):
        for metric in metrics:
            ranks = group[metric].rank(method='average')
            rows.extend({'rule': row.attack_rule, 'metric': metric, 'rank': ranks.loc[i]} for i, row in group.iterrows())
    ranks = pd.DataFrame(rows).pivot_table(index='rule', columns='metric', values='rank').reindex(index=['betweenness', 'degree', 'flow_impact', 'hub_role'], columns=metrics)
    fig, ax = plt.subplots(figsize=(8, 5))
    im = ax.imshow(ranks, cmap='Greys', vmin=1, vmax=4, aspect='auto')
    for y in range(4):
        for x in range(4):
            value = ranks.iloc[y, x]
            ax.text(x, y, f'{value:.2f}', ha='center', va='center', color='white' if value > 2.6 else 'black')
    ax.set_yticks(range(4), ranks.index)
    ax.set_xticks(range(4), ['R_rb', 'CVaR (0.10)', 'rho_early (10)', 'rho (100)'])
    ax.set(title='Destructiveness ranks with tied values', xlabel='Metric')
    fig.colorbar(im, ax=ax, label='Mean rank')
    save(fig, 6)
    print(f'Regenerated six figures in {OUT}')


if __name__ == '__main__':
    main()
