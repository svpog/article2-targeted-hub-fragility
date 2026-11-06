"""Run original simulations in an isolated output copy, preserving archived data."""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New, non-existing work directory')
    parser.add_argument('--runs-b1', type=int, default=200)
    parser.add_argument('--extended', action='store_true', help='Also simulate B3/B4; B2 is derived from B1')
    args = parser.parse_args()
    if args.runs_b1 < 1:
        parser.error('--runs-b1 must be positive')
    out = args.output.resolve()
    if out.exists() or out == ROOT or ROOT / 'source' in out.parents:
        parser.error('--output must be a new directory outside source/')
    if args.extended and args.runs_b1 != 200:
        parser.error('The archived extended protocol requires the full B1 grid (200 runs per cell).')
    shutil.copytree(ROOT / 'source', out, ignore=shutil.ignore_patterns('results', '__pycache__'))
    code = "from src.experiments.runner import run_series; run_series('S3', n_runs=" + str(args.runs_b1) + ", config_path='config/series_S3.yaml', output_dir='results')"
    env = os.environ.copy()
    env['MPLBACKEND'] = 'Agg'
    subprocess.run([sys.executable, '-c', code], cwd=out, env=env, check=True)
    subprocess.run([sys.executable, '_s3_analysis.py'], cwd=out, env=env, check=True)
    if args.extended:
        subprocess.run([sys.executable, '_s3_extended_abc.py'], cwd=out, env=env, check=True)
    print(f'New simulation outputs: {out / "results"}')


if __name__ == '__main__':
    main()
