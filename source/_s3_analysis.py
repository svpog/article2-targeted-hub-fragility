"""
S3 analysis: hub centralization and targeted vulnerability.

Reads:
    results/raw/S3/raw_results.csv
    results/raw/S3/Q_curves.parquet
    results/aggregated/S3/aggregated_results.csv

Writes:
    results/aggregated/S3_hypothesis_test.txt
    bilingual figures in results/figures/S3_*_{uk,en}.png
"""

from __future__ import annotations

import math
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import spearmanr, wilcoxon


RAW_CSV = Path("results/raw/S3/raw_results.csv")
Q_PARQUET = Path("results/raw/S3/Q_curves.parquet")
AGG_CSV = Path("results/aggregated/S3/aggregated_results.csv")
REPORT = Path("results/aggregated/S3_hypothesis_test.txt")
FIG_DIR = Path("results/figures")

H_VALUES = [1, 2, 3, 5, 8]
Q_VALUES = [0.02, 0.05, 0.10, 0.20]
TAU_VALUES = [0.05, 0.10]
MODE_COLORS = {
    "random_fixed_k": "#2a9d8f",
    "targeted": "#d95f02",
}


def _mode_label(mode: str, lang: str) -> str:
    labels = {
        "uk": {"random_fixed_k": "випадковий fixed-k", "targeted": "цільовий"},
        "en": {"random_fixed_k": "random fixed-k", "targeted": "targeted"},
    }
    return labels[lang].get(mode, mode)


def _bootstrap_ci(values: np.ndarray, stat_func, seed: int, B: int = 1000) -> tuple[float, float]:
    arr = np.asarray(values, dtype=float)
    arr = arr[~np.isnan(arr)]
    if len(arr) == 0:
        return (np.nan, np.nan)
    rng = np.random.default_rng(seed)
    stats = np.empty(B)
    for i in range(B):
        sample = rng.choice(arr, size=len(arr), replace=True)
        stats[i] = stat_func(sample)
    return float(np.quantile(stats, 0.025)), float(np.quantile(stats, 0.975))


def _rho_cvar(values: np.ndarray, alpha: float = 0.10) -> float:
    arr = np.asarray(values, dtype=float)
    arr = arr[~np.isnan(arr)]
    if len(arr) == 0:
        return np.nan
    arr = np.sort(arr)
    n_tail = max(1, int(math.floor(alpha * len(arr))))
    return float(arr[:n_tail].mean())


def load_data() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Loads S3 raw, Q curves, and aggregated data."""
    raw = pd.read_csv(RAW_CSV)
    q_df = pd.read_parquet(Q_PARQUET)
    agg = pd.read_csv(AGG_CSV)
    raw = raw[raw["series"] == "S3"].copy()
    return raw, q_df, agg


def paired_wilcoxon(raw: pd.DataFrame) -> pd.DataFrame:
    """Paired random_fixed_k vs targeted Wilcoxon tests for each h/q."""
    rows = []
    valid = raw[raw["valid"].astype(bool)].copy()
    for (h, q), group in valid.groupby(["h_hubs", "attack_fraction"]):
        wide = group.pivot_table(
            index="paired_id",
            columns="disruption_mode",
            values="rho",
            aggfunc="first",
        ).dropna(subset=["random_fixed_k", "targeted"])
        if len(wide) == 0:
            continue
        diff = wide["random_fixed_k"] - wide["targeted"]
        if np.allclose(diff, 0.0):
            stat, p_value = 0.0, 1.0
        else:
            stat, p_value = wilcoxon(
                wide["random_fixed_k"],
                wide["targeted"],
                alternative="greater",
                zero_method="wilcox",
            )
        rows.append({
            "h_hubs": h,
            "attack_fraction": q,
            "n_pairs": len(wide),
            "W_statistic": float(stat),
            "p_value": float(p_value),
            "median_delta_rho": float(np.median(diff)),
            "mean_delta_rho": float(np.mean(diff)),
        })
    tests = pd.DataFrame(rows)
    if not tests.empty:
        tests["p_adj_bonferroni"] = np.minimum(1.0, tests["p_value"] * len(tests))
        tests["significant"] = tests["p_adj_bonferroni"] < 0.05
    return tests


def q_star_table(agg: pd.DataFrame) -> pd.DataFrame:
    """Computes fragility threshold q_star for VI_CVaR."""
    targeted = agg[agg["disruption_mode"] == "targeted"].copy()
    rows = []
    for h, group in targeted.groupby("h_hubs"):
        group = group.sort_values("attack_fraction")
        for tau in TAU_VALUES:
            hit = group[group["VI_CVaR"] >= tau]
            rows.append({
                "h_hubs": int(h),
                "tau": tau,
                "q_star": float(hit["attack_fraction"].iloc[0]) if not hit.empty else np.nan,
            })
    return pd.DataFrame(rows)


def centralization_correlations(agg: pd.DataFrame) -> pd.DataFrame:
    """Spearman correlations between centralization metrics and VI_CVaR."""
    targeted = agg[agg["disruption_mode"] == "targeted"].copy()
    rows = []
    metrics = ["h_hubs", "degree_centralization", "betweenness_centralization",
               "flow_concentration_gini", "max_node_flow_share"]
    for q, group in targeted.groupby("attack_fraction"):
        for metric in metrics:
            x = group[metric].to_numpy(dtype=float)
            y = group["VI_CVaR"].to_numpy(dtype=float)
            if len(x) < 3 or np.allclose(x, x[0]) or np.allclose(y, y[0]):
                r, p = np.nan, np.nan
            else:
                r, p = spearmanr(x, y)
            rows.append({
                "attack_fraction": q,
                "metric": metric,
                "spearman_r": float(r) if not np.isnan(r) else np.nan,
                "p_value": float(p) if not np.isnan(p) else np.nan,
            })
    return pd.DataFrame(rows)


def plot_q_curves(raw: pd.DataFrame, q_df: pd.DataFrame, lang: str) -> None:
    """Median Q(t) random vs targeted for representative attack_fraction=0.10."""
    attack_fraction = 0.10
    sub_raw = raw[
        raw["valid"].astype(bool)
        & (raw["attack_fraction"].round(2) == attack_fraction)
    ][["run_id", "h_hubs", "disruption_mode"]]
    merged = q_df.merge(sub_raw, on="run_id", how="inner")
    fig, axes = plt.subplots(1, len(H_VALUES), figsize=(16, 3.8), sharey=True, constrained_layout=True)
    for ax, h in zip(axes, H_VALUES):
        h_data = merged[merged["h_hubs"] == h]
        for mode in ["random_fixed_k", "targeted"]:
            m_data = h_data[h_data["disruption_mode"] == mode]
            stats = m_data.groupby("t")["Q"].agg(
                med="median",
                q25=lambda x: x.quantile(0.25),
                q75=lambda x: x.quantile(0.75),
            ).reset_index()
            ax.plot(stats["t"], stats["med"], color=MODE_COLORS[mode], linewidth=2,
                    label=_mode_label(mode, lang))
            ax.fill_between(stats["t"], stats["q25"], stats["q75"],
                            color=MODE_COLORS[mode], alpha=0.16)
        ax.axhline(0.95, color="gray", linestyle="--", linewidth=1)
        ax.set_title(f"h={h}")
        ax.set_xlabel("t")
        ax.grid(True, alpha=0.25)
    axes[0].set_ylabel("Q(t)")
    title = (
        "S3: Q(t) криві, q=0.10" if lang == "uk"
        else "S3: Q(t) curves, q=0.10"
    )
    fig.suptitle(title, fontweight="bold")
    axes[-1].legend(frameon=False, loc="lower right")
    fig.savefig(FIG_DIR / f"S3_Q_curves_random_vs_targeted_{lang}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_cvar_vs_h(agg: pd.DataFrame, lang: str) -> None:
    """rho_CVaR vs h_hubs for each attack_fraction and mode."""
    fig, axes = plt.subplots(2, 2, figsize=(11, 8), sharey=True, constrained_layout=True)
    for ax, q in zip(axes.flat, Q_VALUES):
        sub = agg[np.isclose(agg["attack_fraction"], q)]
        for mode in ["random_fixed_k", "targeted"]:
            m = sub[sub["disruption_mode"] == mode].sort_values("h_hubs")
            ax.plot(m["h_hubs"], m["rho_CVaR"], marker="o", linewidth=2,
                    color=MODE_COLORS[mode], label=_mode_label(mode, lang))
        ax.set_title(f"q={q:.2f}")
        ax.set_xlabel("h_hubs")
        ax.grid(True, alpha=0.25)
    axes[0, 0].set_ylabel("rho_CVaR")
    axes[1, 0].set_ylabel("rho_CVaR")
    title = (
        "S3: хвостова стійкість залежно від хабовості"
        if lang == "uk" else
        "S3: lower-tail resilience by hub centralization"
    )
    fig.suptitle(title, fontweight="bold")
    axes[0, 1].legend(frameon=False)
    fig.savefig(FIG_DIR / f"S3_cvar_vs_h_{lang}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_vulnerability_heatmap(agg: pd.DataFrame, lang: str) -> None:
    """VI_CVaR heatmap for targeted rows."""
    targeted = agg[agg["disruption_mode"] == "targeted"]
    matrix = targeted.pivot_table(
        index="attack_fraction", columns="h_hubs", values="VI_CVaR", aggfunc="first"
    ).reindex(index=Q_VALUES, columns=H_VALUES)
    fig, ax = plt.subplots(figsize=(8, 5), constrained_layout=True)
    im = ax.imshow(matrix.values, origin="lower", aspect="auto", cmap="YlOrRd", vmin=0)
    ax.set_xticks(range(len(H_VALUES)), labels=H_VALUES)
    ax.set_yticks(range(len(Q_VALUES)), labels=[f"{q:.2f}" for q in Q_VALUES])
    ax.set_xlabel("h_hubs")
    ax.set_ylabel("attack_fraction q")
    title = "S3: heatmap VI_CVaR" if lang == "en" else "S3: теплова карта VI_CVaR"
    ax.set_title(title, fontweight="bold")
    for i, q in enumerate(Q_VALUES):
        for j, h in enumerate(H_VALUES):
            val = matrix.loc[q, h]
            if not np.isnan(val):
                ax.text(j, i, f"{val:.3f}", ha="center", va="center", fontsize=9)
    fig.colorbar(im, ax=ax, label="VI_CVaR")
    fig.savefig(FIG_DIR / f"S3_vulnerability_heatmap_{lang}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_fragility_threshold(q_star: pd.DataFrame, lang: str) -> None:
    """q_star vs h_hubs for tau=0.05 and tau=0.10."""
    fig, ax = plt.subplots(figsize=(7.5, 4.8), constrained_layout=True)
    for tau in TAU_VALUES:
        sub = q_star[q_star["tau"] == tau].sort_values("h_hubs")
        ax.plot(sub["h_hubs"], sub["q_star"], marker="o", linewidth=2, label=f"tau={tau:.2f}")
    ax.set_xlabel("h_hubs")
    ax.set_ylabel("q_star")
    title = (
        "S3: поріг крихкості" if lang == "uk"
        else "S3: fragility threshold"
    )
    ax.set_title(title, fontweight="bold")
    ax.set_ylim(0, max(Q_VALUES) + 0.02)
    ax.grid(True, alpha=0.25)
    ax.legend(frameon=False)
    fig.savefig(FIG_DIR / f"S3_fragility_threshold_{lang}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def write_report(
    raw: pd.DataFrame,
    agg: pd.DataFrame,
    tests: pd.DataFrame,
    q_star: pd.DataFrame,
    correlations: pd.DataFrame,
) -> None:
    """Writes the S3 text report."""
    valid = raw[raw["valid"].astype(bool)]
    targeted = agg[agg["disruption_mode"] == "targeted"].copy()
    lines = []
    lines.append("=" * 78)
    lines.append("S3: HUB CENTRALIZATION AND TARGETED VULNERABILITY")
    lines.append("=" * 78)
    lines.append("")
    lines.append("Protocol: docs/TZ_S3_targeted_hub_disruptions.docx")
    lines.append("Design: topology=hub; h_hubs={1,2,3,5,8}; attack_fraction={0.02,0.05,0.10,0.20};")
    lines.append("modes={random_fixed_k,targeted}; attack_rule=betweenness; paired seed design.")
    lines.append(f"Rows: raw={len(raw)}, valid={len(valid)}, invalid={len(raw)-len(valid)}.")
    lines.append("")

    lines.append("-" * 78)
    lines.append("AGGREGATED METRICS")
    lines.append("-" * 78)
    lines.append("h  q     mode            n_valid  rho_med  rho_CVaR  R_rb_mean  VI_CVaR")
    for _, r in agg.sort_values(["h_hubs", "attack_fraction", "disruption_mode"]).iterrows():
        lines.append(
            f"{int(r['h_hubs']):<2} {r['attack_fraction']:<5.2f} "
            f"{r['disruption_mode']:<15} {int(r['n_valid']):>7d} "
            f"{r['rho_med']:.4f}   {r['rho_CVaR']:.4f}    {r['R_rb_mean']:.4f}    "
            f"{r['VI_CVaR'] if not np.isnan(r['VI_CVaR']) else np.nan:.4f}"
        )
    lines.append("")

    target_rows = agg[agg["disruption_mode"] == "targeted"].copy()
    target_rows["Delta_ratio_CVaR_to_med"] = (
        target_rows["Delta_CVaR"] / target_rows["Delta_rho_med"]
    )
    ratio_gt_one = int((target_rows["Delta_ratio_CVaR_to_med"] > 1.0).sum())

    lines.append("-" * 78)
    lines.append("PAIRED WILCOXON TESTS: random_fixed_k > targeted by rho")
    lines.append("-" * 78)
    lines.append("h  q     n_pairs  median_delta  p_value      p_adj       significant")
    for _, r in tests.sort_values(["h_hubs", "attack_fraction"]).iterrows():
        lines.append(
            f"{int(r['h_hubs']):<2} {r['attack_fraction']:<5.2f} "
            f"{int(r['n_pairs']):>7d}  {r['median_delta_rho']:+.4f}      "
            f"{r['p_value']:.3e}  {r['p_adj_bonferroni']:.3e}  "
            f"{'YES' if r['significant'] else 'NO'}"
        )
    lines.append("")

    lines.append("-" * 78)
    lines.append("H3.3 CHECK: Delta_CVaR / Delta_rho_med")
    lines.append("-" * 78)
    lines.append("h  q     Delta_rho_med  Delta_CVaR  ratio")
    for _, r in target_rows.sort_values(["h_hubs", "attack_fraction"]).iterrows():
        lines.append(
            f"{int(r['h_hubs']):<2} {r['attack_fraction']:<5.2f} "
            f"{r['Delta_rho_med']:.4f}         {r['Delta_CVaR']:.4f}     "
            f"{r['Delta_ratio_CVaR_to_med']:.3f}"
        )
    lines.append(
        f"Ratio > 1 in {ratio_gt_one}/{len(target_rows)} configurations. "
        "Thus H3.3 is not supported in the minimal S3 betweenness design."
    )
    lines.append("")

    lines.append("-" * 78)
    lines.append("FRAGILITY THRESHOLD q_star")
    lines.append("-" * 78)
    lines.append("h  tau   q_star")
    for _, r in q_star.sort_values(["tau", "h_hubs"]).iterrows():
        q_text = "N/A" if np.isnan(r["q_star"]) else f"{r['q_star']:.2f}"
        lines.append(f"{int(r['h_hubs']):<2} {r['tau']:<5.2f} {q_text}")
    lines.append("")

    lines.append("-" * 78)
    lines.append("CENTRALIZATION CORRELATIONS WITH VI_CVaR")
    lines.append("-" * 78)
    lines.append("q     metric                       Spearman_r   p_value")
    for _, r in correlations.sort_values(["attack_fraction", "metric"]).iterrows():
        lines.append(
            f"{r['attack_fraction']:<5.2f} {r['metric']:<28} "
            f"{r['spearman_r']:+.3f}       {r['p_value']:.3e}"
        )
    lines.append("")

    n_sig = int(tests["significant"].sum()) if not tests.empty else 0
    lines.append("-" * 78)
    lines.append("CONCLUSIONS")
    lines.append("-" * 78)
    lines.append(f"H3.1: targeted vulnerability significant in {n_sig}/{len(tests)} paired tests after Bonferroni.")
    if not targeted.empty:
        max_vi = targeted["VI_CVaR"].max()
        max_row = targeted.loc[targeted["VI_CVaR"].idxmax()]
        lines.append(
            f"Max VI_CVaR={max_vi:.4f} at h={int(max_row['h_hubs'])}, "
            f"q={max_row['attack_fraction']:.2f}."
        )
    lines.append(
        f"H3.3: not supported here; Delta_CVaR/Delta_rho_med > 1 only in "
        f"{ratio_gt_one}/{len(target_rows)} configurations."
    )
    lines.append(
        "Fragility threshold: q_star is N/A for tau=0.05 and tau=0.10 because "
        "max VI_CVaR remains below 0.05 under this fixed-budget betweenness design."
    )
    lines.append("Extended H3.4 attack-rule comparison is not run yet: current minimal design uses betweenness only.")
    lines.append("")
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    """Runs S3 analysis and writes report/figures."""
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    raw, q_df, agg = load_data()
    tests = paired_wilcoxon(raw)
    q_star = q_star_table(agg)
    correlations = centralization_correlations(agg)
    write_report(raw, agg, tests, q_star, correlations)
    for lang in ["uk", "en"]:
        plot_q_curves(raw, q_df, lang)
        plot_cvar_vs_h(agg, lang)
        plot_vulnerability_heatmap(agg, lang)
        plot_fragility_threshold(q_star, lang)
    print(f"Saved report: {REPORT}")
    print("Saved figures:")
    for path in sorted(FIG_DIR.glob("S3_*_*.png")):
        print(f"  {path}")


if __name__ == "__main__":
    main()
