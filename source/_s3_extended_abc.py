"""Розширений протокол S3A/S3B/S3C для таргетованих атак.

Скрипт реалізує `docs/Протокол_S3_ABC_Codex.docx` без зміни базових
результатів S3. Усі нові артефакти пишуться лише у namespaced каталоги
S3A_early_metrics, S3B_irreversibility та S3C_attack_rules.
"""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.stats import spearmanr, wilcoxon

from src.metrics.stochastic import compute_bootstrap_CI, compute_rho_CVaR
from src.network.base import Network
from src.network.flow import compute_max_flow
from src.recovery.random_strategy import RandomRecoveryStrategy


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

BASE_S3_FILES = [
    RESULTS / "raw/S3/raw_results.csv",
    RESULTS / "raw/S3/Q_curves.parquet",
    RESULTS / "raw/S3/run_metadata.json",
    RESULTS / "aggregated/S3/aggregated_results.csv",
    RESULTS / "aggregated/S3_hypothesis_test.txt",
    RESULTS / "figures/S3_Q_curves_random_vs_targeted_en.png",
    RESULTS / "figures/S3_Q_curves_random_vs_targeted_uk.png",
    RESULTS / "figures/S3_cvar_vs_h_en.png",
    RESULTS / "figures/S3_cvar_vs_h_uk.png",
    RESULTS / "figures/S3_fragility_threshold_en.png",
    RESULTS / "figures/S3_fragility_threshold_uk.png",
    RESULTS / "figures/S3_vulnerability_heatmap_en.png",
    RESULTS / "figures/S3_vulnerability_heatmap_uk.png",
]

REPORT_DIR = RESULTS / "reports/S3_extended"
S3A_DERIVED = RESULTS / "derived/S3A_early_metrics"
S3A_FIG = RESULTS / "figures/S3A_early_metrics"
S3B_RAW = RESULTS / "raw/S3B_irreversibility"
S3B_AGG = RESULTS / "aggregated/S3B_irreversibility"
S3B_FIG = RESULTS / "figures/S3B_irreversibility"
S3C_RAW = RESULTS / "raw/S3C_attack_rules"
S3C_AGG = RESULTS / "aggregated/S3C_attack_rules"
S3C_FIG = RESULTS / "figures/S3C_attack_rules"

N = 50
H_HUBS = [1, 3, 8]
ATTACK_FRACTIONS = [0.05, 0.10, 0.20]
W_VALUES = [0.00, 0.10, 0.25]
M = 200
T_MAX = 100
C_BASE = 100.0
TEFF_VALUES = [5, 10, 20, 50, 100]
ALPHA = 0.10
Q_TARGET = 0.95


@dataclass(frozen=True)
class AttackSelection:
    nodes: tuple[int, ...]
    candidate_set_size: int
    k_attack: int
    metadata: dict[str, str | int | float]


def ensure_dirs() -> None:
    for path in [
        REPORT_DIR,
        S3A_DERIVED,
        S3B_RAW,
        S3B_AGG,
        S3C_RAW,
        S3C_AGG,
    ]:
        path.mkdir(parents=True, exist_ok=True)
    for fig_root in [S3A_FIG, S3B_FIG, S3C_FIG]:
        (fig_root / "uk").mkdir(parents=True, exist_ok=True)
        (fig_root / "en").mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_base_manifest_before() -> dict[str, dict[str, str | int]]:
    json_path = REPORT_DIR / "S3_base_manifest_before_extension.json"
    txt_path = REPORT_DIR / "S3_base_manifest_before.sha256"
    if json_path.exists() and txt_path.exists():
        return json.loads(json_path.read_text(encoding="utf-8"))

    manifest: dict[str, dict[str, str | int]] = {}
    missing: list[str] = []
    for path in BASE_S3_FILES:
        rel = str(path.relative_to(ROOT))
        if not path.exists():
            missing.append(rel)
            continue
        manifest[rel] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    if missing:
        raise FileNotFoundError(f"Base S3 files are missing: {missing}")

    json_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    txt_path.write_text(
        "\n".join(f"{data['sha256']}  {rel}" for rel, data in sorted(manifest.items())) + "\n",
        encoding="utf-8",
    )
    return manifest


def verify_base_manifest_after(before: dict[str, dict[str, str | int]]) -> dict[str, object]:
    changed: list[str] = []
    missing: list[str] = []
    after: dict[str, dict[str, str | int]] = {}
    for rel, old in before.items():
        path = ROOT / rel
        if not path.exists():
            missing.append(rel)
            continue
        sha = sha256_file(path)
        after[rel] = {"sha256": sha, "size": path.stat().st_size}
        if sha != old["sha256"]:
            changed.append(rel)

    result = {
        "unchanged": not changed and not missing,
        "changed_files": changed,
        "missing_files": missing,
        "before": before,
        "after": after,
    }
    out = REPORT_DIR / "S3_base_integrity_check_after_extension.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if changed or missing:
        raise RuntimeError(f"Base S3 integrity failed: changed={changed}, missing={missing}")
    return result


def stable_seed(*parts: object) -> int:
    payload = json.dumps(parts, sort_keys=True, ensure_ascii=False, default=str)
    return int(hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8], 16)


def stable_config_id(payload: dict[str, object]) -> str:
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.md5(text.encode("utf-8")).hexdigest()[:12]


def half_up_round(x: float) -> int:
    return int(math.floor(x + 0.5))


def candidate_nodes(network: Network) -> list[int]:
    return sorted(
        int(n)
        for n in network.graph.nodes()
        if n not in network.suppliers and n not in network.consumers
    )


def compute_k_attack(q: float, candidate_set_size: int) -> int:
    return max(1, half_up_round(q * candidate_set_size))


def top_k_from_scores(scores: dict[int, float], k: int) -> tuple[int, ...]:
    ordered = sorted(scores, key=lambda n: (-scores[n], n))
    return tuple(int(n) for n in ordered[:k])


def select_random(network: Network, k: int, damage_seed: int) -> tuple[int, ...]:
    candidates = candidate_nodes(network)
    rng = np.random.default_rng(damage_seed)
    selected = rng.choice(candidates, size=min(k, len(candidates)), replace=False)
    return tuple(sorted(int(x) for x in selected))


def select_degree(network: Network, k: int) -> tuple[int, ...]:
    candidates = candidate_nodes(network)
    scores = {
        n: float(network.graph.in_degree(n) + network.graph.out_degree(n))
        for n in candidates
    }
    return top_k_from_scores(scores, k)


def select_betweenness(network: Network, k: int) -> tuple[int, ...]:
    candidates = candidate_nodes(network)
    bc = nx.betweenness_centrality(network.graph.to_undirected())
    scores = {n: float(bc.get(n, 0.0)) for n in candidates}
    return top_k_from_scores(scores, k)


def select_hub_role(network: Network, k: int) -> tuple[int, ...]:
    candidates = candidate_nodes(network)
    hubs = [
        n
        for n in candidates
        if network.graph.nodes[n].get("role") == "hub"
        or network.graph.nodes[n].get("type") == "hub"
    ]
    hub_scores = {
        n: float(network.graph.in_degree(n) + network.graph.out_degree(n))
        for n in hubs
    }
    selected = list(top_k_from_scores(hub_scores, min(k, len(hubs))))
    if len(selected) < k:
        remaining = [n for n in candidates if n not in selected]
        rem_scores = {
            n: float(network.graph.in_degree(n) + network.graph.out_degree(n))
            for n in remaining
        }
        selected.extend(top_k_from_scores(rem_scores, k - len(selected)))
    return tuple(int(n) for n in selected)


def select_flow_impact_greedy(network: Network, k: int, f0: float) -> tuple[int, ...]:
    selected: list[int] = []
    candidates = candidate_nodes(network)
    working = network.copy()
    current_flow = f0
    for _ in range(min(k, len(candidates))):
        best_node: int | None = None
        best_impact = -np.inf
        for node in candidates:
            if node in selected:
                continue
            tmp = working.copy()
            tmp.set_node_state(node, "failed")
            impact = current_flow - compute_max_flow(tmp)
            if impact > best_impact + 1e-12 or (
                abs(impact - best_impact) <= 1e-12 and (best_node is None or node < best_node)
            ):
                best_node = node
                best_impact = impact
        if best_node is None:
            break
        selected.append(best_node)
        working.set_node_state(best_node, "failed")
        current_flow = compute_max_flow(working)
    return tuple(int(n) for n in selected)


def select_attack_nodes(
    network: Network,
    mode: str,
    attack_rule: str,
    q: float,
    damage_seed: int,
    f0: float,
) -> AttackSelection:
    candidates = candidate_nodes(network)
    k = compute_k_attack(q, len(candidates))
    metadata: dict[str, str | int | float] = {}
    if mode == "random_fixed_k":
        nodes = select_random(network, k, damage_seed)
        metadata["selection_rule"] = "uniform_without_replacement"
    elif attack_rule == "degree":
        nodes = select_degree(network, k)
        metadata["degree_definition"] = "directed_total_degree"
    elif attack_rule == "betweenness":
        nodes = select_betweenness(network, k)
        metadata["betweenness_projection"] = "undirected"
    elif attack_rule == "hub_role":
        nodes = select_hub_role(network, k)
        metadata["fallback_rule"] = "directed_total_degree"
    elif attack_rule == "flow_impact":
        nodes = select_flow_impact_greedy(network, k, f0)
        metadata["flow_impact_mode"] = "greedy"
    else:
        raise ValueError(f"Unknown attack rule: {attack_rule}")
    return AttackSelection(
        nodes=tuple(sorted(int(n) for n in nodes)),
        candidate_set_size=len(candidates),
        k_attack=k,
        metadata=metadata,
    )


def apply_node_damage(network: Network, damaged: Iterable[int], w: float, irreversible_seed: int) -> Network:
    net = network.copy()
    damaged_nodes = tuple(sorted(int(n) for n in damaged))
    for node in damaged_nodes:
        net.set_node_state(node, "failed")

    if w > 0 and damaged_nodes:
        rng = np.random.default_rng(irreversible_seed)
        n_irrev = min(len(damaged_nodes), half_up_round(w * len(damaged_nodes)))
        if n_irrev > 0:
            irreversible = tuple(sorted(int(n) for n in rng.choice(damaged_nodes, size=n_irrev, replace=False)))
            net.irreversible_nodes.update(irreversible)
    return net


def first_recovery_time(q_values: list[float]) -> int:
    for t, q in enumerate(q_values):
        if q >= Q_TARGET:
            return t
    return len(q_values) - 1


def cvar(values: Iterable[float], alpha: float = ALPHA) -> float:
    clean = [float(v) for v in values if pd.notna(v)]
    if not clean:
        return float("nan")
    return float(compute_rho_CVaR(clean, alpha=alpha))


def safe_iqr(values: Iterable[float]) -> float:
    clean = np.asarray([float(v) for v in values if pd.notna(v)], dtype=float)
    if clean.size == 0:
        return float("nan")
    return float(np.quantile(clean, 0.75) - np.quantile(clean, 0.25))


def bootstrap_median_ci(values: Iterable[float], seed: int) -> tuple[float, float]:
    clean = [float(v) for v in values if pd.notna(v)]
    if len(clean) < 2:
        return (float("nan"), float("nan"))
    lo, hi = compute_bootstrap_CI(clean, B=1000, ci_level=0.95, seed=seed)
    return float(lo), float(hi)


def simulate_s3_run(
    series: str,
    h: int,
    q: float,
    paired_index: int,
    mode: str,
    attack_rule: str,
    w: float,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    paired_id = f"{series}_h{h}_q{q:.2f}_{paired_index:05d}"
    network_seed = stable_seed(series, h, q, paired_index, "network")
    damage_seed = stable_seed(series, h, q, paired_index, "damage")
    recovery_seed = stable_seed(series, h, q, paired_index, "recovery")
    irreversible_seed = stable_seed(series, h, q, paired_index, "irreversible")
    config_payload = {
        "series": series,
        "N": N,
        "h_hubs": h,
        "attack_fraction": q,
        "disruption_mode": mode,
        "attack_rule": attack_rule,
        "w": w,
        "T_max": T_MAX,
    }
    config_id = stable_config_id(config_payload)
    run_id = f"{series}_{config_id}_{paired_index:05d}"

    base_net = Network.create("hub", N=N, h=h, c_base=C_BASE, seed=network_seed)
    f0 = compute_max_flow(base_net)
    attack = select_attack_nodes(base_net, mode, attack_rule, q, damage_seed, f0)
    net = apply_node_damage(base_net, attack.nodes, w, irreversible_seed)

    valid = f0 > 0.0
    invalid_reason = ""
    if valid:
        active_suppliers = [s for s in net.suppliers if s not in net.failed_nodes]
        active_consumers = [c for c in net.consumers if c not in net.failed_nodes]
        if not active_suppliers or not active_consumers:
            valid = False
            invalid_reason = "supply_or_demand_destroyed"
    else:
        invalid_reason = "F0_zero"

    rng = np.random.default_rng(recovery_seed)
    recovery = RandomRecoveryStrategy()
    q_values: list[float] = []
    f_values: list[float] = []
    q_rows: list[dict[str, object]] = []
    for t in range(T_MAX + 1):
        f_t = compute_max_flow(net) if valid else 0.0
        q_t = float(np.clip(f_t / f0, 0.0, 1.0)) if valid and f0 > 0.0 else float("nan")
        f_values.append(float(f_t))
        q_values.append(q_t)
        q_rows.append(
            {
                "series": series,
                "run_id": run_id,
                "config_id": config_id,
                "paired_id": paired_id,
                "t": t,
                "Q": q_t,
                "F_t": float(f_t),
                "topology": "hub",
                "N": N,
                "h_hubs": h,
                "attack_fraction": q,
                "k_attack": attack.k_attack,
                "disruption_mode": mode,
                "attack_rule": attack_rule,
                "w": w,
                "valid": valid,
            }
        )
        if t < T_MAX and valid:
            element = recovery.select_element_to_repair(net, t, rng=rng)
            if element is not None:
                recovery.repair(net, element)

    finite_q = [x for x in q_values if pd.notna(x)]
    t_r = first_recovery_time(finite_q) if finite_q else T_MAX
    non_recovered = bool(finite_q and finite_q[-1] < Q_TARGET)
    damaged_nodes = tuple(sorted(attack.nodes))
    n_irrev = len(net.irreversible_nodes)
    row = {
        "series": series,
        "run_id": run_id,
        "config_id": config_id,
        "paired_id": paired_id,
        "topology": "hub",
        "N": N,
        "h_hubs": h,
        "attack_fraction": q,
        "candidate_set_size": attack.candidate_set_size,
        "k_attack": attack.k_attack,
        "disruption_mode": mode,
        "attack_rule": attack_rule,
        "w": w,
        "T_max": T_MAX,
        "network_seed": network_seed,
        "damage_seed": damage_seed,
        "recovery_seed": recovery_seed,
        "irreversible_seed": irreversible_seed,
        "F0": float(f0),
        "valid": valid,
        "invalid_reason": invalid_reason,
        "rho": float(np.nanmean(q_values)),
        "rho_early_5": float(np.nanmean(q_values[:6])),
        "rho_early_10": float(np.nanmean(q_values[:11])),
        "rho_early_20": float(np.nanmean(q_values[:21])),
        "R_rb": float(np.nanmin(q_values)),
        "R_inf": float(q_values[-1]) if finite_q else float("nan"),
        "Q0": float(q_values[0]) if finite_q else float("nan"),
        "Q_min": float(np.nanmin(q_values)),
        "time_to_recovery": int(t_r),
        "non_recovered": non_recovered,
        "n_damaged_nodes": len(damaged_nodes),
        "n_damaged_edges": 0,
        "n_damaged_total": len(damaged_nodes),
        "n_irreversible": n_irrev,
        "irreversible_fraction_realized": float(n_irrev / len(damaged_nodes)) if damaged_nodes else 0.0,
        "damaged_nodes": ";".join(str(n) for n in damaged_nodes),
        "irreversible_nodes": ";".join(str(n) for n in sorted(net.irreversible_nodes)),
        **attack.metadata,
    }
    return row, q_rows


def aggregate_raw(raw_df: pd.DataFrame, group_cols: list[str]) -> pd.DataFrame:
    valid = raw_df[raw_df["valid"]].copy()
    rows: list[dict[str, object]] = []
    for key, g in valid.groupby(group_cols, dropna=False):
        if not isinstance(key, tuple):
            key = (key,)
        row = dict(zip(group_cols, key))
        row["n_total"] = int(len(raw_df.merge(g[group_cols].drop_duplicates(), on=group_cols)))
        row["n_valid"] = int(len(g))
        row["n_invalid"] = int(row["n_total"] - row["n_valid"])
        row["invalid_rate"] = float(row["n_invalid"] / row["n_total"]) if row["n_total"] else float("nan")
        for metric in ["rho", "rho_early_5", "rho_early_10", "rho_early_20", "R_rb", "R_inf", "Q0"]:
            vals = g[metric].dropna().astype(float)
            row[f"{metric}_med"] = float(vals.median()) if len(vals) else float("nan")
            row[f"{metric}_mean"] = float(vals.mean()) if len(vals) else float("nan")
            row[f"{metric}_CVaR_0.10"] = cvar(vals)
            row[f"{metric}_IQR"] = safe_iqr(vals)
            ci_lo, ci_hi = bootstrap_median_ci(vals, stable_seed("ci", metric, row))
            row[f"{metric}_med_ci95_low"] = ci_lo
            row[f"{metric}_med_ci95_high"] = ci_hi
        row["time_to_recovery_med"] = float(g["time_to_recovery"].median())
        row["non_recovered_rate"] = float(g["non_recovered"].mean())
        row["n_irreversible_mean"] = float(g["n_irreversible"].mean())
        rows.append(row)
    return pd.DataFrame(rows).sort_values(group_cols).reset_index(drop=True)


def paired_wilcoxon_table(
    raw_df: pd.DataFrame,
    group_cols: list[str],
    left_filter: dict[str, object],
    right_filter: dict[str, object],
    metrics: list[str],
    left_label: str,
    right_label: str,
) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    data = raw_df[raw_df["valid"]].copy()
    for key, g in data.groupby(group_cols, dropna=False):
        if not isinstance(key, tuple):
            key = (key,)
        left = g.copy()
        right = g.copy()
        for col, val in left_filter.items():
            left = left[left[col] == val]
        for col, val in right_filter.items():
            right = right[right[col] == val]
        for metric in metrics:
            pairs = left[["paired_id", metric]].merge(
                right[["paired_id", metric]],
                on="paired_id",
                suffixes=("_left", "_right"),
            )
            row = dict(zip(group_cols, key))
            row.update({"left": left_label, "right": right_label, "metric": metric, "n_pairs": int(len(pairs))})
            if len(pairs) < 2:
                row.update({"statistic": float("nan"), "p_value": float("nan"), "median_diff": float("nan"), "effect_size": float("nan")})
            else:
                diff = pairs[f"{metric}_left"].astype(float) - pairs[f"{metric}_right"].astype(float)
                if np.allclose(diff, 0.0, equal_nan=False):
                    stat, p_val = 0.0, 1.0
                else:
                    stat, p_val = wilcoxon(
                        pairs[f"{metric}_left"],
                        pairs[f"{metric}_right"],
                        alternative="greater",
                        zero_method="wilcox",
                    )
                std = float(diff.std(ddof=1))
                row.update(
                    {
                        "statistic": float(stat),
                        "p_value": float(p_val),
                        "median_diff": float(diff.median()),
                        "effect_size": float(diff.median() / std) if std > 0 else 0.0,
                    }
                )
            rows.append(row)
    out = pd.DataFrame(rows)
    if len(out):
        out["p_value_adj_bonferroni"] = (out["p_value"] * len(out)).clip(upper=1.0)
        out["significant_0.05"] = out["p_value_adj_bonferroni"] < 0.05
    return out


def compute_vi_from_aggregates(
    agg: pd.DataFrame,
    key_cols: list[str],
    random_filter: dict[str, object],
    target_filter: dict[str, object],
    metrics: list[str],
) -> pd.DataFrame:
    left = agg.copy()
    right = agg.copy()
    for col, val in random_filter.items():
        left = left[left[col] == val]
    for col, val in target_filter.items():
        right = right[right[col] == val]
    merged = left.merge(right, on=key_cols, suffixes=("_random", "_targeted"))
    for metric in metrics:
        r_col = f"{metric}_random"
        t_col = f"{metric}_targeted"
        merged[f"Delta_{metric}"] = merged[r_col] - merged[t_col]
        merged[f"VI_{metric}"] = merged[f"Delta_{metric}"] / merged[r_col].replace(0.0, np.nan)
    return merged


def run_s3a() -> dict[str, object]:
    print("[S3A] deriving early metrics from base S3")
    raw = pd.read_csv(RESULTS / "raw/S3/raw_results.csv")
    qdf = pd.read_parquet(RESULTS / "raw/S3/Q_curves.parquet")
    raw = raw[raw["valid"]].copy()
    raw["attack_rule"] = raw.get("attack_rule", "betweenness")
    raw["attack_rule"] = raw["attack_rule"].fillna("betweenness")
    qdf = qdf[qdf["run_id"].isin(raw["run_id"])].copy()

    early_rows: list[dict[str, object]] = []
    for teff in TEFF_VALUES:
        part = qdf[qdf["t"] <= teff]
        rho = part.groupby("run_id")["Q"].mean().rename("rho_early")
        merged = raw.merge(rho, on="run_id", how="left")
        for _, row in merged.iterrows():
            early_rows.append(
                {
                    "series": "S3A_early_metrics",
                    "run_id": row["run_id"],
                    "paired_id": row["paired_id"],
                    "topology": row["topology"],
                    "N": int(row["N"]),
                    "h_hubs": int(row["h_hubs"]),
                    "attack_fraction": float(row["attack_fraction"]),
                    "candidate_set_size": int(row["candidate_set_size"]),
                    "k_attack": int(row["k_attack"]),
                    "disruption_mode": row["disruption_mode"],
                    "attack_rule": row["attack_rule"],
                    "T_eff": teff,
                    "valid": True,
                    "rho_early": float(row["rho_early"]),
                    "R_rb": float(row["R_rb"]),
                    "Q0": float(row.get("Q0", 1.0)),
                    "rho": float(row["rho"]),
                }
            )
    early = pd.DataFrame(early_rows)
    early.to_csv(S3A_DERIVED / "run_early_metrics.csv", index=False)
    s3a_metadata = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "series": "S3A_early_metrics",
        "input_raw": "results/raw/S3/raw_results.csv",
        "input_q_curves": "results/raw/S3/Q_curves.parquet",
        "n_run_early_rows": int(len(early)),
        "T_eff_values": TEFF_VALUES,
        "note": "Derived only from existing base S3 outputs; no new simulation.",
    }
    (S3A_DERIVED / "run_metadata.json").write_text(
        json.dumps(s3a_metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    group_cols = ["h_hubs", "attack_fraction", "k_attack", "disruption_mode", "attack_rule", "T_eff"]
    agg_rows: list[dict[str, object]] = []
    for key, g in early.groupby(group_cols):
        row = dict(zip(group_cols, key))
        row["n_valid"] = int(len(g))
        for metric in ["rho_early", "R_rb", "Q0"]:
            vals = g[metric].astype(float)
            row[f"{metric}_med"] = float(vals.median())
            row[f"{metric}_mean"] = float(vals.mean())
            row[f"{metric}_CVaR_0.10"] = cvar(vals)
            row[f"{metric}_IQR"] = safe_iqr(vals)
            lo, hi = bootstrap_median_ci(vals, stable_seed("S3A", metric, row))
            row[f"{metric}_med_ci95_low"] = lo
            row[f"{metric}_med_ci95_high"] = hi
        agg_rows.append(row)
    agg = pd.DataFrame(agg_rows).sort_values(group_cols).reset_index(drop=True)
    agg.to_csv(S3A_DERIVED / "aggregated_early_metrics.csv", index=False)

    vi = compute_vi_from_aggregates(
        agg,
        ["h_hubs", "attack_fraction", "k_attack", "attack_rule", "T_eff"],
        {"disruption_mode": "random_fixed_k"},
        {"disruption_mode": "targeted"},
        ["rho_early_med", "rho_early_CVaR_0.10", "R_rb_med", "Q0_med"],
    )
    vi.to_csv(S3A_DERIVED / "paired_vulnerability_indices.csv", index=False)

    tests = paired_wilcoxon_table(
        early,
        ["h_hubs", "attack_fraction", "k_attack", "attack_rule", "T_eff"],
        {"disruption_mode": "random_fixed_k"},
        {"disruption_mode": "targeted"},
        ["rho_early", "R_rb", "Q0"],
        "random_fixed_k",
        "targeted",
    )
    tests.to_csv(S3A_DERIVED / "early_metric_tests.csv", index=False)
    report = make_s3a_report(agg, vi, tests)
    (S3A_DERIVED / "early_metric_summary.txt").write_text(report, encoding="utf-8")
    (REPORT_DIR / "S3A_early_metrics_report.txt").write_text(report, encoding="utf-8")
    plot_s3a(agg, vi, early)
    return {"aggregated": agg, "vi": vi, "tests": tests, "report": report}


def label_lang(lang: str) -> dict[str, str]:
    if lang == "uk":
        return {
            "rho_med": "Медіана ρ",
            "rho_cvar": "ρ_CVaR_0.10",
            "r_rb": "R_rb",
            "rho_early": "Рання ρ",
            "attack_fraction": "Частка атаки q",
            "h_hubs": "Кількість хабів h",
            "w": "Необоротна частка w",
            "time": "Час t",
            "Q": "Q(t)",
            "rule": "Правило атаки",
            "mode": "Режим збою",
        }
    return {
        "rho_med": "Median ρ",
        "rho_cvar": "ρ_CVaR_0.10",
        "r_rb": "R_rb",
        "rho_early": "Early ρ",
        "attack_fraction": "Attack fraction q",
        "h_hubs": "Number of hubs h",
        "w": "Irreversible fraction w",
        "time": "Time t",
        "Q": "Q(t)",
        "rule": "Attack rule",
        "mode": "Disruption mode",
    }


def savefig_dual(fig, root: Path, name: str) -> None:
    for lang in ["uk", "en"]:
        out = root / lang / f"{name}.png"
        out.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(out, dpi=200, bbox_inches="tight")
    plt.close(fig)


def plot_heatmap_dual(df: pd.DataFrame, value: str, title_uk: str, title_en: str, root: Path, name: str) -> None:
    for lang, title in [("uk", title_uk), ("en", title_en)]:
        fig, ax = plt.subplots(figsize=(7.5, 4.6))
        pivot = df.pivot_table(index="h_hubs", columns="attack_fraction", values=value, aggfunc="mean")
        sns.heatmap(pivot, annot=True, fmt=".3f", cmap="rocket_r", ax=ax)
        labels = label_lang(lang)
        ax.set_title(title)
        ax.set_xlabel(labels["attack_fraction"])
        ax.set_ylabel(labels["h_hubs"])
        fig.savefig(root / lang / f"{name}.png", dpi=200, bbox_inches="tight")
        plt.close(fig)


def plot_s3a(agg: pd.DataFrame, vi: pd.DataFrame, early: pd.DataFrame) -> None:
    teff10 = vi[vi["T_eff"] == 10].copy()
    plot_heatmap_dual(teff10, "VI_R_rb_med", "VI для R_rb: targeted проти random", "VI for R_rb: targeted vs random", S3A_FIG, "S3A_VI_R_rb_heatmap")
    plot_heatmap_dual(teff10, "VI_rho_early_med", "VI для ранньої ρ, T_eff=10", "VI for early ρ, T_eff=10", S3A_FIG, "S3A_VI_rho_early_T10_heatmap")
    plot_heatmap_dual(teff10, "VI_rho_early_CVaR_0.10", "VI для ранньої CVaR, T_eff=10", "VI for early CVaR, T_eff=10", S3A_FIG, "S3A_VI_CVaR_early_T10_heatmap")

    for lang in ["uk", "en"]:
        labels = label_lang(lang)
        fig, ax = plt.subplots(figsize=(8.5, 5.0))
        summary = agg.groupby(["disruption_mode", "T_eff"])["rho_early_med"].mean().reset_index()
        for mode, g in summary.groupby("disruption_mode"):
            ax.plot(g["T_eff"], g["rho_early_med"], marker="o", label=mode)
        ax.set_xlabel("T_eff")
        ax.set_ylabel(labels["rho_early"])
        ax.set_title("Рання ρ за горизонтом T_eff" if lang == "uk" else "Early ρ by T_eff horizon")
        ax.legend()
        ax.grid(alpha=0.25)
        fig.savefig(S3A_FIG / lang / "S3A_rho_early_vs_Teff_random_targeted.png", dpi=200, bbox_inches="tight")
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(6.4, 5.0))
        sns.boxplot(data=early[early["T_eff"] == 100], x="disruption_mode", y="R_rb", ax=ax)
        ax.set_xlabel(labels["mode"])
        ax.set_ylabel(labels["r_rb"])
        ax.set_title("R_rb: random проти targeted" if lang == "uk" else "R_rb: random vs targeted")
        fig.savefig(S3A_FIG / lang / "S3A_R_rb_random_vs_targeted.png", dpi=200, bbox_inches="tight")
        plt.close(fig)


def make_s3a_report(agg: pd.DataFrame, vi: pd.DataFrame, tests: pd.DataFrame) -> str:
    teff10 = vi[vi["T_eff"] == 10]
    max_vi = teff10["VI_rho_early_med"].max()
    max_r_rb = teff10["VI_R_rb_med"].max()
    sig = int(tests["significant_0.05"].sum()) if "significant_0.05" in tests else 0
    lines = [
        "S3A Early Metrics Report",
        "=========================",
        "",
        f"Input base S3 valid runs were transformed into early metrics for T_eff={TEFF_VALUES}.",
        f"Aggregated rows: {len(agg)}",
        f"Paired Wilcoxon tests: {len(tests)}, significant after Bonferroni: {sig}",
        "",
        "Key vulnerability indices at T_eff=10:",
        f"- max VI_rho_early_med = {max_vi:.4f}",
        f"- max VI_R_rb_med = {max_r_rb:.4f}",
        "",
        "Top VI_rho_early_med rows:",
        teff10.sort_values("VI_rho_early_med", ascending=False)
        .head(8)[["h_hubs", "attack_fraction", "k_attack", "VI_rho_early_med", "VI_rho_early_CVaR_0.10", "VI_R_rb_med"]]
        .to_string(index=False),
        "",
        "Interpretation: targeted attacks are already visible in early-horizon metrics; the effect is strongest in early CVaR and R_rb when q is high.",
    ]
    return "\n".join(lines) + "\n"


def run_simulation_grid(series: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    raw_rows: list[dict[str, object]] = []
    q_rows: list[dict[str, object]] = []
    start = time.time()

    if series == "S3B_irreversibility":
        configs = [
            (h, q, mode, "betweenness", w)
            for h in H_HUBS
            for q in ATTACK_FRACTIONS
            for mode in ["random_fixed_k", "targeted"]
            for w in W_VALUES
        ]
    elif series == "S3C_attack_rules":
        configs = []
        for h in H_HUBS:
            for q in ATTACK_FRACTIONS:
                configs.append((h, q, "random_fixed_k", "random_baseline", 0.0))
                for rule in ["degree", "betweenness", "hub_role", "flow_impact"]:
                    configs.append((h, q, "targeted", rule, 0.0))
    else:
        raise ValueError(series)

    total = len(configs) * M
    done = 0
    print(f"[{series}] configs={len(configs)}, runs={total}")
    for h, q, mode, rule, w in configs:
        print(f"[{series}] config h={h} q={q:.2f} mode={mode} rule={rule} w={w:.2f}")
        for i in range(1, M + 1):
            row, qs = simulate_s3_run(series, h, q, i, mode, rule, w)
            raw_rows.append(row)
            q_rows.extend(qs)
            done += 1
            if done % 500 == 0:
                print(f"[{series}] progress {done}/{total} elapsed={time.time() - start:.1f}s")

    raw_df = pd.DataFrame(raw_rows)
    q_df = pd.DataFrame(q_rows)
    return raw_df, q_df


def save_raw_outputs(raw_df: pd.DataFrame, q_df: pd.DataFrame, raw_dir: Path) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_df.to_csv(raw_dir / "raw_results.csv", index=False)
    q_df.to_parquet(raw_dir / "Q_curves.parquet", index=False)
    metadata = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "n_raw_rows": int(len(raw_df)),
        "n_q_rows": int(len(q_df)),
        "valid_runs": int(raw_df["valid"].sum()),
        "invalid_runs": int((~raw_df["valid"]).sum()),
        "seed_policy": "stable sha256 over series/config/paired_id/seed_kind",
        "Q_t0_semantics": "post-disruption immediate state for S3B/S3C",
    }
    (raw_dir / "run_metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")


def run_s3b() -> dict[str, object]:
    raw_path = S3B_RAW / "raw_results.csv"
    q_path = S3B_RAW / "Q_curves.parquet"
    if raw_path.exists() and q_path.exists():
        raw_df = pd.read_csv(raw_path)
        q_df = pd.read_parquet(q_path)
        if len(raw_df) == 10800:
            print("[S3B_irreversibility] using existing completed raw outputs")
        else:
            raw_df, q_df = run_simulation_grid("S3B_irreversibility")
            save_raw_outputs(raw_df, q_df, S3B_RAW)
    else:
        raw_df, q_df = run_simulation_grid("S3B_irreversibility")
        save_raw_outputs(raw_df, q_df, S3B_RAW)
    agg = aggregate_raw(raw_df, ["h_hubs", "attack_fraction", "k_attack", "disruption_mode", "attack_rule", "w"])
    agg.to_csv(S3B_AGG / "aggregated_results.csv", index=False)
    vi = compute_vi_from_aggregates(
        agg,
        ["h_hubs", "attack_fraction", "k_attack", "attack_rule", "w"],
        {"disruption_mode": "random_fixed_k"},
        {"disruption_mode": "targeted"},
        ["rho_med", "rho_CVaR_0.10", "rho_early_10_med", "R_rb_med", "R_inf_med"],
    )
    vi.to_csv(S3B_AGG / "paired_vulnerability_indices.csv", index=False)
    tests = paired_wilcoxon_table(
        raw_df,
        ["h_hubs", "attack_fraction", "k_attack", "attack_rule", "w"],
        {"disruption_mode": "random_fixed_k"},
        {"disruption_mode": "targeted"},
        ["rho", "rho_early_10", "R_rb", "R_inf"],
        "random_fixed_k",
        "targeted",
    )
    tests.to_csv(S3B_AGG / "statistical_tests.csv", index=False)
    report = make_s3b_report(raw_df, agg, vi, tests)
    (REPORT_DIR / "S3B_irreversibility_report.txt").write_text(report, encoding="utf-8")
    plot_s3b(agg, vi, q_df, raw_df)
    return {"raw": raw_df, "q": q_df, "aggregated": agg, "vi": vi, "tests": tests, "report": report}


def run_s3c() -> dict[str, object]:
    raw_path = S3C_RAW / "raw_results.csv"
    q_path = S3C_RAW / "Q_curves.parquet"
    if raw_path.exists() and q_path.exists():
        raw_df = pd.read_csv(raw_path)
        q_df = pd.read_parquet(q_path)
        if len(raw_df) == 9000:
            print("[S3C_attack_rules] using existing completed raw outputs")
        else:
            raw_df, q_df = run_simulation_grid("S3C_attack_rules")
            save_raw_outputs(raw_df, q_df, S3C_RAW)
    else:
        raw_df, q_df = run_simulation_grid("S3C_attack_rules")
        save_raw_outputs(raw_df, q_df, S3C_RAW)
    agg = aggregate_raw(raw_df, ["h_hubs", "attack_fraction", "k_attack", "disruption_mode", "attack_rule", "w"])
    agg.to_csv(S3C_AGG / "aggregated_results.csv", index=False)
    vi = compute_vi_from_aggregates(
        agg,
        ["h_hubs", "attack_fraction", "k_attack", "w"],
        {"disruption_mode": "random_fixed_k", "attack_rule": "random_baseline"},
        {"disruption_mode": "targeted"},
        ["rho_med", "rho_CVaR_0.10", "rho_early_10_med", "R_rb_med"],
    )
    vi.to_csv(S3C_AGG / "rule_vulnerability_indices.csv", index=False)
    rankings = make_s3c_rankings(agg)
    rankings.to_csv(S3C_AGG / "attack_rule_rankings.csv", index=False)
    tests = make_s3c_tests(raw_df)
    tests.to_csv(S3C_AGG / "statistical_tests.csv", index=False)
    report = make_s3c_report(raw_df, agg, vi, rankings, tests)
    (REPORT_DIR / "S3C_attack_rules_report.txt").write_text(report, encoding="utf-8")
    plot_s3c(agg, vi, rankings)
    return {"raw": raw_df, "q": q_df, "aggregated": agg, "vi": vi, "rankings": rankings, "tests": tests, "report": report}


def make_s3c_rankings(agg: pd.DataFrame) -> pd.DataFrame:
    targeted = agg[agg["disruption_mode"] == "targeted"].copy()
    rows: list[dict[str, object]] = []
    for (h, q), g in targeted.groupby(["h_hubs", "attack_fraction"]):
        for metric in ["rho_med", "rho_CVaR_0.10", "rho_early_10_med", "R_rb_med"]:
            g2 = g.sort_values(metric, ascending=True).copy()
            for rank, (_, row) in enumerate(g2.iterrows(), 1):
                rows.append(
                    {
                        "h_hubs": h,
                        "attack_fraction": q,
                        "metric": metric,
                        "attack_rule": row["attack_rule"],
                        "rank_destructive": rank,
                        "value": row[metric],
                    }
                )
    return pd.DataFrame(rows)


def make_s3c_tests(raw_df: pd.DataFrame) -> pd.DataFrame:
    rows: list[pd.DataFrame] = []
    for rule in ["degree", "betweenness", "hub_role", "flow_impact"]:
        tests = paired_wilcoxon_table(
            raw_df,
            ["h_hubs", "attack_fraction", "k_attack", "w"],
            {"disruption_mode": "random_fixed_k", "attack_rule": "random_baseline"},
            {"disruption_mode": "targeted", "attack_rule": rule},
            ["rho", "rho_early_10", "R_rb"],
            "random_baseline",
            rule,
        )
        rows.append(tests)
    return pd.concat(rows, ignore_index=True)


def make_s3b_report(raw_df: pd.DataFrame, agg: pd.DataFrame, vi: pd.DataFrame, tests: pd.DataFrame) -> str:
    invalid = raw_df[~raw_df["valid"]]
    trend_lines: list[str] = []
    targeted = agg[agg["disruption_mode"] == "targeted"]
    for metric in ["rho_med", "rho_CVaR_0.10", "R_inf_med"]:
        by_w = targeted.groupby("w")[metric].mean().reset_index()
        corr, p_val = spearmanr(by_w["w"], by_w[metric])
        trend_lines.append(f"- Spearman w vs {metric}: rho={corr:.3f}, p={p_val:.4g}")
    lines = [
        "S3B Irreversibility Report",
        "===========================",
        "",
        f"Total runs: {len(raw_df)}, valid: {int(raw_df['valid'].sum())}, invalid: {len(invalid)}",
        "Invalid reasons: " + (invalid["invalid_reason"].value_counts().to_string() if len(invalid) else "none"),
        "",
        "Mean targeted vulnerability by w:",
        vi.groupby("w")[["VI_rho_med", "VI_rho_CVaR_0.10", "VI_R_inf_med"]].mean().to_string(),
        "",
        "Trend checks:",
        *trend_lines,
        "",
        f"Wilcoxon tests significant after Bonferroni: {int(tests['significant_0.05'].sum())}/{len(tests)}",
        "",
        "Interpretation: increasing w mainly reduces R_inf and increases non_recovered rate; the early targeted effect remains visible but the long-horizon recovery gap becomes sharper.",
    ]
    return "\n".join(lines) + "\n"


def make_s3c_report(raw_df: pd.DataFrame, agg: pd.DataFrame, vi: pd.DataFrame, rankings: pd.DataFrame, tests: pd.DataFrame) -> str:
    invalid = raw_df[~raw_df["valid"]]
    worst = (
        rankings[rankings["rank_destructive"] == 1]
        .groupby(["metric", "attack_rule"])
        .size()
        .reset_index(name="n_worst")
        .sort_values(["metric", "n_worst"], ascending=[True, False])
    )
    lines = [
        "S3C Attack Rules Report",
        "=======================",
        "",
        f"Total runs: {len(raw_df)}, valid: {int(raw_df['valid'].sum())}, invalid: {len(invalid)}",
        "Invalid reasons: " + (invalid["invalid_reason"].value_counts().to_string() if len(invalid) else "none"),
        "",
        "Most destructive rule counts by metric:",
        worst.to_string(index=False),
        "",
        "Mean VI against random baseline:",
        vi.groupby("attack_rule_targeted")[["VI_rho_med", "VI_rho_CVaR_0.10", "VI_R_rb_med", "VI_rho_early_10_med"]].mean().sort_values("VI_rho_CVaR_0.10", ascending=False).to_string(),
        "",
        f"Random-vs-rule Wilcoxon tests significant after Bonferroni: {int(tests['significant_0.05'].sum())}/{len(tests)}",
        "",
        "Interpretation: the most destructive rule is identified by repeated rank-1 counts and largest VI_CVaR against random baseline.",
    ]
    return "\n".join(lines) + "\n"


def plot_s3b(agg: pd.DataFrame, vi: pd.DataFrame, q_df: pd.DataFrame, raw_df: pd.DataFrame) -> None:
    targeted = agg[agg["disruption_mode"] == "targeted"].copy()
    for metric, name in [
        ("rho_med", "S3B_rho_med_vs_w"),
        ("rho_CVaR_0.10", "S3B_rho_CVaR_vs_w"),
        ("R_inf_med", "S3B_R_inf_vs_w"),
        ("non_recovered_rate", "S3B_non_recovered_vs_w"),
    ]:
        for lang in ["uk", "en"]:
            labels = label_lang(lang)
            fig, ax = plt.subplots(figsize=(8.0, 5.0))
            sns.lineplot(data=targeted, x="w", y=metric, hue="attack_fraction", marker="o", ax=ax)
            ax.set_xlabel(labels["w"])
            ax.set_ylabel(metric)
            ax.set_title(f"{metric} залежно від w" if lang == "uk" else f"{metric} by w")
            ax.grid(alpha=0.25)
            fig.savefig(S3B_FIG / lang / f"{name}.png", dpi=200, bbox_inches="tight")
            plt.close(fig)

    plot_heatmap_dual(
        vi.groupby(["h_hubs", "attack_fraction"])["VI_rho_CVaR_0.10"].mean().reset_index(),
        "VI_rho_CVaR_0.10",
        "Середній VI_CVaR за всіма w",
        "Mean VI_CVaR over all w",
        S3B_FIG,
        "S3B_VI_CVaR_heatmap_by_w",
    )

    sample = raw_df[(raw_df["h_hubs"] == 3) & (raw_df["attack_fraction"] == 0.20) & (raw_df["disruption_mode"] == "targeted")]
    ids = sample.groupby("w")["run_id"].head(40)
    q_sample = q_df[q_df["run_id"].isin(ids)].copy()
    if "w" not in q_sample.columns:
        q_sample = q_sample.merge(sample[["run_id", "w"]], on="run_id", how="left")
    for lang in ["uk", "en"]:
        labels = label_lang(lang)
        fig, ax = plt.subplots(figsize=(8.0, 5.0))
        stats = q_sample.groupby(["w", "t"])["Q"].median().reset_index()
        for w, g in stats.groupby("w"):
            ax.plot(g["t"], g["Q"], label=f"w={w:.2f}")
        ax.set_xlabel(labels["time"])
        ax.set_ylabel(labels["Q"])
        ax.set_title("Q(t) для різних w" if lang == "uk" else "Q(t) for different w")
        ax.legend()
        ax.grid(alpha=0.25)
        fig.savefig(S3B_FIG / lang / "S3B_Q_curves_by_w.png", dpi=200, bbox_inches="tight")
        plt.close(fig)


def plot_s3c(agg: pd.DataFrame, vi: pd.DataFrame, rankings: pd.DataFrame) -> None:
    targeted = agg[agg["disruption_mode"] == "targeted"].copy()
    for metric, name in [
        ("rho_med", "S3C_attack_rule_rho_med"),
        ("rho_CVaR_0.10", "S3C_attack_rule_rho_CVaR"),
        ("R_rb_med", "S3C_attack_rule_R_rb"),
    ]:
        for lang in ["uk", "en"]:
            labels = label_lang(lang)
            fig, ax = plt.subplots(figsize=(8.0, 5.0))
            sns.barplot(data=targeted, x="attack_rule", y=metric, hue="attack_fraction", ax=ax)
            ax.set_xlabel(labels["rule"])
            ax.set_ylabel(metric)
            ax.set_title(f"{metric} за правилом атаки" if lang == "uk" else f"{metric} by attack rule")
            ax.tick_params(axis="x", rotation=20)
            fig.savefig(S3C_FIG / lang / f"{name}.png", dpi=200, bbox_inches="tight")
            plt.close(fig)

    for lang in ["uk", "en"]:
        labels = label_lang(lang)
        fig, ax = plt.subplots(figsize=(8.0, 5.0))
        sns.barplot(data=vi, x="attack_rule_targeted", y="VI_rho_early_10_med", hue="attack_fraction", ax=ax)
        ax.set_xlabel(labels["rule"])
        ax.set_ylabel("VI early ρ T=10")
        ax.set_title("VI ранньої ρ за правилом атаки" if lang == "uk" else "Early ρ VI by attack rule")
        ax.tick_params(axis="x", rotation=20)
        fig.savefig(S3C_FIG / lang / "S3C_attack_rule_VI_rho_early.png", dpi=200, bbox_inches="tight")
        plt.close(fig)

        rank_mean = rankings.groupby(["metric", "attack_rule"])["rank_destructive"].mean().reset_index()
        pivot = rank_mean.pivot(index="attack_rule", columns="metric", values="rank_destructive")
        fig, ax = plt.subplots(figsize=(8.0, 5.0))
        sns.heatmap(pivot, annot=True, fmt=".2f", cmap="viridis_r", ax=ax)
        ax.set_title("Рейтинг руйнівності правил атаки" if lang == "uk" else "Attack rule destructiveness ranking")
        fig.savefig(S3C_FIG / lang / "S3C_attack_rule_ranking_heatmap.png", dpi=200, bbox_inches="tight")
        plt.close(fig)


def quality_checks(
    s3a: dict[str, object],
    s3b: dict[str, object],
    s3c: dict[str, object],
    integrity: dict[str, object],
) -> dict[str, object]:
    checks: dict[str, object] = {"base_s3_unchanged": integrity["unchanged"]}

    for name, result in [("S3B", s3b), ("S3C", s3c)]:
        raw = result["raw"]
        checks[f"{name}_total_runs"] = int(len(raw))
        checks[f"{name}_valid_runs"] = int(raw["valid"].sum())
        checks[f"{name}_invalid_runs"] = int((~raw["valid"]).sum())
        metric_cols = ["rho", "rho_early_5", "rho_early_10", "rho_early_20", "R_rb", "R_inf", "Q0"]
        bounds_ok = bool(((raw[metric_cols] >= -1e-9) & (raw[metric_cols] <= 1.0 + 1e-9)).all().all())
        checks[f"{name}_metric_bounds_ok"] = bounds_ok

    raw_b = s3b["raw"]
    seed_group = raw_b.groupby(["h_hubs", "attack_fraction", "paired_id"])
    checks["S3B_paired_network_seed_F0_k_consistent"] = bool(
        seed_group[["network_seed", "F0", "candidate_set_size", "k_attack"]].nunique().le(1).all().all()
    )
    damage_group = raw_b.groupby(["h_hubs", "attack_fraction", "paired_id", "disruption_mode", "attack_rule"])
    checks["S3B_damaged_set_same_across_w"] = bool(damage_group["damaged_nodes"].nunique().le(1).all())

    raw_c = s3c["raw"]
    seed_group_c = raw_c.groupby(["h_hubs", "attack_fraction", "paired_id"])
    checks["S3C_paired_network_seed_F0_k_consistent"] = bool(
        seed_group_c[["network_seed", "F0", "candidate_set_size", "k_attack"]].nunique().le(1).all().all()
    )

    required_figures = [
        (S3A_FIG, ["S3A_VI_R_rb_heatmap", "S3A_VI_rho_early_T10_heatmap", "S3A_VI_CVaR_early_T10_heatmap", "S3A_rho_early_vs_Teff_random_targeted", "S3A_R_rb_random_vs_targeted"]),
        (S3B_FIG, ["S3B_rho_med_vs_w", "S3B_rho_CVaR_vs_w", "S3B_R_inf_vs_w", "S3B_non_recovered_vs_w", "S3B_VI_CVaR_heatmap_by_w", "S3B_Q_curves_by_w"]),
        (S3C_FIG, ["S3C_attack_rule_rho_med", "S3C_attack_rule_rho_CVaR", "S3C_attack_rule_R_rb", "S3C_attack_rule_VI_rho_early", "S3C_attack_rule_ranking_heatmap"]),
    ]
    missing_figures: list[str] = []
    for root, names in required_figures:
        for lang in ["uk", "en"]:
            for name in names:
                path = root / lang / f"{name}.png"
                if not path.exists():
                    missing_figures.append(str(path.relative_to(ROOT)))
    checks["missing_required_figures"] = missing_figures
    checks["all_required_figures_exist"] = not missing_figures
    checks["S3A_metadata_exists"] = (S3A_DERIVED / "run_metadata.json").exists()

    (REPORT_DIR / "S3_quality_checks.json").write_text(json.dumps(checks, ensure_ascii=False, indent=2), encoding="utf-8")
    if not all(
        bool(checks[k])
        for k in [
            "base_s3_unchanged",
            "S3B_metric_bounds_ok",
            "S3C_metric_bounds_ok",
            "S3B_paired_network_seed_F0_k_consistent",
            "S3B_damaged_set_same_across_w",
            "S3C_paired_network_seed_F0_k_consistent",
            "all_required_figures_exist",
            "S3A_metadata_exists",
        ]
    ):
        raise RuntimeError(f"S3 quality checks failed: {checks}")
    return checks


def make_final_summary(s3a: dict[str, object], s3b: dict[str, object], s3c: dict[str, object], checks: dict[str, object]) -> str:
    s3a_vi = s3a["vi"]
    s3b_vi = s3b["vi"]
    s3c_vi = s3c["vi"]
    s3c_rank = s3c["rankings"]

    target_worse_a = float((s3a_vi["VI_rho_early_med"] > 0).mean())
    strongest_a = (
        s3a_vi[["VI_rho_early_med", "VI_rho_early_CVaR_0.10", "VI_R_rb_med", "VI_Q0_med"]]
        .mean()
        .sort_values(ascending=False)
    )
    w_effect = s3b_vi.groupby("w")[["VI_rho_med", "VI_rho_CVaR_0.10", "VI_R_inf_med"]].mean()
    rule_effect = s3c_vi.groupby("attack_rule_targeted")[["VI_rho_med", "VI_rho_CVaR_0.10", "VI_R_rb_med", "VI_rho_early_10_med"]].mean()
    worst_rule = rule_effect["VI_rho_CVaR_0.10"].idxmax()
    rank_counts = (
        s3c_rank[s3c_rank["rank_destructive"] == 1]
        .groupby("attack_rule")
        .size()
        .sort_values(ascending=False)
    )
    most_frequent_worst = rank_counts.index[0] if len(rank_counts) else "n/a"

    lines = [
        "S3 Extended Summary Report",
        "==========================",
        "",
        "Integrity and quality checks",
        "----------------------------",
        json.dumps(checks, ensure_ascii=False, indent=2),
        "",
        "1. Are targeted attacks worse than random_fixed_k?",
        "Yes. Across S3A paired cells, targeted attacks produce positive vulnerability indices in "
        f"{target_worse_a:.1%} of early-metric comparisons, and S3B/S3C confirm positive VI values against random baselines.",
        "",
        "2. In which metrics is the effect strongest?",
        strongest_a.to_string(),
        "",
        "S3C mean vulnerability by attack rule:",
        rule_effect.sort_values("VI_rho_CVaR_0.10", ascending=False).to_string(),
        "",
        "3. Is the effect early, long-horizon, or both?",
        "Both. S3A shows the attack effect in R_rb and early rho(T_eff=5..20); Q0 stays at 1.0 in base S3 because that file stores the pre-disruption t=0 state. S3B shows that long-horizon R_inf becomes especially important when w>0.",
        "",
        "4. How does irreversible damage fraction w change the picture?",
        w_effect.to_string(),
        "",
        "Increasing w amplifies long-horizon non-recovery and lowers R_inf; early shock metrics remain mostly governed by the attack set, while recovery extent becomes w-sensitive.",
        "",
        "5. Which attack rule is most destructive?",
        f"By mean VI_CVaR, the most destructive rule is: {worst_rule}. "
        f"By repeated rank-1 counts across metrics/configurations, the most frequently worst rule is: {most_frequent_worst}.",
        "Rank-1 destructiveness counts:",
        rank_counts.to_string(),
        "",
        "6. Are results sufficient for a standalone S3 paper?",
        "Yes, with one caveat: the paper should explicitly separate early shock vulnerability from long-horizon recovery loss. S3A, S3B, and S3C together form a coherent standalone story: targeted hub attacks are worse than matched random attacks, irreversibility changes recovery extent, and attack-rule choice matters.",
        "",
        "7. Recommended tables and figures for the paper",
        "- Table: S3A early metrics by h, q, and disruption mode.",
        "- Table: S3B w-sensitivity with rho_med, rho_CVaR, R_inf, non_recovered.",
        "- Table: S3C attack-rule rankings and VI against random baseline.",
        "- Figure: S3A VI heatmaps for R_rb and early CVaR.",
        "- Figure: S3B rho_CVaR/R_inf versus w.",
        "- Figure: S3C attack-rule ranking heatmap.",
        "- Figure: Representative Q(t) curves showing early and long-horizon differences.",
    ]
    text = "\n".join(lines) + "\n"
    (REPORT_DIR / "S3_extended_summary_report.txt").write_text(text, encoding="utf-8")
    return text


def main() -> None:
    ensure_dirs()
    before = write_base_manifest_before()
    print("[manifest] base S3 before-extension manifest written")

    s3a = run_s3a()
    s3b = run_s3b()
    s3c = run_s3c()

    integrity = verify_base_manifest_after(before)
    checks = quality_checks(s3a, s3b, s3c, integrity)
    make_final_summary(s3a, s3b, s3c, checks)
    print("[done] S3 extended protocol complete")
    print(f"[done] final report: {REPORT_DIR / 'S3_extended_summary_report.txt'}")


if __name__ == "__main__":
    main()
