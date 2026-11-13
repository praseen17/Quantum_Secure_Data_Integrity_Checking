#!/usr/bin/env python3
"""Summarize Q-SAFE tidy benchmark CSV files without making unsupported claims."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "qsafe-matplotlib-cache"))
Path(os.environ["MPLCONFIGDIR"]).mkdir(parents=True, exist_ok=True)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import hypergeom


REQUIRED = {
    "strategy", "pattern", "repetition", "round", "file_bytes", "shard_count",
    "corruption_fraction", "sample_fraction", "sample_count", "wall_ms", "cpu_ms", "bytes_transferred",
    "detected", "repair_success", "repair_bytes", "sign_ms", "verify_ms",
    "storage_bytes", "metadata_bytes",
}


def bootstrap_median(values: np.ndarray, rng: np.random.Generator,
                     samples: int = 5000) -> tuple[float, float, float]:
    values = np.asarray(values, dtype=float)
    if values.size == 0:
        return float("nan"), float("nan"), float("nan")
    boot = np.median(rng.choice(values, size=(samples, values.size), replace=True), axis=1)
    return float(np.median(values)), float(np.quantile(boot, .025)), float(np.quantile(boot, .975))


def load(paths: list[Path]) -> pd.DataFrame:
    frames = [pd.read_csv(path) for path in paths]
    if not frames:
        raise ValueError("provide at least one benchmark CSV")
    data = pd.concat(frames, ignore_index=True)
    missing = REQUIRED - set(data.columns)
    if missing:
        raise ValueError("benchmark CSV is missing columns: " + ", ".join(sorted(missing)))
    if data.empty:
        raise ValueError("benchmark CSVs contain no rows")
    return data


def plot_detection(data: pd.DataFrame, output: Path) -> None:
    frame = data[data.strategy == "B1_uniform"].copy()
    if frame.empty:
        return
    frame["theoretical"] = [
        hypergeom.sf(0, int(n), int(round(n * rho)), int(k))
        for n, rho, k in zip(frame.shard_count, frame.corruption_fraction, frame.sample_count)
    ]
    grouped = frame.groupby("corruption_fraction").agg(
        empirical=("detected", "mean"), theoretical=("theoretical", "mean"))
    ax = grouped.plot(marker="o")
    ax.set(xlabel="Corruption fraction", ylabel="Detection probability", ylim=(0, 1),
           title="Uniform audit: empirical and hypergeometric detection")
    ax.figure.tight_layout()
    ax.figure.savefig(output / "detection_probability.png", dpi=160)
    plt.close(ax.figure)


def plot_time_to_detection(data: pd.DataFrame, output: Path, rng: np.random.Generator) -> None:
    rows = []
    keys = ["pattern", "sample_fraction", "strategy", "repetition"]
    for (pattern, sample_fraction, strategy, repetition), group in data.sort_values("round").groupby(keys):
        hits = group[group.detected.astype(bool)]
        rounds = float(hits.iloc[0]["round"]) if not hits.empty else float(group.iloc[-1]["round"] + 1)
        rows.append({"pattern": pattern, "sample_fraction": sample_fraction,
                     "strategy": strategy, "repetition": repetition,
                     "rounds": rounds, "audit_cost": group.bytes_transferred.mean()})
    ttd = pd.DataFrame(rows)
    if ttd.empty:
        return
    patterns = list(ttd.pattern.unique())
    fig, axes = plt.subplots(1, len(patterns), figsize=(6 * len(patterns), 4), squeeze=False)
    for ax, pattern in zip(axes[0], patterns):
        subset = ttd[ttd.pattern == pattern]
        for (strategy, fraction), group in subset.groupby(["strategy", "sample_fraction"]):
            median, low, high = bootstrap_median(group.rounds.to_numpy(), rng)
            cost = float(group.audit_cost.median())
            ax.errorbar(cost, median, yerr=[[median - low], [high - median]], marker="o",
                        capsize=4, label=f"{strategy} @ {fraction:g}")
        ax.set(title=pattern, xlabel="Mean bytes transferred per audit", ylabel="Rounds to detection")
        ax.legend()
    fig.tight_layout()
    fig.savefig(output / "time_to_detection.png", dpi=160)
    plt.close(fig)


def plot_repair_bytes(data: pd.DataFrame, output: Path) -> None:
    frame = data[data.repair_success.astype(bool)]
    if frame.empty:
        return
    summary = frame.groupby("strategy")[["repair_bytes", "file_bytes"]].median().sort_values(
        "repair_bytes")
    summary = summary.rename(columns={"repair_bytes": "Observed repair", "file_bytes": "Whole-file restore"})
    ax = summary.plot(kind="bar")
    ax.set(ylabel="Median bytes", title="Stripe repair traffic versus whole-file restore")
    ax.figure.tight_layout()
    ax.figure.savefig(output / "repair_bytes.png", dpi=160)
    plt.close(ax.figure)


def plot_crypto_share(data: pd.DataFrame, output: Path) -> None:
    frame = data.copy()
    frame["crypto_share"] = (frame.sign_ms + frame.verify_ms) / frame.wall_ms.replace(0, np.nan)
    summary = frame.groupby("strategy").crypto_share.median().dropna()
    if summary.empty:
        return
    ax = summary.plot(kind="bar")
    ax.set(ylabel="Median fraction of audit wall time", title="ML-DSA signing and verification share")
    ax.figure.tight_layout()
    ax.figure.savefig(output / "crypto_time_share.png", dpi=160)
    plt.close(ax.figure)


def write_overheads(data: pd.DataFrame, output: Path) -> None:
    frame = data.copy()
    frame["storage_overhead"] = (frame.storage_bytes - frame.file_bytes) / frame.file_bytes.replace(0, np.nan)
    frame["metadata_fraction"] = frame.metadata_bytes / frame.file_bytes.replace(0, np.nan)
    frame.groupby("strategy")[["storage_overhead", "metadata_fraction", "metadata_bytes"]].median().to_csv(
        output / "overhead_summary.csv")


def print_hypothesis_summary(data: pd.DataFrame, rng: np.random.Generator) -> None:
    ttd = []
    for (pattern, sample_fraction, strategy, repetition), group in data.sort_values("round").groupby(
            ["pattern", "sample_fraction", "strategy", "repetition"]):
        hits = group[group.detected.astype(bool)]
        rounds = float(hits.iloc[0]["round"]) if not hits.empty else float(group.iloc[-1]["round"] + 1)
        cost = float(group.bytes_transferred.mean())
        ttd.append((pattern, sample_fraction, strategy, repetition, rounds, cost))
    table = pd.DataFrame(ttd, columns=["pattern", "sample_fraction", "strategy", "repetition", "rounds", "cost"])
    print("Hypothesis check (observed data only; strategies are compared only when mean costs are within 10%):")
    for (pattern, fraction), group in table.groupby(["pattern", "sample_fraction"]):
        uniform = group[group.strategy == "B1_uniform"]
        qsafe = group[group.strategy == "QSAFE_full"]
        if uniform.empty or qsafe.empty:
            print(f"- {pattern} @ sample fraction {fraction:g}: insufficient B1_uniform/QSAFE_full observations")
            continue
        cost_gap = abs(uniform.cost.mean() - qsafe.cost.mean()) / max(uniform.cost.mean(), 1.0)
        if cost_gap > .10:
            print(f"- {pattern} @ {fraction:g}: inconclusive; average audit costs differ by {cost_gap:.1%}")
            continue
        if min(len(uniform), len(qsafe)) < 30:
            print(f"- {pattern} @ {fraction:g}: preliminary only; {len(uniform)} uniform and {len(qsafe)} "
                  "Q-SAFE repetitions are below the 30-repetition target")
            continue
        med_u, low_u, high_u = bootstrap_median(uniform.rounds.to_numpy(), rng)
        med_q, low_q, high_q = bootstrap_median(qsafe.rounds.to_numpy(), rng)
        if med_q < med_u and high_q < low_u:
            result = "supports faster detection for QSAFE_full in this pattern"
        elif med_q > med_u and low_q > high_u:
            result = "QSAFE_full was slower in this pattern"
        else:
            result = "does not show a clear difference in this pattern"
        print(f"- {pattern} @ {fraction:g}: {result}; uniform median {med_u:g} [{low_u:g}, {high_u:g}], "
              f"Q-SAFE median {med_q:g} [{low_q:g}, {high_q:g}] rounds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, default=Path("analysis/output"))
    parser.add_argument("--seed", type=int, default=20261112)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    data = load(args.csv)
    rng = np.random.default_rng(args.seed)
    plot_detection(data, args.output)
    plot_time_to_detection(data, args.output, rng)
    plot_repair_bytes(data, args.output)
    plot_crypto_share(data, args.output)
    write_overheads(data, args.output)
    print_hypothesis_summary(data, rng)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
