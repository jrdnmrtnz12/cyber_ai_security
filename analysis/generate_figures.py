"""
Generate publication-quality figures from the security findings results matrix.

Usage (from project root):
    python3 analysis/generate_figures.py

Outputs four PNG files to analysis/figures/:
    bandit_heatmap.png       — Bandit-detected findings by group × task
    manual_heatmap.png       — Manual-review findings by group × task
    severity_stacked_bar.png — Total findings stacked by severity per group
    bandit_vs_manual_gap.png — Side-by-side Bandit vs Manual count per group

Requires: pandas, matplotlib, seaborn
    pip install pandas matplotlib seaborn
"""

import os
import sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns
import numpy as np

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
CSV_PATH     = os.path.join(SCRIPT_DIR, "results_matrix.csv")
FIGURES_DIR  = os.path.join(SCRIPT_DIR, "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
df = pd.read_csv(CSV_PATH)
df.columns = df.columns.str.strip()

# Canonical ordering
LLM_ORDER   = ["chatgpt", "gemini", "claude_code"]
STYLE_ORDER = ["naive", "secure"]
TASK_ORDER  = [
    "task1_registration",
    "task2_password_storage",
    "task3_login_endpoint",
    "task4_session_management",
    "task5_password_reset",
]
SEV_ORDER   = ["Critical", "High", "Medium", "Low"]

# Build display labels
TASK_LABELS = {
    "task1_registration":      "Task 1\nRegistration",
    "task2_password_storage":  "Task 2\nPwd Storage",
    "task3_login_endpoint":    "Task 3\nLogin",
    "task4_session_management":"Task 4\nSession Mgmt",
    "task5_password_reset":    "Task 5\nPwd Reset",
}
GROUP_LABELS = {
    "chatgpt_naive":      "ChatGPT\nNaive",
    "chatgpt_secure":     "ChatGPT\nSecure",
    "gemini_naive":       "Gemini\nNaive",
    "gemini_secure":      "Gemini\nSecure",
    "claude_code_naive":  "Claude Code\nNaive",
    "claude_code_secure": "Claude Code\nSecure",
}
GROUP_ORDER = [f"{llm}_{style}" for llm in LLM_ORDER for style in STYLE_ORDER]

# Add group column
df["group"] = df["LLM"] + "_" + df["Prompt_Style"]

# "Bandit + Manual" rows are counted for both methods; split them now.
# (In this dataset Tool_Detected is only 'Bandit' or 'Manual', but guard
# against future additions.)
bandit_mask = df["Tool_Detected"].str.contains("Bandit", case=False, na=False)
manual_mask = df["Tool_Detected"].str.contains("Manual", case=False, na=False)

df_bandit = df[bandit_mask].copy()
df_manual = df[manual_mask].copy()

# Colorblind-safe palette
BLUE   = "#4477AA"
ORANGE = "#EE7733"

# ---------------------------------------------------------------------------
# Shared style
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "font.family":     "DejaVu Sans",
    "font.size":       11,
    "axes.titlesize":  13,
    "axes.titleweight":"bold",
    "axes.labelsize":  11,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.dpi":      300,
})

FIG_W, FIG_H = 10, 6


# ---------------------------------------------------------------------------
# Helper: build heatmap pivot
# ---------------------------------------------------------------------------
def build_heatmap_pivot(source_df):
    """Return a (group × task) pivot table of finding counts."""
    pivot = (
        source_df
        .groupby(["group", "Task"])
        .size()
        .reset_index(name="count")
        .pivot(index="group", columns="Task", values="count")
        .reindex(index=GROUP_ORDER, columns=TASK_ORDER)
        .fillna(0)
        .astype(int)
    )
    pivot.index   = [GROUP_LABELS[g] for g in GROUP_ORDER]
    pivot.columns = [TASK_LABELS[t]  for t in TASK_ORDER]
    return pivot


# ---------------------------------------------------------------------------
# Figure 1 — Bandit heatmap
# ---------------------------------------------------------------------------
def fig_bandit_heatmap(vmax_override=None):
    pivot = build_heatmap_pivot(df_bandit)
    vmax  = vmax_override if vmax_override is not None else pivot.values.max()

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    sns.heatmap(
        pivot,
        ax=ax,
        annot=True,
        fmt="d",
        cmap="YlOrRd",
        linewidths=0.5,
        linecolor="white",
        vmin=0,
        vmax=max(vmax, 1),
        cbar_kws={"label": "Finding count", "shrink": 0.8},
    )
    ax.set_title("Bandit Static Analysis Findings by LLM, Prompt Style, and Task")
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.tick_params(axis="x", rotation=0)
    ax.tick_params(axis="y", rotation=0)
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "bandit_heatmap.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return out, pivot.values.max()


# ---------------------------------------------------------------------------
# Figure 2 — Manual heatmap
# ---------------------------------------------------------------------------
def fig_manual_heatmap(vmax_override=None):
    pivot = build_heatmap_pivot(df_manual)
    vmax  = vmax_override if vmax_override is not None else pivot.values.max()

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    sns.heatmap(
        pivot,
        ax=ax,
        annot=True,
        fmt="d",
        cmap="YlOrRd",
        linewidths=0.5,
        linecolor="white",
        vmin=0,
        vmax=max(vmax, 1),
        cbar_kws={"label": "Finding count", "shrink": 0.8},
    )
    ax.set_title("Manual Code Review Findings by LLM, Prompt Style, and Task")
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.tick_params(axis="x", rotation=0)
    ax.tick_params(axis="y", rotation=0)
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "manual_heatmap.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return out, pivot.values.max()


# ---------------------------------------------------------------------------
# Figure 3 — Severity stacked bar
# ---------------------------------------------------------------------------
def fig_severity_stacked_bar():
    # Colorblind-safe, prints distinctly in grayscale (viridis-derived)
    SEV_COLORS = {
        "Critical": "#440154",  # dark purple
        "High":     "#31688E",  # blue
        "Medium":   "#35B779",  # green
        "Low":      "#FDE725",  # yellow
    }

    counts = (
        df.groupby(["group", "Severity"])
        .size()
        .reset_index(name="count")
        .pivot(index="group", columns="Severity", values="count")
        .reindex(index=GROUP_ORDER, columns=SEV_ORDER)
        .fillna(0)
        .astype(int)
    )
    counts.index = [GROUP_LABELS[g] for g in GROUP_ORDER]

    x      = np.arange(len(counts))
    width  = 0.55
    totals = counts.sum(axis=1).values

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    bottoms = np.zeros(len(counts))

    for sev in SEV_ORDER:
        vals = counts[sev].values
        ax.bar(
            x, vals,
            width=width,
            bottom=bottoms,
            label=sev,
            color=SEV_COLORS[sev],
            edgecolor="white",
            linewidth=0.6,
        )
        bottoms += vals

    # Total labels on top of each bar
    for i, total in enumerate(totals):
        ax.text(
            x[i], total + 0.3,
            str(int(total)),
            ha="center", va="bottom",
            fontsize=10, fontweight="bold",
        )

    ax.set_xticks(x)
    ax.set_xticklabels([GROUP_LABELS[g] for g in GROUP_ORDER], ha="center")
    ax.set_ylabel("Number of Findings")
    ax.set_title("Findings by Severity, LLM, and Prompt Style")
    ax.legend(
        title="Severity",
        loc="upper right",
        framealpha=0.9,
        fontsize=9,
    )
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.set_ylim(0, totals.max() * 1.15)
    sns.despine(ax=ax)

    # Vertical separator lines between LLM groups
    for sep in [1.5, 3.5]:
        ax.axvline(sep, color="grey", linewidth=0.8, linestyle="--", alpha=0.5)

    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "severity_stacked_bar.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Figure 4 — Bandit vs Manual grouped bar
# ---------------------------------------------------------------------------
def fig_bandit_vs_manual():
    bandit_counts = (
        df_bandit.groupby("group").size().reindex(GROUP_ORDER, fill_value=0)
    )
    manual_counts = (
        df_manual.groupby("group").size().reindex(GROUP_ORDER, fill_value=0)
    )

    x      = np.arange(len(GROUP_ORDER))
    width  = 0.35

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))

    bars_b = ax.bar(
        x - width / 2,
        bandit_counts.values,
        width=width,
        label="Bandit (static analysis)",
        color=BLUE,
        edgecolor="white",
        linewidth=0.6,
    )
    bars_m = ax.bar(
        x + width / 2,
        manual_counts.values,
        width=width,
        label="Manual review",
        color=ORANGE,
        edgecolor="white",
        linewidth=0.6,
    )

    # Value labels on each bar
    for bar in (*bars_b, *bars_m):
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                h + 0.15,
                str(int(h)),
                ha="center", va="bottom",
                fontsize=9,
            )

    ax.set_xticks(x)
    ax.set_xticklabels([GROUP_LABELS[g] for g in GROUP_ORDER], ha="center")
    ax.set_ylabel("Number of Findings")
    ax.set_title("Bandit vs Manual Review: Findings Detected by Method")
    ax.legend(framealpha=0.9, fontsize=10)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    max_val = max(bandit_counts.max(), manual_counts.max())
    ax.set_ylim(0, max_val * 1.2)
    sns.despine(ax=ax)

    # Vertical separator lines between LLM groups
    for sep in [1.5, 3.5]:
        ax.axvline(sep, color="grey", linewidth=0.8, linestyle="--", alpha=0.5)

    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "bandit_vs_manual_gap.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Stdout summary table
# ---------------------------------------------------------------------------
CONSOLE_LABELS = {g: v.replace("\n", " ") for g, v in GROUP_LABELS.items()}


def print_summary():
    print("\n=== Findings parsed from results_matrix.csv ===\n")

    summary = (
        df.groupby(["group", "Tool_Detected"])
        .size()
        .reset_index(name="count")
        .pivot(index="group", columns="Tool_Detected", values="count")
        .reindex(index=GROUP_ORDER)
        .fillna(0)
        .astype(int)
    )
    summary.index = [CONSOLE_LABELS[g] for g in GROUP_ORDER]
    summary["Total"] = summary.sum(axis=1)

    # Column widths
    col_w = 14
    label_w = 20
    cols = list(summary.columns)
    header = f"{'Group':<{label_w}}" + "".join(f"{c:>{col_w}}" for c in cols)
    print(header)
    print("-" * (label_w + col_w * len(cols)))
    for group, row in summary.iterrows():
        line = f"{group:<{label_w}}" + "".join(f"{int(row[c]):>{col_w}}" for c in cols)
        print(line)
    print("-" * (label_w + col_w * len(cols)))
    totals_row = summary.sum()
    print(
        f"{'TOTAL':<{label_w}}"
        + "".join(f"{int(totals_row[c]):>{col_w}}" for c in cols)
    )
    print(f"\nTotal rows in CSV: {len(df)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Reading:", CSV_PATH)
    print(f"Loaded {len(df)} findings\n")

    # Generate heatmaps — use a shared vmax so they are directly comparable.
    # First pass: get both raw maxima.
    b_pivot = build_heatmap_pivot(df_bandit)
    m_pivot = build_heatmap_pivot(df_manual)
    shared_max = max(b_pivot.values.max(), m_pivot.values.max())

    if shared_max <= m_pivot.values.max() * 2:
        # Manual counts are within 2× of Bandit — shared scale is readable
        out1, _ = fig_bandit_heatmap(vmax_override=shared_max)
        out2, _ = fig_manual_heatmap(vmax_override=shared_max)
        print(f"[Fig 1 & 2] Using shared colour scale (vmax={shared_max})")
    else:
        # Manual counts blow out the Bandit scale; use independent scales
        out1, bmax = fig_bandit_heatmap()
        out2, mmax = fig_manual_heatmap()
        print(f"[Fig 1] Independent scale (vmax={bmax})")
        print(f"[Fig 2] Independent scale (vmax={mmax})")

    out3 = fig_severity_stacked_bar()
    out4 = fig_bandit_vs_manual()

    print_summary()

    print("\n=== Generated 4 figures in analysis/figures/ ===")
    for path in [out1, out2, out3, out4]:
        print(" ", os.path.relpath(path, PROJECT_ROOT))
