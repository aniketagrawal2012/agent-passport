"""
Generates 4 IEEEtran publication-grade figures (PDF & PNG, 300 DPI)
from the empirical benchmark results in datasets/benchmark_summary.json.
"""

import json
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

os.makedirs("plots", exist_ok=True)
os.environ["MPLCONFIGDIR"] = os.path.abspath(".matplotlib_cache")
os.makedirs(".matplotlib_cache", exist_ok=True)

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
    "font.size": 9,
    "axes.titlesize": 10,
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "figure.dpi": 300,
})


def generate_all_plots() -> None:
    with open("datasets/benchmark_summary.json") as f:
        summary = json.load(f)

    # ------------------------------------------------------------------
    # Figure 1: Per-Hop Delegation & Verification Latency Scaling (1 to 4 Hops)
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(6.2, 3.4))
    hops = [1, 2, 3, 4]
    arch_labels = [
        ("Centralized_RFC8693_IdP", "RFC 8693 IdP Token Exchange (Per-Hop Round-Trip)", "#EA4335", "s", "--"),
        ("Client_Callback_Auth", "Client before_tool_callback Forwarding (Teradata Baseline)", "#FBBC04", "^", "-."),
        ("Raw_Bearer_Passthrough", "Unattenuated Bearer Passthrough (Resort Wristband)", "#9AA0A6", "d", ":"),
        ("Agent_Passport_Ours", "Agent-Passport (Chained HMAC + AS-Path + Zeroize)", "#1A73E8", "o", "-"),
    ]
    for key, label, color, marker, ls in arch_labels:
        y = [summary[key]["latency_by_hop_ms"][str(h)] for h in hops]
        ax.plot(hops, y, label=label, color=color, marker=marker, linestyle=ls, linewidth=2.0, markersize=6)

    ax.set_yscale("log")
    ax.set_xticks(hops)
    ax.set_xticklabels([f"{h} Hop{'s' if h > 1 else ''}" for h in hops])
    ax.set_xlabel("Cross-Domain A2A / MCP Delegation Chain Depth")
    ax.set_ylabel("End-to-End Auth & Verification Latency (ms, log scale)")
    ax.set_title("Multi-Hop Delegation Latency Scaling Across Agent Topologies (N = 1,200)")
    ax.grid(True, which="both", linestyle=":", alpha=0.6)
    ax.legend(loc="upper left", frameon=True)
    fig.tight_layout()
    fig.savefig("plots/fig1_hop_latency_scaling.pdf")
    fig.savefig("plots/fig1_hop_latency_scaling.png", dpi=300)
    plt.close(fig)

    # ------------------------------------------------------------------
    # Figure 2: 5-Axis Security, Loop Prevention & Governance Compliance Matrix
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(6.8, 3.6))
    metrics = [
        "Cross-Hop Escalation\nBlock Rate (%)",
        "CMP Draft-Lock\nEnforcement (%)",
        "EU AI Act Art. 14\nHITL Compliance (%)",
        "BGP AS-Path Loop\nPrevention (%)",
        "Turn-Scoped RAM\nZeroization (%)",
    ]
    x = np.arange(len(metrics))
    width = 0.18

    compare_archs = [
        ("Static_SA_Impersonation", "Static SA Baseline", "#DADCE0"),
        ("Raw_Bearer_Passthrough", "Raw Bearer Passthrough", "#F28B82"),
        ("Centralized_RFC8693_IdP", "RFC 8693 IdP Exchange", "#FDD663"),
        ("Agent_Passport_Ours", "Agent-Passport (Ours)", "#1A73E8"),
    ]
    for idx, (key, label, color) in enumerate(compare_archs):
        d = summary[key]
        vals = [
            d["escalation_block_rate_pct"],
            d["draft_lock_enforcement_pct"],
            d["hitl_art14_compliance_pct"],
            d["loop_prevention_rate_pct"],
            d["ram_zeroization_rate_pct"],
        ]
        offset = (idx - 1.5) * width
        bars = ax.bar(x + offset, vals, width, label=label, color=color, edgecolor="#202124", linewidth=0.6)
        if key == "Agent_Passport_Ours":
            for b in bars:
                ax.text(
                    b.get_x() + b.get_width() / 2.0,
                    b.get_height() + 1.5,
                    f"{b.get_height():.0f}%",
                    ha="center",
                    va="bottom",
                    fontsize=7,
                    fontweight="bold",
                    color="#1A73E8",
                )

    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Enforcement / Compliance Rate (%)")
    ax.set_title("Security & Governance Invariant Enforcement Across 1,200 Enterprise Traces")
    ax.grid(True, axis="y", linestyle=":", alpha=0.6)
    ax.legend(loc="upper center", ncol=4, frameon=True)
    fig.tight_layout()
    fig.savefig("plots/fig2_security_governance_matrix.pdf")
    fig.savefig("plots/fig2_security_governance_matrix.png", dpi=300)
    plt.close(fig)

    # ------------------------------------------------------------------
    # Figure 3: Tail Latency Distribution (p50, p95, p99) & Throughput Tradeoff
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(6.0, 3.2))
    arch_keys = ["Agent_Passport_Ours", "Raw_Bearer_Passthrough", "Static_SA_Impersonation", "Client_Callback_Auth", "Centralized_RFC8693_IdP"]
    arch_names_clean = [
        "Agent-Passport\n(Ours)",
        "Raw Bearer\nPassthrough",
        "Static SA\nImpersonation",
        "Client Callback\n(before_tool)",
        "RFC 8693\nIdP Exchange",
    ]
    p50s = [summary[k]["p50_latency_ms"] for k in arch_keys]
    p95s = [summary[k]["p95_latency_ms"] for k in arch_keys]
    p99s = [summary[k]["p99_latency_ms"] for k in arch_keys]

    x3 = np.arange(len(arch_keys))
    w3 = 0.25
    ax.bar(x3 - w3, p50s, w3, label="p50 Median (ms)", color="#34A853", edgecolor="#202124", linewidth=0.6)
    ax.bar(x3, p95s, w3, label="p95 Tail (ms)", color="#FBBC04", edgecolor="#202124", linewidth=0.6)
    ax.bar(x3 + w3, p99s, w3, label="p99 Tail (ms)", color="#EA4335", edgecolor="#202124", linewidth=0.6)

    ax.set_yscale("log")
    ax.set_xticks(x3)
    ax.set_xticklabels(arch_names_clean)
    ax.set_ylabel("Latency (ms, log scale)")
    ax.set_title("Percentile Latency Distribution (p50 / p95 / p99) Across All 6 Strata")
    ax.grid(True, which="both", axis="y", linestyle=":", alpha=0.6)
    ax.legend(loc="upper left", frameon=True)
    fig.tight_layout()
    fig.savefig("plots/fig3_tail_latency_percentiles.pdf")
    fig.savefig("plots/fig3_tail_latency_percentiles.png", dpi=300)
    plt.close(fig)

    print("Successfully generated all publication figures in plots/.")


if __name__ == "__main__":
    generate_all_plots()
