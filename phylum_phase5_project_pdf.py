#!/usr/bin/env python3
"""
Phase 5: Project-level PDF risk report from the combined project JSON.

Input:
  - Project JSON from phylum_phase5_project_report.py, e.g.:
        reports/project_andrea-test-project-01dec.json

Output:
  - Landscape PDF with:
      1. Project-level dashboard
         - Project metadata / counts
         - Project-level Domain Risk Breakdown radar
      2. Phylum Domain Classification Overview
         - Definitions of Issues / Total Issues, Vulnerability, Malicious,
           License, Engineering, Author
      3. Scoring Methodology
         - Fix Priority Score formula and rationale
         - Program Risk Score formula and worked example
      4. Top Risky Components Across the Portfolio
         - Text-wrapped table of top components by Fix Priority Score
         - Program Risk by Label table (no charts) with wrapped label names
      5. One rich section per label:
         - Label summary table
         - Program Risk Score gauge (label-level)
         - Domain Risk Breakdown radar (label-level)
         - Issues by Severity & Domain (label-level, bar with values)
         - Top risky packages for that label
         - Full findings table (all issues, Critical → Low) with Recommendation text
         - Package-level details table
         - Dependency Structure (label-level)
         - Recommendations (label-level)
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    PageBreak,
)


# ---------- Scoring helpers ----------

def severity_order(sev: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return order.get(sev, 4)


def compute_fix_priority_score(pkg: Dict[str, Any]) -> int:
    """
    Fix Priority Score per package:
      Score = 8×Critical + 5×High + 3×Medium + 1×Low
            + 5×Malicious
      +5 bonus if Direct and has ≥1 Critical.
    """
    sev = pkg.get("issue_counts_by_severity", {})
    crit = sev.get("CRITICAL", 0)
    high = sev.get("HIGH", 0)
    med = sev.get("MEDIUM", 0)
    low = sev.get("LOW", 0)

    score = 8 * crit + 5 * high + 3 * med + 1 * low

    dom = pkg.get("issue_counts_by_domain", {})
    mal = dom.get("malicious", 0)
    score += 5 * mal

    if pkg.get("is_direct") is True and crit > 0:
        score += 5

    return score


def compute_program_risk_score(packages: List[Dict[str, Any]]) -> float:
    """
    Label-level Program Risk Score (0–10):

        avg_pkg_score = average(Fix Priority Score per package)
        Program Risk Score (0–10) = min(10, avg_pkg_score)

    Values near 0 indicate low risk; values near 10 indicate high risk.
    """
    if not packages:
        return 0.0
    scores = [compute_fix_priority_score(p) for p in packages]
    avg_pkg_score = sum(scores) / len(scores)
    return max(0.0, min(10.0, avg_pkg_score))


def bool_to_direct_label(val: Any) -> str:
    if val is True:
        return "Direct"
    if val is False:
        return "Transitive"
    return "Unknown"


# ---------- Chart helpers ----------

def make_bar_chart_with_values(data: Dict[str, int], title: str, outfile: Path,
                               figsize=(4.0, 2.4), fontsize_labels=8) -> None:
    """
    Create a bar chart with value labels on each bar, sized so labels sit inside
    the plotting area and do not overlap axes.
    """
    outfile.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=figsize)
    if not data:
        ax.text(0.5, 0.5, "No data", ha="center", va="center")
        ax.set_axis_off()
    else:
        labels = list(data.keys())
        values = [data[k] for k in labels]
        max_val = max(values) if values else 1

        bars = ax.bar(range(len(labels)), values)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=fontsize_labels)
        ax.set_ylabel("Count")
        ax.set_title(title, fontsize=fontsize_labels+1)

        ax.set_ylim(0, max_val * 1.3 if max_val > 0 else 1.0)

        for idx, bar in enumerate(bars):
            v = values[idx]
            y = v + max_val * 0.05 if max_val > 0 else 0.1
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                y,
                str(v),
                ha="center",
                va="bottom",
                fontsize=fontsize_labels,
            )

    fig.subplots_adjust(bottom=0.35, top=0.9, left=0.15, right=0.98)
    fig.savefig(outfile)
    plt.close(fig)


def make_program_risk_chart(score: float, outfile: Path) -> None:
    """Horizontal gauge for Program Risk Score."""
    outfile.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(3.8, 1.8))
    ax.barh([0], [score], height=0.3)
    ax.set_xlim(0, 10)
    ax.set_ylim(-0.5, 0.5)
    ax.set_yticks([])
    ax.set_xticks(range(0, 11, 2))
    ax.set_xlabel("Program Risk Score (0 = low risk, 10 = high risk)")
    ax.set_title("Program Risk Score", fontsize=9)

    ax.text(
        score,
        0.15,
        f"{score:.1f}",
        ha="center",
        va="bottom",
        fontsize=10,
        fontweight="bold",
    )

    fig.subplots_adjust(bottom=0.25, top=0.9, left=0.15, right=0.98)
    fig.savefig(outfile)
    plt.close(fig)


def make_domain_risk_radar(domain_counts: Dict[str, int], outfile: Path) -> None:
    """
    Radar chart for Domain Risk Breakdown.
    """
    outfile.parent.mkdir(parents=True, exist_ok=True)

    labels = ["vulnerability", "malicious", "license", "engineering", "author"]
    raw = [int(domain_counts.get(d, 0)) for d in labels]
    max_val = max(raw) if any(raw) else 1
    norm = [v / max_val for v in raw]

    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False).tolist()
    norm += norm[:1]
    angles += angles[:1]

    fig, ax = plt.subplots(subplot_kw=dict(polar=True), figsize=(3.5, 3.0))

    ax.plot(angles, norm, linewidth=2)
    ax.fill(angles, norm, alpha=0.25)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(
        [f"{lab}\n({val})" for lab, val in zip(labels, raw)],
        fontsize=7,
    )
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["0.25", "0.5", "0.75", "1.0"], fontsize=6)
    ax.set_title("Domain Risk Breakdown (normalized)", fontsize=9)

    fig.subplots_adjust(bottom=0.25, top=0.9, left=0.1, right=0.95)
    fig.savefig(outfile)
    plt.close(fig)


# ---------- Project-level aggregations & tables ----------

def build_project_summary_table(project_metadata: Dict[str, Any],
                                labels: List[Dict[str, Any]]) -> Table:
    total_labels = len(labels)
    total_pkgs = 0
    total_issues = 0
    total_by_domain: Dict[str, int] = {}
    total_by_severity: Dict[str, int] = {}

    for lbl in labels:
        summ = lbl.get("summary", {})
        total_pkgs += summ.get("package_count", 0)
        total_issues += summ.get("issues_total", 0)
        for d, c in (summ.get("issues_by_domain") or {}).items():
            total_by_domain[d] = total_by_domain.get(d, 0) + c
        for s, c in (summ.get("issues_by_severity") or {}).items():
            total_by_severity[s] = total_by_severity.get(s, 0) + c

    rows = [
        ["Project", project_metadata.get("project", "")],
        ["Organization", project_metadata.get("org", "")],
        ["Group", project_metadata.get("group", "")],
        ["Total labels (apps/SCA agents)", total_labels],
        ["Total packages", total_pkgs],
        ["Total issues", total_issues],
        ["Critical issues", total_by_severity.get("CRITICAL", 0)],
        ["High issues", total_by_severity.get("HIGH", 0)],
        ["Medium issues", total_by_severity.get("MEDIUM", 0)],
        ["Low issues", total_by_severity.get("LOW", 0)],
        ["Malicious findings", total_by_domain.get("malicious", 0)],
        ["Vulnerability findings", total_by_domain.get("vulnerability", 0)],
        ["License findings", total_by_domain.get("license", 0)],
        ["Engineering findings", total_by_domain.get("engineering", 0)],
        ["Author findings", total_by_domain.get("author", 0)],
    ]

    table = Table(rows, colWidths=[3.0 * inch, 2.2 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    return table


def build_program_risk_by_label_table(labels: List[Dict[str, Any]], styles) -> Tuple[Table, Dict[str, float]]:
    tiny = ParagraphStyle(
        "LabelTiny",
        parent=styles["Normal"],
        fontSize=7,
        leading=8,
    )

    header = [
        Paragraph("Label", tiny),
        Paragraph("Prog&nbsp;Risk<br/>(0–10)", tiny),
        Paragraph("Total<br/>Issues", tiny),
        Paragraph("Malicious<br/>Findings", tiny),
    ]

    rows = [header]
    risk_map: Dict[str, float] = {}

    for lbl in labels:
        meta = lbl.get("metadata", {})
        summ = lbl.get("summary", {})
        pkgs = lbl.get("packages", [])
        label_name = meta.get("label", "")
        score = compute_program_risk_score(pkgs)
        risk_map[label_name] = score
        total_issues = summ.get("issues_total", 0)
        mal = (summ.get("issues_by_domain") or {}).get("malicious", 0)
        rows.append([
            Paragraph(label_name, tiny),
            f"{score:.2f}",
            total_issues,
            mal,
        ])

    table = Table(rows, colWidths=[4.0 * inch, 1.3 * inch, 1.2 * inch, 1.3 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (1, 1), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    return table, risk_map


def derive_top_risky_packages_across_project(labels: List[Dict[str, Any]],
                                             top_n: int = 15) -> List[Dict[str, Any]]:
    rows = []
    for lbl in labels:
        label_name = lbl.get("metadata", {}).get("label", "")
        for p in lbl.get("packages", []):
            score = compute_fix_priority_score(p)
            sev = p.get("issue_counts_by_severity", {})
            dom = p.get("issue_counts_by_domain", {})
            rows.append({
                "label": label_name,
                "name": p.get("name", ""),
                "version": p.get("version", ""),
                "direct": bool_to_direct_label(p.get("is_direct")),
                "score": score,
                "crit": sev.get("CRITICAL", 0),
                "high": sev.get("HIGH", 0),
                "med": sev.get("MEDIUM", 0),
                "low": sev.get("LOW", 0),
                "mal_cnt": dom.get("malicious", 0),
            })
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:top_n]


def build_top_risky_packages_table(rows: List[Dict[str, Any]], styles) -> Table:
    tiny = ParagraphStyle(
        "TopLabelTiny",
        parent=styles["Normal"],
        fontSize=7,
        leading=8,
    )

    header = [
        Paragraph("Label", tiny),
        Paragraph("Package", tiny),
        Paragraph("Version", tiny),
        Paragraph("Direct?", tiny),
        Paragraph("Fix<br/>Priority", tiny),
        Paragraph("Critical", tiny),
        Paragraph("High", tiny),
        Paragraph("Medium", tiny),
        Paragraph("Low", tiny),
        Paragraph("Malicious?", tiny),
    ]

    table_rows = [header]
    for r in rows:
        table_rows.append([
            Paragraph(r["label"], tiny),
            Paragraph(r["name"], tiny),
            str(r["version"]),
            r["direct"],
            r["score"],
            r["crit"],
            r["high"],
            r["med"],
            r["low"],
            "Yes" if r["mal_cnt"] > 0 else "No",
        ])

    col_widths = [
        2.3 * inch, 2.6 * inch, 0.8 * inch, 0.8 * inch,
        0.8 * inch, 0.6 * inch, 0.6 * inch, 0.6 * inch, 0.6 * inch, 0.9 * inch,
    ]
    table = Table(table_rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (1, 1), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    return table


def flatten_issues_for_label(pkgs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for p in pkgs:
        name = p.get("name", "")
        ver = p.get("version", "")
        direct = bool_to_direct_label(p.get("is_direct"))
        for issue in p.get("issues", []):
            rows.append({
                "severity": issue.get("severity_bucket", "UNKNOWN"),
                "domain": issue.get("domain"),
                "package": name,
                "version": ver,
                "tag": issue.get("tag"),
                "direct": direct,
                "recommendation_text": issue.get("recommendation_text"),
                "fixed_version": issue.get("fixed_version"),
            })

    rows.sort(key=lambda r: (
        severity_order(r["severity"]),
        r["domain"] or "",
        r["package"] or "",
    ))
    return rows


def format_recommendation(issue: Dict[str, Any]) -> str:
    rec = issue.get("recommendation_text")
    fixed = issue.get("fixed_version")
    if rec and fixed:
        return f"{rec} (fixed: {fixed})"
    if rec:
        return rec
    if fixed:
        return f"(fixed: {fixed})"
    return ""


def build_issues_table(issues: List[Dict[str, Any]], styles) -> Table:
    tiny = ParagraphStyle(
        "IssueTiny",
        parent=styles["Normal"],
        fontSize=7,
        leading=8,
    )

    header = [
        "Severity", "Domain", "Package", "Version", "Tag", "Direct?", "Recommendation"
    ]
    rows = [header]

    for i in issues:
        rows.append([
            i["severity"],
            i["domain"],
            i["package"],
            str(i["version"]),
            i["tag"],
            i["direct"],
            Paragraph(format_recommendation(i), tiny),
        ])

    col_widths = [
        0.7 * inch, 1.1 * inch, 2.3 * inch,
        0.8 * inch, 2.8 * inch, 0.8 * inch, 2.8 * inch,
    ]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    return table


def build_package_details_table(packages: List[Dict[str, Any]]) -> Table:
    rows = [["Package", "Version", "Direct?",
             "Fix Priority Score", "Total Issues",
             "Malicious", "Vuln", "License", "Engineering", "Author"]]

    for p in packages:
        dom = p.get("issue_counts_by_domain", {})
        total = sum(dom.values())
        score = compute_fix_priority_score(p)
        rows.append([
            p.get("name", ""),
            str(p.get("version", "")),
            bool_to_direct_label(p.get("is_direct")),
            score,
            total,
            dom.get("malicious", 0),
            dom.get("vulnerability", 0),
            dom.get("license", 0),
            dom.get("engineering", 0),
            dom.get("author", 0),
        ])

    col_widths = [
        3.2 * inch, 1.0 * inch, 1.0 * inch,
        1.1 * inch, 1.0 * inch,
        0.8 * inch, 0.8 * inch, 0.8 * inch, 0.9 * inch, 0.8 * inch,
    ]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    return table


def derive_recommendations(packages: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    immediate_mal = []
    crit_vuln = []
    license_risk = []

    for p in packages:
        name_ver = f"{p.get('name','')}@{p.get('version','')}"
        dom = p.get("issue_counts_by_domain", {})
        sev = p.get("issue_counts_by_severity", {})

        if dom.get("malicious", 0) > 0:
            immediate_mal.append(name_ver)
        if sev.get("CRITICAL", 0) > 0:
            crit_vuln.append(name_ver)
        if dom.get("license", 0) > 0:
            license_risk.append(name_ver)

    def dedupe(seq: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {
        "immediate_malicious": dedupe(immediate_mal),
        "critical_vuln": dedupe(crit_vuln),
        "license_risk": dedupe(license_risk),
    }


# ---------- PDF builder ----------

def build_pdf(project_json: Path, output_pdf: Path) -> None:
    with project_json.open("r", encoding="utf-8") as f:
        proj = json.load(f)

    project_metadata = proj.get("project_metadata", {})
    labels = proj.get("labels", [])

    charts_dir = output_pdf.parent / (output_pdf.stem + "_charts")
    charts_dir.mkdir(parents=True, exist_ok=True)

    # Styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleLarge", parent=styles["Title"], fontSize=20))
    styles.add(ParagraphStyle(name="HeadingSection", parent=styles["Heading2"], fontSize=14))
    styles.add(ParagraphStyle(name="NormalSmall", parent=styles["Normal"], fontSize=9))
    styles.add(ParagraphStyle(name="NormalTiny", parent=styles["Normal"], fontSize=7))

    # Project-level domain counts
    proj_domain_counts: Dict[str, int] = {}
    for lbl in labels:
        summ = lbl.get("summary", {})
        issues_by_domain = summ.get("issues_by_domain") or {}
        for d, c in issues_by_domain.items():
            proj_domain_counts[d] = proj_domain_counts.get(d, 0) + c

    # Project radar chart
    project_radar_chart = charts_dir / "project_domain_risk_radar.png"
    make_domain_risk_radar(proj_domain_counts, project_radar_chart)

    # Tables for risk by label and top components
    program_risk_table, program_risk_map = build_program_risk_by_label_table(labels, styles)
    top_risky_rows = derive_top_risky_packages_across_project(labels, top_n=15)
    top_risky_table = build_top_risky_packages_table(top_risky_rows, styles)

    # PDF
    doc = SimpleDocTemplate(
        str(output_pdf),
        pagesize=landscape(A4),
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )

    elements: List[Any] = []

    # ----- Page 1: Project-level dashboard -----
    elements.append(Paragraph("Phylum Portfolio Risk Report", styles["TitleLarge"]))
    elements.append(Paragraph(
        f"Org: {project_metadata.get('org','')} | Group: {project_metadata.get('group','')} | "
        f"Project: {project_metadata.get('project','')}",
        styles["NormalSmall"],
    ))
    elements.append(Paragraph(
        f"Generated at: {project_metadata.get('generated_at','')}",
        styles["NormalTiny"],
    ))
    elements.append(Spacer(1, 0.10 * inch))

    elements.append(Paragraph("1. Project-level Dashboard", styles["HeadingSection"]))
    elements.append(build_project_summary_table(project_metadata, labels))
    elements.append(Spacer(1, 0.1 * inch))

    elements.append(Paragraph("Project Domain Risk Breakdown", styles["HeadingSection"]))
    elements.append(Image(str(project_radar_chart), width=4.0 * inch, height=3.0 * inch))
    elements.append(Spacer(1, 0.1 * inch))

    elements.append(Paragraph(
        "The Domain Risk Breakdown radar shows how issues are distributed across the Phylum domains "
        "(vulnerability, malicious, license, engineering, author) for this project. Values are normalized "
        "so the most-common domain is plotted at 1.0, with others scaled proportionally.",
        styles["NormalSmall"],
    ))

    elements.append(PageBreak())

    # ----- Page 2: Phylum domain classification overview -----
    elements.append(Paragraph("2. Phylum Domain Classification Overview", styles["HeadingSection"]))
    elements.append(Spacer(1, 0.05 * inch))

    elements.append(Paragraph("<b>Issues / Total Issues</b>", styles["NormalSmall"]))
    elements.append(Paragraph(
        "Total Issues is the number of findings detected across all Phylum domains for a label or for "
        "the entire project. It is the sum of vulnerability, malicious, license, engineering, and author "
        "findings. It does not represent CVEs alone—it represents the full software supply chain risk "
        "surface as assessed by Phylum.",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.08 * inch))

    elements.append(Paragraph("<b>Vulnerability</b>", styles["NormalSmall"]))
    elements.append(Paragraph(
        "Weaknesses in packages or dependencies that could be exploited by an attacker to compromise "
        "confidentiality, integrity, availability, or authorization. These are typically backed by CVE "
        "or GHSA identifiers and mapped to CRITICAL, HIGH, MEDIUM, or LOW using CVSS.",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.05 * inch))

    elements.append(Paragraph("<b>Malicious</b>", styles["NormalSmall"]))
    elements.append(Paragraph(
        "Packages or versions that exhibit clear malicious behavior, such as embedded malware, remote "
        "payload download, credential harvesting, command-and-control callbacks, or compromised maintainer "
        "activity. Malicious findings represent the highest-risk class of issues.",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.05 * inch))

    elements.append(Paragraph("<b>License</b>", styles["NormalSmall"]))
    elements.append(Paragraph(
        "Legal or policy issues relating to package licenses, including incompatible or restrictive "
        "licenses (e.g., GPL contagion risk), missing or ambiguous license files, and conflicts with "
        "organizational open-source governance requirements.",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.05 * inch))

    elements.append(Paragraph("<b>Engineering</b>", styles["NormalSmall"]))
    elements.append(Paragraph(
        "Signals of poor engineering hygiene or structural weaknesses, such as abandoned or severely "
        "outdated packages, unsafe build configurations, and patterns that are predictive of future "
        "vulnerabilities. These issues indicate latent risk in the supply chain.",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.05 * inch))

    elements.append(Paragraph("<b>Author</b>", styles["NormalSmall"]))
    elements.append(Paragraph(
        "Concerns related to publisher or maintainer trustworthiness, including unverifiable authors, "
        "suspicious or disposable accounts, or maintainers associated with known malicious packages. "
        "Author risk helps detect supply-chain trust failures and social engineering in package ecosystems.",
        styles["NormalSmall"],
    ))

    elements.append(PageBreak())

    # ----- Page 3: Scoring methodology -----
    elements.append(Paragraph("3. Scoring Methodology", styles["HeadingSection"]))
    elements.append(Spacer(1, 0.05 * inch))

    elements.append(Paragraph("<b>Fix Priority Score (per package)</b>", styles["NormalSmall"]))
    elements.append(Paragraph(
        "For each package, Fix Priority Score aggregates the severity and nature of findings across "
        "all domains. The formula is:",
        styles["NormalSmall"],
    ))
    elements.append(Paragraph(
        "FixPriority = 8 × (#Critical) + 5 × (#High) + 3 × (#Medium) + 1 × (#Low) "
        "+ 5 × (#malicious-domain findings) + 5 (if the package is Direct and has ≥1 Critical issue)",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph(
        "This weighting emphasizes Critical and High issues, elevates malicious findings, and gives "
        "additional weight to Direct dependencies that the application explicitly relies on.",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.08 * inch))

    elements.append(Paragraph("<b>Program Risk Score (per label)</b>", styles["NormalSmall"]))
    elements.append(Paragraph(
        "For each label (application or SCA agent), we compute Fix Priority Score for every package, "
        "then take the average across all packages and cap it at 10:",
        styles["NormalSmall"],
    ))
    elements.append(Paragraph(
        "avg_pkg_score = average(FixPriority of all packages in the label)<br/>"
        "ProgramRisk = min(10, avg_pkg_score)",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph(
        "Values near 0 indicate low risk (few mild findings). Values near 10 indicate high risk "
        "(many severe or malicious findings).",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.08 * inch))

    elements.append(Paragraph("<b>Worked Example</b>", styles["NormalSmall"]))
    elements.append(Paragraph(
        "Example package with: 1 Critical, 3 High, 2 Medium, 0 Low, 1 Malicious, Direct dependency:",
        styles["NormalSmall"],
    ))
    elements.append(Paragraph(
        "FixPriority = 8×1 + 5×3 + 3×2 + 1×0 + 5×1 + 5<br/>"
        "            = 8 + 15 + 6 + 0 + 5 + 5 = 39",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph(
        "If a label has FixPriority scores [39, 12, 50, 6, 7] across its packages, then:<br/>"
        "avg_pkg_score = (39 + 12 + 50 + 6 + 7) / 5 = 22.8<br/>"
        "ProgramRisk = min(10, 22.8) = 10",
        styles["NormalSmall"],
    ))

    elements.append(PageBreak())

    # ----- Page 4: Top risky components -----
    elements.append(Paragraph("4. Top Risky Components Across the Portfolio", styles["HeadingSection"]))
    if top_risky_rows:
        elements.append(Paragraph(
            "Components ranked by Fix Priority Score across all labels. This highlights cross-portfolio "
            "hotspots where remediation will have the largest risk reduction.",
            styles["NormalSmall"],
        ))
        elements.append(Spacer(1, 0.06 * inch))
        elements.append(top_risky_table)
    else:
        elements.append(Paragraph("No packages with issues were found in this project.", styles["NormalSmall"]))

    elements.append(PageBreak())

    # ----- Page 5: Program Risk by Label -----
    elements.append(Paragraph("5. Program Risk by Label", styles["HeadingSection"]))
    elements.append(Paragraph(
        "This table lists each label, its Program Risk Score (0–10), total issues, and malicious findings. "
        "Program Risk is derived from the average Fix Priority Score of packages in that label.",
        styles["NormalSmall"],
    ))
    elements.append(Spacer(1, 0.06 * inch))
    elements.append(program_risk_table)

    elements.append(PageBreak())

    # ----- Per-label sections -----
    for lbl in labels:
        meta = lbl.get("metadata", {})
        summ = lbl.get("summary", {})
        pkgs = lbl.get("packages", [])

        label_name = meta.get("label", "")
        job_id = meta.get("job_id", "")
        sbom_path = meta.get("sbom_path", "")

        label_charts_dir = charts_dir / "labels"
        label_charts_dir.mkdir(parents=True, exist_ok=True)

        # Label-level charts
        label_program_score = compute_program_risk_score(pkgs)
        label_program_chart = label_charts_dir / f"{label_name}_program_risk.png"
        make_program_risk_chart(label_program_score, label_program_chart)

        label_domain_counts = summ.get("issues_by_domain") or {}
        label_radar_chart = label_charts_dir / f"{label_name}_domain_radar.png"
        make_domain_risk_radar(label_domain_counts, label_radar_chart)

        label_sev_counts = summ.get("issues_by_severity") or {}
        label_sev_chart = label_charts_dir / f"{label_name}_issues_by_severity.png"
        make_bar_chart_with_values(label_sev_counts, "Issues by Severity", label_sev_chart)

        label_dom_chart = label_charts_dir / f"{label_name}_issues_by_domain.png"
        make_bar_chart_with_values(label_domain_counts, "Issues by Domain", label_dom_chart)

        # Header & summary
        elements.append(Paragraph(f"6. Label: {label_name}", styles["HeadingSection"]))
        elements.append(Paragraph(
            f"Job ID: {job_id} | SBOM: {sbom_path}",
            styles["NormalTiny"],
        ))
        elements.append(Spacer(1, 0.06 * inch))

        rows = [
            ["Metric", "Value"],
            ["Packages", summ.get("package_count", 0)],
            ["Total issues", summ.get("issues_total", 0)],
        ]
        sev = summ.get("issues_by_severity") or {}
        dom = summ.get("issues_by_domain") or {}
        rows.append(["Critical issues", sev.get("CRITICAL", 0)])
        rows.append(["High issues", sev.get("HIGH", 0)])
        rows.append(["Medium issues", sev.get("MEDIUM", 0)])
        rows.append(["Low issues", sev.get("LOW", 0)])
        rows.append(["Malicious findings", dom.get("malicious", 0)])
        rows.append(["Vulnerability findings", dom.get("vulnerability", 0)])
        rows.append(["License findings", dom.get("license", 0)])
        rows.append(["Engineering findings", dom.get("engineering", 0)])
        rows.append(["Author findings", dom.get("author", 0)])

        label_summary_table = Table(rows, colWidths=[2.8 * inch, 1.5 * inch])
        label_summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ]))
        elements.append(label_summary_table)
        elements.append(Spacer(1, 0.08 * inch))

        # Label-level Program Risk & Radar
        label_chart_row = [
            Image(str(label_program_chart), width=3.5 * inch, height=2.1 * inch),
            Image(str(label_radar_chart), width=3.5 * inch, height=2.6 * inch),
        ]
        label_charts_table = Table([label_chart_row], colWidths=[3.8 * inch, 3.8 * inch])
        elements.append(label_charts_table)
        elements.append(Spacer(1, 0.06 * inch))

        # Label-level severity/domain bars
        label_chart_row2 = [
            Image(str(label_sev_chart), width=3.5 * inch, height=2.1 * inch),
            Image(str(label_dom_chart), width=3.5 * inch, height=2.1 * inch),
        ]
        label_charts_table2 = Table([label_chart_row2], colWidths=[3.8 * inch, 3.8 * inch])
        elements.append(label_charts_table2)
        elements.append(Spacer(1, 0.06 * inch))

        elements.append(Paragraph(
            "Fix Priority Score and Program Risk Score for this label are computed using the same "
            "formula as described in the Scoring Methodology. High-severity and malicious findings "
            "on Direct dependencies push these scores higher.",
            styles["NormalSmall"],
        ))
        elements.append(Spacer(1, 0.08 * inch))

        # Top risky packages for this label
        label_rows = []
        for p in pkgs:
            score = compute_fix_priority_score(p)
            sev_counts = p.get("issue_counts_by_severity", {})
            dom_counts = p.get("issue_counts_by_domain", {})
            label_rows.append({
                "name": p.get("name", ""),
                "version": p.get("version", ""),
                "direct": bool_to_direct_label(p.get("is_direct")),
                "score": score,
                "crit": sev_counts.get("CRITICAL", 0),
                "high": sev_counts.get("HIGH", 0),
                "med": sev_counts.get("MEDIUM", 0),
                "low": sev_counts.get("LOW", 0),
                "mal_cnt": dom_counts.get("malicious", 0),
            })
        label_rows.sort(key=lambda r: r["score"], reverse=True)
        top_label_rows = label_rows[:10]

        if top_label_rows:
            table_rows = [["Package", "Version", "Direct?",
                           "Fix Priority Score", "Critical", "High", "Medium", "Low", "Malicious?"]]
            for r in top_label_rows:
                table_rows.append([
                    r["name"],
                    str(r["version"]),
                    r["direct"],
                    r["score"],
                    r["crit"],
                    r["high"],
                    r["med"],
                    r["low"],
                    "Yes" if r["mal_cnt"] > 0 else "No",
                ])
            col_widths = [
                3.0 * inch, 1.0 * inch, 1.0 * inch,
                1.0 * inch, 0.7 * inch, 0.7 * inch,
                0.7 * inch, 0.7 * inch, 1.0 * inch,
            ]
            label_pkg_table = Table(table_rows, colWidths=col_widths, repeatRows=1)
            label_pkg_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]))
            elements.append(Paragraph("Top Risky Packages for this Label", styles["HeadingSection"]))
            elements.append(label_pkg_table)
        else:
            elements.append(Paragraph("No risky packages found for this label.", styles["NormalSmall"]))

        elements.append(Spacer(1, 0.08 * inch))

        # Full findings
        elements.append(Paragraph("Full Findings (Critical → Low) for this Label", styles["HeadingSection"]))
        label_issues = flatten_issues_for_label(pkgs)
        elements.append(build_issues_table(label_issues, styles))
        elements.append(PageBreak())

        # Package-level details
        elements.append(Paragraph("Package-Level Details for this Label", styles["HeadingSection"]))
        elements.append(build_package_details_table(pkgs))
        elements.append(PageBreak())

        # Dependency structure
        elements.append(Paragraph("Dependency Structure for this Label", styles["HeadingSection"]))
        direct_count = sum(1 for p in pkgs if p.get("is_direct") is True)
        trans_count = sum(1 for p in pkgs if p.get("is_direct") is False)
        unknown_count = sum(1 for p in pkgs if p.get("is_direct") is None)
        if direct_count == 0 and trans_count == 0:
            elements.append(Paragraph(
                "This SBOM does not contain enough dependency edge information to distinguish "
                "direct vs transitive dependencies. All components are marked as Unknown.",
                styles["NormalSmall"],
            ))
        else:
            elements.append(Paragraph(
                f"Direct dependencies: {direct_count} | Transitive dependencies: {trans_count} | "
                f"Unknown classification: {unknown_count}",
                styles["NormalSmall"],
            ))
        elements.append(PageBreak())

        # Recommendations
        elements.append(Paragraph("Recommendations for this Label", styles["HeadingSection"]))
        recs = derive_recommendations(pkgs)

        elements.append(Paragraph("<b>Immediate Attention – Potential Malicious Packages</b>", styles["NormalSmall"]))
        if not recs["immediate_malicious"]:
            elements.append(Paragraph("No packages with malicious-domain findings were detected.", styles["NormalTiny"]))
        else:
            for name_ver in recs["immediate_malicious"]:
                elements.append(Paragraph(
                    f"- {name_ver}: flagged with malicious-domain issues. Review usage, investigate integrity, "
                    "and consider replacement or removal.",
                    styles["NormalTiny"],
                ))
        elements.append(Spacer(1, 0.06 * inch))

        elements.append(Paragraph("<b>High Priority – Critical Vulnerabilities</b>", styles["NormalSmall"]))
        if not recs["critical_vuln"]:
            elements.append(Paragraph("No packages with critical severity vulnerabilities.", styles["NormalTiny"]))
        else:
            for name_ver in recs["critical_vuln"]:
                elements.append(Paragraph(
                    f"- {name_ver}: contains at least one critical vulnerability. "
                    "Prioritize upgrade or mitigation (e.g., configuration, isolation).",
                    styles["NormalTiny"],
                ))
        elements.append(Spacer(1, 0.06 * inch))

        elements.append(Paragraph("<b>License Risk – Review for Compliance</b>", styles["NormalSmall"]))
        if not recs["license_risk"]:
            elements.append(Paragraph("No license findings were detected.", styles["NormalTiny"]))
        else:
            for name_ver in recs["license_risk"]:
                elements.append(Paragraph(
                    f"- {name_ver}: license issues detected. Review license terms against organizational "
                    "policy and consider alternatives.",
                    styles["NormalTiny"],
                ))
        elements.append(PageBreak())

    doc.build(elements)


# ---------- CLI ----------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Phase 5: Generate a project-level PDF risk report from a combined project JSON."
    )
    parser.add_argument(
        "--project-json",
        required=True,
        help="Path to project JSON (output of phylum_phase5_project_report.py).",
    )
    parser.add_argument(
        "--output-pdf",
        required=True,
        help="Path to output PDF file.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_json = Path(args.project_json)
    output_pdf = Path(args.output_pdf)

    if not project_json.is_file():
        raise SystemExit(f"Project JSON does not exist: {project_json}")

    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    build_pdf(project_json, output_pdf)
    print(f"✅ Project-level PDF report written to: {output_pdf}")


if __name__ == "__main__":
    main()
