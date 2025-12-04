#!/usr/bin/env python3
"""
Phase 5: Project-level SBOM risk aggregation for Phylum.

This script:
  - Reads the upload index CSV created by upload_sboms_to_phylum.py
      (e.g., phylum_output/phylum_sbom_upload_index.csv)
  - Filters rows for a specific org/group/project
  - For each SBOM/label with a completed analysis:
      * Derives the Phylum Job ID from the phylum_output_json (CLI stdout)
      * Loads the SBOM from disk (CycloneDX)
      * Fetches job policy input from Phylum:
            GET /data/jobs/{jobId}/policy/input
      * Normalizes job input + SBOM into the same structure as Phase 3 extract:
            metadata, sbom.components (with is_direct), summary, packages, raw job input
      * Enriches each package with recommendation_text and fixed_version using:
            GET /data/packages/{purl}
        where:
            - purl is taken from the SBOM component when available (any ecosystem)
            - otherwise we fall back to a Maven-specific PURL builder.

  - Writes:
      * One enriched JSON per label under <output-dir>/labels/
      * One combined project-level JSON that aggregates ALL labels.

This script does NOT generate PDFs; that is done by Phase 4/5 PDF scripts.

Prereqs:
  - pip install requests
  - export PHYLUM_API_KEY="ph0_..."
"""

import argparse
import csv
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests
from urllib.parse import quote


PHYLUM_API_BASE = os.getenv("PHYLUM_API_BASE", "https://api.phylum.io/api/v0")


# ---------- Common helpers (API auth, severity bucketing, etc.) ----------

def get_phylum_api_key() -> str:
    key = os.getenv("PHYLUM_API_KEY")
    if not key:
        raise SystemExit(
            "PHYLUM_API_KEY environment variable is not set.\n"
            "Generate an API key in Phylum UI or via `phylum auth create-token` "
            "and export it as PHYLUM_API_KEY."
        )
    return key


def bucket_severity(issue: Dict[str, Any]) -> str:
    """
    Map Phylum issue severity to CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN.

    Preference:
      - use CVSS.baseSeverity if present (CRITICAL/HIGH/MEDIUM/LOW)
      - else numeric severity 1..4
    """
    cvss = issue.get("cvss")
    if isinstance(cvss, dict) and cvss.get("baseSeverity"):
        sev = str(cvss["baseSeverity"]).upper()
        if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return sev

    s = issue.get("severity")
    if s is None:
        return "UNKNOWN"
    try:
        s_int = int(s)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if s_int >= 4:
        return "CRITICAL"
    if s_int == 3:
        return "HIGH"
    if s_int == 2:
        return "MEDIUM"
    if s_int == 1:
        return "LOW"
    return "UNKNOWN"


# ---------- Phase 3 extract logic (inline) ----------

def load_sbom(sbom_path: Path) -> Dict[str, Any]:
    with sbom_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_dependency_graph(sbom: Dict[str, Any]) -> Dict[str, List[str]]:
    graph: Dict[str, List[str]] = {}
    deps = sbom.get("dependencies", []) or []
    for entry in deps:
        ref = entry.get("ref")
        depends_on = entry.get("dependsOn", []) or []
        if not ref:
            continue
        graph.setdefault(ref, [])
        for child in depends_on:
            if child:
                graph[ref].append(child)
    return graph


def find_root_refs(sbom: Dict[str, Any], graph: Dict[str, List[str]]) -> List[str]:
    roots: List[str] = []
    meta = sbom.get("metadata") or {}
    meta_comp = meta.get("component") or {}
    meta_ref = meta_comp.get("bom-ref") or meta_comp.get("bomRef")
    if meta_ref:
        roots.append(meta_ref)
        return roots

    if not graph:
        return roots

    all_refs = set(graph.keys())
    depends_refs = set()
    for children in graph.values():
        for child in children:
            depends_refs.add(child)

    candidate_roots = sorted(all_refs - depends_refs)
    return candidate_roots


def compute_is_direct_map(sbom: Dict[str, Any]) -> Dict[str, bool]:
    """
    Compute which components are direct dependencies vs transitive using the dependency graph.

    If the graph has no usable parent->child edges (no direct children of roots),
    return an empty map and treat all entries as is_direct=None.
    """
    graph = build_dependency_graph(sbom)
    is_direct_by_ref: Dict[str, bool] = {}

    if not graph:
        return is_direct_by_ref

    roots = find_root_refs(sbom, graph)
    direct_refs = set()
    for r in roots:
        for child in graph.get(r, []):
            direct_refs.add(child)

    if not direct_refs:
        # Graph doesn't give us enough info
        return is_direct_by_ref

    for ref in graph.keys():
        is_direct_by_ref[ref] = ref in direct_refs

    return is_direct_by_ref


def normalize_components_with_direct_flag(sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Normalize CycloneDX components:
      - keep name, version, group, purl, scope, type
      - attach is_direct if we can determine it from the graph
    """
    components = sbom.get("components", []) or []
    is_direct_by_ref = compute_is_direct_map(sbom)

    normalized: List[Dict[str, Any]] = []
    for comp in components:
        ref = comp.get("bom-ref") or comp.get("bomRef")
        normalized.append(
            {
                "bom_ref": ref,
                "name": comp.get("name"),
                "version": comp.get("version"),
                "type": comp.get("type"),
                "purl": comp.get("purl"),
                "group": comp.get("group"),
                "scope": comp.get("scope"),
                "is_direct": is_direct_by_ref.get(ref, None),
            }
        )
    return normalized


def fetch_job_policy_input(job_id: str) -> Dict[str, Any]:
    """
    GET /data/jobs/{jobId}/policy/input
    """
    api_key = get_phylum_api_key()
    url = f"{PHYLUM_API_BASE}/data/jobs/{job_id}/policy/input"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    resp = requests.get(url, headers=headers, timeout=60)
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        raise SystemExit(
            f"Error fetching policy input for job {job_id}: {e}\n"
            f"Status code: {resp.status_code}\nResponse: {resp.text}"
        )
    return resp.json()


def build_component_index(
    sbom_components: List[Dict[str, Any]]
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """
    Build a lookup index for SBOM components keyed by (name, version)
    and, for Maven-style group:name naming, also (group:name, version).

    This index is used both for:
      - attaching is_direct
      - retrieving the PURL for enrichment
    """
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for comp in sbom_components:
        name = comp.get("name")
        grp = comp.get("group")
        ver = comp.get("version")
        if not name or not ver:
            continue
        key1 = (name, str(ver))
        index[key1] = comp
        if grp:
            key2 = (f"{grp}:{name}", str(ver))
            index[key2] = comp
    return index


def summarize_job(job_input: Dict[str, Any],
                  sbom_components: List[Dict[str, Any]]) -> (Dict[str, Any], List[Dict[str, Any]]):
    """
    Normalize Phylum job input + SBOM components into:
      - summary (package_count, issues_total, issues_by_domain, issues_by_severity)
      - packages (per-package issues, counts, is_direct, etc.)
    """
    deps = job_input.get("dependencies", []) or []
    package_count = len(deps)
    issues_total = 0
    issues_by_domain = Counter()
    issues_by_severity = Counter()

    comp_index = build_component_index(sbom_components)
    packages: List[Dict[str, Any]] = []

    for dep in deps:
        pname = dep.get("name")
        ver = dep.get("version")
        eco = dep.get("ecosystem")
        license_str = dep.get("license")
        issues = dep.get("issues") or []

        issues_total += len(issues)

        counts_dom = Counter()
        counts_sev = Counter()
        issues_norm: List[Dict[str, Any]] = []

        for issue in issues:
            dom = issue.get("domain")
            sev_bucket = bucket_severity(issue)

            counts_dom[dom] += 1
            counts_sev[sev_bucket] += 1
            issues_by_domain[dom] += 1
            issues_by_severity[sev_bucket] += 1

            issues_norm.append(
                {
                    "id": issue.get("id"),
                    "domain": dom,
                    "severity_bucket": sev_bucket,
                    "severity_numeric": issue.get("severity"),
                    "tag": issue.get("tag"),
                    "cvss": issue.get("cvss"),
                }
            )

        key = (pname, str(ver))
        comp = comp_index.get(key)
        is_direct = None
        purl = None
        if comp:
            is_direct = comp.get("is_direct")
            purl = comp.get("purl")

        packages.append(
            {
                "name": pname,
                "version": ver,
                "ecosystem": eco,
                "license": license_str,
                "published_date": dep.get("published_date"),
                "is_direct": is_direct,
                "purl": purl,
                "issue_counts_by_domain": dict(counts_dom),
                "issue_counts_by_severity": dict(counts_sev),
                "issues": issues_norm,
            }
        )

    domain_summary = {}
    for k, v in issues_by_domain.items():
        key = k if k is not None else "unknown"
        domain_summary[key] = v

    severity_summary = {}
    for k, v in issues_by_severity.items():
        key = k if k is not None else "UNKNOWN"
        severity_summary[key] = v

    summary = {
        "package_count": package_count,
        "issues_total": issues_total,
        "issues_by_domain": domain_summary,
        "issues_by_severity": severity_summary,
    }

    return summary, packages


# ---------- Phase 3 enrich logic (using PURLs from SBOM) ----------

def build_purl_fallback(ecosystem: str, name: str, version: str) -> str:
    """
    Fallback PURL builder for cases where the SBOM component has no purl.

    Currently only covers Maven; everything else relies on the SBOM's purl.
    """
    ecosystem = (ecosystem or "").lower()
    version = str(version)

    if ecosystem == "maven":
        if ":" not in name:
            group = "unknown"
            artifact = name
        else:
            group, artifact = name.split(":", 1)
        return f"pkg:maven/{group}/{artifact}@{version}"

    return ""


def parse_recommendation_block(description: str) -> Tuple[str, str]:
    """
    Extract recommendation_text and fixed_version from issue.description
    by scanning the '### Recommendation' section.

    Returns (recommendation_text, fixed_version) or (None, None).
    """
    if not description:
        return None, None

    marker = "### Recommendation"
    idx = description.find(marker)
    if idx == -1:
        return None, None

    after = description[idx + len(marker):]
    next_idx = after.find("### ")
    if next_idx != -1:
        rec_block = after[:next_idx]
    else:
        rec_block = after
    rec_block = rec_block.strip()
    if not rec_block:
        return None, None

    fixed_version = None
    patterns = [
        r"Upgrade\s+to\s+version\s+([0-9A-Za-z\.\-\+_]+)",
        r"Upgrade\s+beyond\s+version\s+([0-9A-Za-z\.\-\+_]+)",
        r"Upgrade\s+to\s+([0-9A-Za-z\.\-\+_]+)",
        r"Upgrade\s+beyond\s+([0-9A-Za-z\.\-\+_]+)",
    ]
    for pat in patterns:
        m = re.search(pat, rec_block, flags=re.IGNORECASE)
        if m:
            fixed_version = m.group(1)
            break

    return rec_block, fixed_version


def build_issue_recommendation_map(details: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    From a package detail response, build:
      tag -> { "recommendation_text": ..., "fixed_version": ... }
    """
    rec_map: Dict[str, Dict[str, Any]] = {}
    if not details:
        return rec_map

    issues = details.get("issues") or []
    for issue in issues:
        tag = issue.get("tag")
        desc = issue.get("description")
        if not tag or not desc:
            continue
        rec_text, fixed_version = parse_recommendation_block(desc)
        if rec_text or fixed_version:
            rec_map[tag] = {
                "recommendation_text": rec_text,
                "fixed_version": fixed_version,
            }
    return rec_map


def fetch_package_details_by_purl(raw_purl: str) -> Dict[str, Any]:
    """
    Call GET /data/packages/{package} where {package} is the PURL.

    raw_purl example:
      - "pkg:gem/actionmailer@4.2.5?platform=ruby"
      - "pkg:maven/org.springframework/spring-web@5.2.7.RELEASE"
    """
    api_key = get_phylum_api_key()
    if not raw_purl:
        return {}
    encoded = quote(raw_purl, safe="")
    url = f"{PHYLUM_API_BASE}/data/packages/{encoded}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=60)
    except requests.RequestException as e:
        print(f"[WARN] Request error for {raw_purl}: {e}")
        return {}

    if resp.status_code == 404:
        print(f"[INFO] Package not found in package API: {raw_purl}")
        return {}
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        print(f"[WARN] Package API error for {raw_purl}: {e} (status {resp.status_code})")
        return {}

    return resp.json()


def enrich_packages(packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich each package's issues with recommendation_text and fixed_version
    from the package detail API, using SBOM PURLs when available.
    """
    if not packages:
        return packages

    # Build a mapping: purl -> list of (pkg_index)
    # Also derive a fallback PURL for cases where SBOM has no purl.
    unique_purls: Dict[str, Dict[str, Any]] = {}
    for p in packages:
        eco = p.get("ecosystem") or ""
        name = p.get("name") or ""
        ver = str(p.get("version") or "")
        purl = p.get("purl")

        if not purl:
            # fallback if SBOM didn't have a purl
            purl = build_purl_fallback(eco, name, ver)
            if not purl:
                print(f"[WARN] No PURL for {eco}:{name}@{ver} (SBOM lacked purl and no fallback available)")
                continue

        if purl not in unique_purls:
            unique_purls[purl] = {"ecosystem": eco, "name": name, "version": ver}

    # Fetch details once per unique PURL
    rec_map_by_purl: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for purl, info in unique_purls.items():
        details = fetch_package_details_by_purl(purl)
        rec_map_by_purl[purl] = build_issue_recommendation_map(details)

    # Attach recs to each package issue
    for p in packages:
        eco = p.get("ecosystem") or ""
        name = p.get("name") or ""
        ver = str(p.get("version") or "")
        purl = p.get("purl") or build_purl_fallback(eco, name, ver)
        rec_map = rec_map_by_purl.get(purl, {}) if purl else {}

        for issue in p.get("issues", []):
            tag = issue.get("tag")
            rec_info = rec_map.get(tag)
            if rec_info:
                issue["recommendation_text"] = rec_info.get("recommendation_text")
                issue["fixed_version"] = rec_info.get("fixed_version")
            else:
                issue["recommendation_text"] = None
                issue["fixed_version"] = None

    return packages


# ---------- Utility: extract Job ID from CLI output JSON ----------

JOB_ID_REGEX = re.compile(r"Job ID:\s*([0-9a-fA-F-]+)")


def extract_job_id_from_cli_output(path: Path) -> str:
    """
    Given phylum_output_json produced by upload_sboms_to_phylum.py, extract Job ID from stdout.
    """
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    stdout = data.get("stdout") or ""
    m = JOB_ID_REGEX.search(stdout)
    if not m:
        raise SystemExit(f"Could not find Job ID in {path}")
    return m.group(1)


# ---------- Orchestrator (Phase 5) ----------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Phase 5: Build project-level SBOM risk report for all labels/SBOMs "
            "in a given Phylum org/group/project using the Phase 3 extract+enrich logic."
        )
    )
    parser.add_argument(
        "--index-csv",
        default="phylum_output/phylum_sbom_upload_index.csv",
        help="Path to CSV index created by upload_sboms_to_phylum.py "
             "(default: phylum_output/phylum_sbom_upload_index.csv).",
    )
    parser.add_argument(
        "--org",
        required=True,
        help="Phylum organization name to filter on (e.g., Veracode).",
    )
    parser.add_argument(
        "--group",
        required=True,
        help="Phylum group name to filter on (e.g., andrea-test).",
    )
    parser.add_argument(
        "--project",
        required=True,
        help="Phylum project name to filter on (e.g., andrea-test-project-01dec).",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Base directory for per-label JSON reports (default: reports).",
    )
    parser.add_argument(
        "--project-output",
        default="reports/project_combined.json",
        help="Path to write combined project-level JSON (default: reports/project_combined.json).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    index_path = Path(args.index_csv)
    if not index_path.is_file():
        raise SystemExit(f"Index CSV not found: {index_path}")

    output_dir = Path(args.output_dir)
    labels_dir = output_dir / "labels"
    labels_dir.mkdir(parents=True, exist_ok=True)

    combined_labels: List[Dict[str, Any]] = []

    with index_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Filter rows by org/group/project and completed analyses
    target_rows = []
    for row in rows:
        if row.get("phylum_org") != args.org:
            continue
        if row.get("phylum_group") != args.group:
            continue
        if row.get("phylum_project") != args.project:
            continue
        status = row.get("analysis_status") or ""
        if status not in ("complete_pass", "complete_policy_failure"):
            # Skip pending or genuine errors
            continue
        target_rows.append(row)

    if not target_rows:
        print("[INFO] No completed SBOMs found for the specified org/group/project.")
        return

    print(f"[INFO] Found {len(target_rows)} completed SBOM rows in {index_path}")

    for row in target_rows:
        sbom_path = Path(row["sbom_path"])
        if not sbom_path.is_file():
            print(f"[WARN] SBOM file missing, skipping: {sbom_path}")
            continue

        phylum_output_json = Path(row["phylum_output_json"])
        if not phylum_output_json.is_file():
            print(f"[WARN] CLI output JSON missing, skipping: {phylum_output_json}")
            continue

        label = row.get("phylum_label") or ""
        print(f"[INFO] Processing label={label} sbom={sbom_path}")

        job_id = extract_job_id_from_cli_output(phylum_output_json)

        # Phase 3 extract
        sbom = load_sbom(sbom_path)
        sbom_components = normalize_components_with_direct_flag(sbom)
        job_input = fetch_job_policy_input(job_id)
        summary, packages = summarize_job(job_input, sbom_components)

        # Phase 3 enrich (now PURL-aware across ecosystems)
        packages = enrich_packages(packages)

        # Build label-level report (same shape as Phase 3 enriched)
        now = datetime.now(timezone.utc).isoformat()
        label_report: Dict[str, Any] = {
            "metadata": {
                "org": args.org,
                "group": args.group,
                "project": args.project,
                "label": label,
                "job_id": job_id,
                "generated_at": now,
                "sbom_path": str(sbom_path),
                "sbom_format": sbom.get("bomFormat") or "cyclonedx",
            },
            "sbom": {
                "bomFormat": sbom.get("bomFormat"),
                "specVersion": sbom.get("specVersion"),
                "serialNumber": sbom.get("serialNumber"),
                "components": sbom_components,
            },
            "summary": summary,
            "packages": packages,
            "phylum_job_policy_input_raw": job_input,
        }

        # Write per-label JSON
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label) or "label"
        label_json_path = labels_dir / f"{safe_label}.json"
        with label_json_path.open("w", encoding="utf-8") as lf:
            json.dump(label_report, lf, indent=2)

        print(f"[OK] Label report written: {label_json_path}")
        combined_labels.append(label_report)

    # Build combined project-level JSON
    project_out = Path(args.project_output)
    project_out.parent.mkdir(parents=True, exist_ok=True)

    combined: Dict[str, Any] = {
        "project_metadata": {
            "org": args.org,
            "group": args.group,
            "project": args.project,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "index_csv": str(index_path),
        },
        "labels": combined_labels,
    }

    with project_out.open("w", encoding="utf-8") as pf:
        json.dump(combined, pf, indent=2)

    print(f"[OK] Combined project JSON written: {project_out}")


if __name__ == "__main__":
    main()
