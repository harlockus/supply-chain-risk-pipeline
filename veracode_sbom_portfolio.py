#!/usr/bin/env python3
"""
Veracode SBOM export tool - Portfolio (US region)

- Enumerate ALL application profiles (AppSec) and ALL SCA agent-based projects.
- Fetch CycloneDX (or SPDX) SBOMs via SBOM REST API.
- Export per target:
  - raw JSON SBOM
  - normalized JSON (flattened components)
  - CSV (flattened components)
- Produce master index CSVs for discovery:
  - sbom_index_apps.csv
  - sbom_index_agents.csv
- Show professional, concise terminal summaries with optional spinners & tables.

Requires:
  pip install requests veracode-api-signing
Optional (recommended) for visuals:
  pip install rich

Veracode credentials:
  - ~/.veracode/credentials
    or
  - VERACODE_API_KEY_ID / VERACODE_API_KEY_SECRET env vars
"""

import argparse
import csv
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

# Optional rich-based visuals
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    RICH_AVAILABLE = True
    console = Console()
except ImportError:  # pragma: no cover
    RICH_AVAILABLE = False
    console = None

DEFAULT_BASE_URL = os.getenv("VERACODE_API_BASE_URL", "https://api.veracode.com")


def slugify(text: Optional[str]) -> str:
    if not text:
        return ""
    text = text.strip()
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    return text[:80]  # keep filenames sane


class VeracodeSbomClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = RequestsAuthPluginVeracodeHMAC()
        self.timeout = timeout

    # ------------ Application profiles (AppSec) ------------

    def iter_applications(self, page_size: int = 50) -> Iterable[Dict[str, Any]]:
        """
        Iterate ALL application profiles.

        Uses paged HAL endpoint:
          GET /appsec/v1/applications?page=0&size=50
        """
        page = 0
        while True:
            params = {"page": page, "size": page_size}
            url = f"{self.base_url}/appsec/v1/applications"
            resp = self.session.get(url, params=params, timeout=self.timeout)
            self._raise_for_status(resp, f"list applications (page {page})")

            data = resp.json()
            embedded = data.get("_embedded", {})
            apps = embedded.get("applications", []) or []

            if not apps:
                break

            for app in apps:
                yield app

            page_info = data.get("page", {})
            total_pages = page_info.get("totalPages")
            number = page_info.get("number")

            if total_pages is not None and number is not None:
                if number >= total_pages - 1:
                    break
            else:
                if len(apps) < page_size:
                    break

            page += 1

    def get_application_sbom(
        self,
        application_guid: str,
        format_slug: str = "cyclonedx",
        linked: bool = False,
        include_vulnerabilities: bool = True,
    ) -> Dict[str, Any]:
        """
        GET /srcclr/sbom/v1/targets/{applicationGuid}/{format}?type=application[&linked=true][&vulnerability=false]
        """
        url = f"{self.base_url}/srcclr/sbom/v1/targets/{application_guid}/{format_slug}"
        params: Dict[str, str] = {"type": "application"}
        if linked:
            params["linked"] = "true"
        if not include_vulnerabilities:
            params["vulnerability"] = "false"

        resp = self.session.get(url, params=params, timeout=self.timeout)
        self._raise_for_status(resp, f"fetch application SBOM {application_guid}")
        return resp.json()

    # ------------ Agent-based workspaces & projects ------------

    def iter_workspaces(self, page_size: int = 50) -> Iterable[Dict[str, Any]]:
        """
        Iterate ALL SCA workspaces.

        Endpoint:
          GET /srcclr/v3/workspaces?page=0&size=50

        Supports both plain-list and HAL-style responses.
        """
        page = 0
        while True:
            params = {"page": page, "size": page_size}
            url = f"{self.base_url}/srcclr/v3/workspaces"
            resp = self.session.get(url, params=params, timeout=self.timeout)
            self._raise_for_status(resp, f"list workspaces (page {page})")
            data = resp.json()

            if isinstance(data, list):
                workspaces = data
                for ws in workspaces:
                    yield ws
                if len(workspaces) < page_size:
                    break
                page += 1
                continue

            embedded = data.get("_embedded", {})
            workspaces = (
                data.get("workspaces")
                or embedded.get("workspaces")
                or embedded.get("workspaceList", [])
                or []
            )

            if not workspaces:
                break

            for ws in workspaces:
                yield ws

            page_info = data.get("page", {})
            total_pages = page_info.get("totalPages")
            number = page_info.get("number")

            if total_pages is not None and number is not None:
                if number >= total_pages - 1:
                    break
            else:
                if len(workspaces) < page_size:
                    break

            page += 1

    def iter_projects_for_workspace(
        self, workspace_guid: str, page_size: int = 50
    ) -> Iterable[Dict[str, Any]]:
        """
        Iterate ALL projects in a workspace.

        Endpoint:
          GET /srcclr/v3/workspaces/{workspaceGuid}/projects?page=0&size=50
        """
        page = 0
        while True:
            params = {"page": page, "size": page_size}
            url = f"{self.base_url}/srcclr/v3/workspaces/{workspace_guid}/projects"
            resp = self.session.get(url, params=params, timeout=self.timeout)
            self._raise_for_status(
                resp, f"list projects for workspace {workspace_guid} (page {page})"
            )
            data = resp.json()

            if isinstance(data, list):
                projects = data
                for prj in projects:
                    yield prj
                if len(projects) < page_size:
                    break
                page += 1
                continue

            embedded = data.get("_embedded", {})
            projects = (
                data.get("projects")
                or embedded.get("projects")
                or embedded.get("projectList", [])
                or []
            )

            if not projects:
                break

            for prj in projects:
                yield prj

            page_info = data.get("page", {})
            total_pages = page_info.get("totalPages")
            number = page_info.get("number")

            if total_pages is not None and number is not None:
                if number >= total_pages - 1:
                    break
            else:
                if len(projects) < page_size:
                    break

            page += 1

    def get_agent_project_sbom(
        self,
        project_guid: str,
        format_slug: str = "cyclonedx",
        include_vulnerabilities: bool = True,
    ) -> Dict[str, Any]:
        """
        GET /srcclr/sbom/v1/targets/{projectGuid}/{format}?type=agent[&vulnerability=false]
        """
        url = f"{self.base_url}/srcclr/sbom/v1/targets/{project_guid}/{format_slug}"
        params: Dict[str, str] = {"type": "agent"}
        if not include_vulnerabilities:
            params["vulnerability"] = "false"

        resp = self.session.get(url, params=params, timeout=self.timeout)
        self._raise_for_status(resp, f"fetch agent project SBOM {project_guid}")
        return resp.json()

    # ------------ Internal helper ------------

    @staticmethod
    def _raise_for_status(resp: requests.Response, context: str) -> None:
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            msg = f"HTTP error during {context}: {exc} | Response text: {resp.text}"
            raise RuntimeError(msg) from exc


# ------------ CycloneDX normalization ------------

def normalize_cyclonedx_components(bom: Dict[str, Any]) -> List[Dict[str, Any]]:
    components = bom.get("components", []) or []
    vulnerabilities = bom.get("vulnerabilities", []) or []

    vuln_index: Dict[str, List[Dict[str, Any]]] = {}
    for vuln in vulnerabilities:
        affects = vuln.get("affects", []) or []
        for aff in affects:
            ref = aff.get("ref")
            if ref:
                vuln_index.setdefault(ref, []).append(vuln)

    rows: List[Dict[str, Any]] = []

    for comp in components:
        bom_ref = comp.get("bom-ref") or comp.get("bomRef")
        licenses = comp.get("licenses", []) or []
        license_ids: List[str] = []
        for l in licenses:
            lic = l.get("license") or {}
            name = lic.get("name")
            spdx_id = lic.get("id")
            if spdx_id:
                license_ids.append(spdx_id)
            elif name:
                license_ids.append(name)

        supplier = comp.get("supplier") or {}
        supplier_name = supplier.get("name")

        comp_vulns = vuln_index.get(bom_ref, []) if bom_ref else []
        vuln_ids: List[str] = []
        vuln_severities: List[str] = []

        for v in comp_vulns:
            v_id = v.get("id")
            if v_id:
                vuln_ids.append(str(v_id))
            ratings = v.get("ratings", []) or []
            for r in ratings:
                sev = r.get("severity")
                if sev:
                    vuln_severities.append(str(sev))

        row = {
            "bom_ref": bom_ref,
            "name": comp.get("name"),
            "version": comp.get("version"),
            "type": comp.get("type"),
            "group": comp.get("group"),
            "purl": comp.get("purl"),
            "scope": comp.get("scope"),
            "supplier": supplier_name,
            "licenses": ";".join(sorted(set(license_ids))) if license_ids else None,
            "vuln_count": len(comp_vulns),
            "vuln_ids": ";".join(sorted(set(vuln_ids))) if vuln_ids else None,
            "vuln_severities": ";".join(sorted(set(vuln_severities)))
            if vuln_severities
            else None,
        }
        rows.append(row)

    return rows


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        with path.open("w", encoding="utf-8", newline="") as f:
            f.write("")
        return

    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def export_bom(
    bom: Dict[str, Any],
    base_name: str,
    out_dir: Path,
) -> Tuple[Path, Path, Path]:
    """
    Export raw + normalized + CSV for a single SBOM and
    return the three paths (for index building).
    """
    raw_path = out_dir / f"{base_name}.json"
    normalized_path = out_dir / f"{base_name}.normalized.json"
    csv_path = out_dir / f"{base_name}.csv"

    write_json(raw_path, bom)
    rows = normalize_cyclonedx_components(bom)
    write_json(normalized_path, rows)
    write_csv(csv_path, rows)

    return raw_path, normalized_path, csv_path


# ------------ Stats & index helpers ------------

def classify_error(message: str) -> str:
    """
    Classify a RuntimeError from SBOM fetch into a reason bucket.
    """
    if "No Policy or Agent Scan Performed in last 13 Months" in message:
        return "no_recent_scan"
    if '"code":"NOT_FOUND"' in message or "404 Client Error" in message:
        # generic NOT_FOUND with no recent-scan hint
        return "not_found"
    return "other_error"


def init_stats() -> Dict[str, Any]:
    return {
        "total": 0,
        "success": 0,
        "no_recent_scan": 0,
        "not_found": 0,
        "other_error": 0,
    }


def write_index_file(index_path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    write_csv(index_path, rows)


# ------------ CLI ------------

def parse_args() -> argparse.Namespace:
    # Parent parser holding global options
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--format",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        help="SBOM format slug used in the URL. CSV/normalized assume CycloneDX-like structure.",
    )
    parent.add_argument(
        "--output-dir",
        default="sbom_output",
        help="Directory to write output files into.",
    )
    parent.add_argument(
        "--no-vulns",
        action="store_true",
        help="Exclude vulnerabilities from SBOM API (vulnerability=false).",
    )
    parent.add_argument(
        "--include-linked-agent",
        action="store_true",
        help="For application SBOMs, include linked agent-based project data (linked=true).",
    )

    parser = argparse.ArgumentParser(
        description="Export Veracode SBOMs (US region) for all applications "
                    "and/or all agent-based projects.",
        parents=[parent],
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    # Applications
    app_parser = subparsers.add_parser(
        "applications",
        help="Export SBOMs for ALL application profiles",
        parents=[parent],
        add_help=True,
    )
    app_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional cap on number of applications processed (for testing).",
    )

    # Agent-based projects
    agent_parser = subparsers.add_parser(
        "agents",
        help="Export SBOMs for ALL agent-based projects",
        parents=[parent],
        add_help=True,
    )
    agent_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional cap on number of projects processed (for testing).",
    )

    # Both
    both_parser = subparsers.add_parser(
        "all",
        help="Export SBOMs for ALL apps and ALL agent-based projects",
        parents=[parent],
        add_help=True,
    )
    both_parser.add_argument(
        "--app-limit",
        type=int,
        default=None,
        help="Optional cap on number of applications processed.",
    )
    both_parser.add_argument(
        "--project-limit",
        type=int,
        default=None,
        help="Optional cap on number of projects processed.",
    )

    return parser.parse_args()


def render_summary_table(
    title: str,
    stats: Dict[str, Any],
    entity_label: str,
    output_dir: Path,
    index_filename: str,
) -> None:
    if not RICH_AVAILABLE:
        print()
        print(f"=== {title} ===")
        print(f"Total {entity_label}:              {stats['total']}")
        print(f"  ✅ SBOMs generated:             {stats['success']}")
        print(f"  ⚠️  Skipped (no recent scan):    {stats['no_recent_scan']}")
        print(f"  ⚠️  Skipped (not found):         {stats['not_found']}")
        print(f"  ❌ Skipped (other errors):       {stats['other_error']}")
        print(f"📄 Index file: {output_dir / index_filename}")
        print(f"📁 Output directory: {output_dir}")
        return

    table = Table(title=title)
    table.add_column("Metric", justify="left", style="bold")
    table.add_column("Count", justify="right")

    table.add_row(f"Total {entity_label}", str(stats["total"]))
    table.add_row("✅ SBOMs generated", str(stats["success"]))
    table.add_row("⚠️ Skipped – no recent scan", str(stats["no_recent_scan"]))
    table.add_row("⚠️ Skipped – not found", str(stats["not_found"]))
    table.add_row("❌ Skipped – other errors", str(stats["other_error"]))

    console.print()
    console.print(table)
    console.print(f"📄 Index file: [bold]{output_dir / index_filename}[/bold]")
    console.print(f"📁 Output directory: [bold]{output_dir}[/bold]")


def main() -> None:
    args = parse_args()
    client = VeracodeSbomClient()
    out_dir = Path(args.output_dir)
    include_vulns = not args.no_vulns

    app_stats = init_stats()
    agent_stats = init_stats()

    apps_index_rows: List[Dict[str, Any]] = []
    agents_index_rows: List[Dict[str, Any]] = []

    # -------- Applications --------
    if args.mode in ("applications", "all"):
        app_limit = getattr(args, "limit", None) if args.mode == "applications" else args.app_limit

        if RICH_AVAILABLE:
            console.print("🚀 Starting SBOM export for application profiles...", style="bold")
            with Progress(
                SpinnerColumn(style="bold green"),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Processing application SBOMs...", total=None)

                for app in client.iter_applications():
                    guid = app.get("guid")
                    name = app.get("name") or app.get("profile", {}).get("name")
                    if not guid:
                        continue
                    if app_limit is not None and app_stats["total"] >= app_limit:
                        break

                    app_stats["total"] += 1
                    base_name = f"app_{slugify(name)}_{guid}_{args.format}"

                    status = "success"
                    reason_detail = ""
                    raw_p = normalized_p = csv_p = ""

                    try:
                        bom = client.get_application_sbom(
                            application_guid=guid,
                            format_slug=args.format,
                            linked=args.include_linked_agent,
                            include_vulnerabilities=include_vulns,
                        )
                        raw_path, normalized_path, csv_path = export_bom(bom, base_name, out_dir)
                        app_stats["success"] += 1
                        raw_p, normalized_p, csv_p = map(str, (raw_path, normalized_path, csv_path))
                    except Exception as exc:
                        msg = str(exc)
                        status = classify_error(msg)
                        app_stats[status] += 1
                        reason_detail = msg[:300]

                    apps_index_rows.append(
                        {
                            "entity_type": "application",
                            "guid": guid,
                            "name": name,
                            "sbom_status": status,
                            "reason_detail": reason_detail,
                            "raw_path": raw_p,
                            "normalized_path": normalized_p,
                            "csv_path": csv_p,
                        }
                    )

                    progress.advance(task)
        else:
            print("🚀 Starting SBOM export for application profiles...")
            for app in client.iter_applications():
                guid = app.get("guid")
                name = app.get("name") or app.get("profile", {}).get("name")
                if not guid:
                    continue
                if app_limit is not None and app_stats["total"] >= app_limit:
                    break

                app_stats["total"] += 1
                base_name = f"app_{slugify(name)}_{guid}_{args.format}"

                status = "success"
                reason_detail = ""
                raw_p = normalized_p = csv_p = ""

                try:
                    bom = client.get_application_sbom(
                        application_guid=guid,
                        format_slug=args.format,
                        linked=args.include_linked_agent,
                        include_vulnerabilities=include_vulns,
                    )
                    raw_path, normalized_path, csv_path = export_bom(bom, base_name, out_dir)
                    app_stats["success"] += 1
                    raw_p, normalized_p, csv_p = map(str, (raw_path, normalized_path, csv_path))
                except Exception as exc:
                    msg = str(exc)
                    status = classify_error(msg)
                    app_stats[status] += 1
                    reason_detail = msg[:300]

                apps_index_rows.append(
                    {
                        "entity_type": "application",
                        "guid": guid,
                        "name": name,
                        "sbom_status": status,
                        "reason_detail": reason_detail,
                        "raw_path": raw_p,
                        "normalized_path": normalized_p,
                        "csv_path": csv_p,
                    }
                )

                print(f"\r⏳ Processed applications: {app_stats['total']}", end="")

            print()  # newline

        # Write app index
        apps_index_path = out_dir / "sbom_index_apps.csv"
        write_index_file(apps_index_path, apps_index_rows)

        render_summary_table(
            title="Application SBOM Export Summary",
            stats=app_stats,
            entity_label="applications",
            output_dir=out_dir,
            index_filename="sbom_index_apps.csv",
        )

    # -------- Agent-based projects --------
    if args.mode in ("agents", "all"):
        proj_limit = getattr(args, "limit", None) if args.mode == "agents" else args.project_limit

        workspace_seen = False

        if RICH_AVAILABLE:
            console.print("\n🚀 Starting SBOM export for agent-based projects...", style="bold")
            with Progress(
                SpinnerColumn(style="bold cyan"),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Processing agent-based SBOMs...", total=None)

                for ws in client.iter_workspaces():
                    workspace_seen = True
                    ws_guid = ws.get("id") or ws.get("guid") or ws.get("workspaceGuid") or ws.get("workspaceId")
                    ws_name = ws.get("name")
                    if not ws_guid:
                        continue

                    for prj in client.iter_projects_for_workspace(ws_guid):
                        if proj_limit is not None and agent_stats["total"] >= proj_limit:
                            break

                        prj_guid = (
                            prj.get("id")
                            or prj.get("guid")
                            or prj.get("projectGuid")
                            or prj.get("projectId")
                        )
                        prj_name = prj.get("name")
                        if not prj_guid:
                            continue

                        agent_stats["total"] += 1
                        base_name = f"agent_{slugify(ws_name)}_{slugify(prj_name)}_{prj_guid}_{args.format}"

                        status = "success"
                        reason_detail = ""
                        raw_p = normalized_p = csv_p = ""

                        try:
                            bom = client.get_agent_project_sbom(
                                project_guid=prj_guid,
                                format_slug=args.format,
                                include_vulnerabilities=include_vulns,
                            )
                            raw_path, normalized_path, csv_path = export_bom(bom, base_name, out_dir)
                            agent_stats["success"] += 1
                            raw_p, normalized_p, csv_p = map(str, (raw_path, normalized_path, csv_path))
                        except Exception as exc:
                            msg = str(exc)
                            status = classify_error(msg)
                            agent_stats[status] += 1
                            reason_detail = msg[:300]

                        agents_index_rows.append(
                            {
                                "entity_type": "agent_project",
                                "workspace_guid": ws_guid,
                                "workspace_name": ws_name,
                                "guid": prj_guid,
                                "name": prj_name,
                                "sbom_status": status,
                                "reason_detail": reason_detail,
                                "raw_path": raw_p,
                                "normalized_path": normalized_p,
                                "csv_path": csv_p,
                            }
                        )

                        progress.advance(task)

                    if proj_limit is not None and agent_stats["total"] >= proj_limit:
                        break
        else:
            print("\n🚀 Starting SBOM export for agent-based projects...")
            for ws in client.iter_workspaces():
                workspace_seen = True
                ws_guid = ws.get("id") or ws.get("guid") or ws.get("workspaceGuid") or ws.get("workspaceId")
                ws_name = ws.get("name")
                if not ws_guid:
                    continue

                for prj in client.iter_projects_for_workspace(ws_guid):
                    if proj_limit is not None and agent_stats["total"] >= proj_limit:
                        break

                    prj_guid = (
                        prj.get("id")
                        or prj.get("guid")
                        or prj.get("projectGuid")
                        or prj.get("projectId")
                    )
                    prj_name = prj.get("name")
                    if not prj_guid:
                        continue

                    agent_stats["total"] += 1
                    base_name = f"agent_{slugify(ws_name)}_{slugify(prj_name)}_{prj_guid}_{args.format}"

                    status = "success"
                    reason_detail = ""
                    raw_p = normalized_p = csv_p = ""

                    try:
                        bom = client.get_agent_project_sbom(
                            project_guid=prj_guid,
                            format_slug=args.format,
                            include_vulnerabilities=include_vulns,
                        )
                        raw_path, normalized_path, csv_path = export_bom(bom, base_name, out_dir)
                        agent_stats["success"] += 1
                        raw_p, normalized_p, csv_p = map(str, (raw_path, normalized_path, csv_path))
                    except Exception as exc:
                        msg = str(exc)
                        status = classify_error(msg)
                        agent_stats[status] += 1
                        reason_detail = msg[:300]

                    agents_index_rows.append(
                        {
                            "entity_type": "agent_project",
                            "workspace_guid": ws_guid,
                            "workspace_name": ws_name,
                            "guid": prj_guid,
                            "name": prj_name,
                            "sbom_status": status,
                            "reason_detail": reason_detail,
                            "raw_path": raw_p,
                            "normalized_path": normalized_p,
                            "csv_path": csv_p,
                        }
                    )

                    print(f"\r⏳ Processed agent projects: {agent_stats['total']}", end="")

                if proj_limit is not None and agent_stats["total"] >= proj_limit:
                    break

            print()

        # Write agent index
        agents_index_path = out_dir / "sbom_index_agents.csv"
        write_index_file(agents_index_path, agents_index_rows)

        render_summary_table(
            title="Agent-based SBOM Export Summary",
            stats=agent_stats,
            entity_label="agent-based projects",
            output_dir=out_dir,
            index_filename="sbom_index_agents.csv",
        )

        if agent_stats["total"] == 0 and not workspace_seen:
            msg = (
                "ℹ️  No SCA workspaces were returned by the API. "
                "If you expect agent-based projects, verify that:\n"
                "   • This API key has SCA Agent permissions and entitlements\n"
                "   • You are using the correct org/region for your SCA tenant"
            )
            if RICH_AVAILABLE:
                console.print(msg)
            else:
                print(msg)


if __name__ == "__main__":
    main()
