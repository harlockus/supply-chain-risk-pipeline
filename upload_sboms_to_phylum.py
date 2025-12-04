#!/usr/bin/env python3
"""
Phase 2: Upload Veracode-generated SBOMs into Phylum via the official CLI.

Behavior:
  - Scans a directory (default: sbom_output) for SBOM files matching '*_cyclonedx.json'.
  - For each SBOM:
      * Generates a UNIQUE Phylum label based on the SBOM filename:
            <label-prefix><normalized-app-or-project-name>
        e.g., veracode-sbom-test-for-metadata
      * Calls:
            phylum analyze --type cyclonedx
                           --project <project>
                           --group <group>
                           --org <org>
                           --label <unique-label>
                           <sbom_path>
      * Classifies the result as:
            - 'complete_pass'           : analysis finished, no policy violations (exit_code == 0)
            - 'complete_policy_failure' : analysis finished, policy failed (exit_code != 0)
            - 'pending'                 : upload OK, Phylum still processing packages
            - 'error'                   : other CLI/API error
      * Stores CLI output for each SBOM as JSON in phylum_output/.
  - Generates:
      * phylum_output/phylum_sbom_upload_index.csv
      * Rich summary table (if 'rich' is installed).

Prereqs:
  - Phylum CLI installed and on PATH:
        brew install phylum
        or: curl https://sh.phylum.io/ | sh -
  - Auth configured:
        phylum auth login
"""

import argparse
import csv
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List

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


# ---------- Helpers ----------

def find_sbom_files(sbom_dir: Path, glob_pattern: str = "*_cyclonedx.json") -> List[Path]:
    files = sorted(sbom_dir.glob(glob_pattern))
    return [f for f in files if f.is_file()]


def detect_entity_type(sbom_path: Path) -> str:
    """
    Infer entity type from filename prefix (matches Phase 1 naming):
      - app_...   → 'application'
      - agent_... → 'agent_project'
      - otherwise → 'unknown'
    """
    name = sbom_path.name
    if name.startswith("app_"):
        return "application"
    if name.startswith("agent_"):
        return "agent_project"
    return "unknown"


def generate_unique_label(sbom_path: Path, prefix: str = "veracode-sbom-") -> str:
    """
    Create a unique label for each SBOM based on its filename.

    Examples:
      app_TEST_FOR_METADATA_c43b98..._cyclonedx.json
        -> veracode-sbom-test-for-metadata

      agent_Engineering_ServiceAPI_1234..._cyclonedx.json
        -> veracode-sbom-engineering-serviceapi
    """
    name = sbom_path.stem  # strip .json

    # remove trailing '_cyclonedx'
    name = re.sub(r"_cyclonedx$", "", name, flags=re.IGNORECASE)

    # remove leading 'app_' or 'agent_'
    name = re.sub(r"^(app|agent)_", "", name, flags=re.IGNORECASE)

    # remove trailing GUID-style suffix if present
    name = re.sub(
        r"_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        "",
        name,
    )

    # normalize to lowercase and kebab-case
    name = name.lower()
    name = re.sub(r"[^a-z0-9]+", "-", name).strip("-")

    if not name:
        name = "sbom"

    return f"{prefix}{name}"


def classify_analysis(exit_code: int, stdout_text: str, stderr_text: str) -> str:
    """
    Map CLI result to a high-level status:

      - 'complete_pass'           : analysis succeeded (exit_code == 0)
      - 'complete_policy_failure' : analysis finished, policy failed
      - 'pending'                 : upload OK but Phylum still processing packages
      - 'error'                   : other error

    'pending' is detected by:
      - non-zero exit code, AND
      - Phylum's message about unprocessed packages / should complete soon.

    'complete_policy_failure' is detected by:
      - parse success,
      - failure banner,
      - not pending.
    """
    combined = (stdout_text or "") + "\n" + (stderr_text or "")
    lower = combined.lower()

    has_parse_success = "successfully parsed dependency file" in lower
    has_unprocessed = "unprocessed packages" in lower
    has_should_complete = ("should complete soon" in lower
                           or "preventing a complete risk analysis" in lower)
    has_failure_banner = ("phylum supply chain risk analysis — failure" in lower
                          or "phylum supply chain risk analysis - failure" in lower)

    # 1) Clean success (no policy violations)
    if exit_code == 0 and has_parse_success:
        return "complete_pass"

    # 2) Analysis incomplete / still processing
    if exit_code != 0 and has_parse_success and (has_unprocessed or has_should_complete):
        return "pending"

    # 3) Analysis finished but policy failed
    if exit_code != 0 and has_parse_success and has_failure_banner and not (has_unprocessed or has_should_complete):
        return "complete_policy_failure"

    # 4) Everything else: real error
    return "error"


def run_phylum_analyze(
    sbom_path: Path,
    sbom_type: str,
    project: str,
    group: str,
    org: str,
    label: str,
    timeout: int = 600,
) -> Dict[str, Any]:
    """
    Call `phylum analyze` on a single SBOM file.

    We deliberately DO NOT use --json so we can rely on the human-readable
    messages (including 'unprocessed packages') for classification.

    Returns:
      {
        "exit_code": int,
        "analysis_status": "complete_pass" | "complete_policy_failure" | "pending" | "error",
        "stdout": "<raw stdout>",
        "stderr": "<raw stderr>",
      }
    """
    cmd = [
        "phylum",
        "analyze",
        "--type",
        sbom_type,
        "--project",
        project,
        "--group",
        group,
        "--org",
        org,
        "--label",
        label,
        str(sbom_path),
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "phylum CLI not found. Make sure it is installed and on PATH "
            "(e.g., `brew install phylum` or `curl https://sh.phylum.io/ | sh -`)."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        return {
            "exit_code": -1,
            "analysis_status": "error",
            "stdout": "",
            "stderr": f"Timeout running {' '.join(cmd)}: {exc}",
        }

    analysis_status = classify_analysis(proc.returncode, proc.stdout, proc.stderr)

    return {
        "exit_code": proc.returncode,
        "analysis_status": analysis_status,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def render_summary_table(
    total: int,
    complete_pass: int,
    complete_policy_failure: int,
    pending: int,
    errors: int,
    output_dir: Path,
    index_filename: str,
) -> None:
    if not RICH_AVAILABLE:
        print()
        print("=== Phylum SBOM Upload Summary ===")
        print(f"Total SBOMs processed:                        {total}")
        print(f"  ✅ Complete (no policy violations):         {complete_pass}")
        print(f"  ❗ Complete (policy violations detected):   {complete_policy_failure}")
        print(f"  ⏳ Pending analyses:                        {pending}")
        print(f"  ❌ Errors (technical/CLI):                  {errors}")
        print(f"📄 Index file: {output_dir / index_filename}")
        print(f"📁 Output directory: {output_dir}")
        return

    table = Table(title="Phylum SBOM Upload Summary")
    table.add_column("Metric", justify="left", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Total SBOM files", str(total))
    table.add_row("✅ Complete (no policy violations)", str(complete_pass))
    table.add_row("❗ Complete (policy violations)", str(complete_policy_failure))
    table.add_row("⏳ Pending analyses", str(pending))
    table.add_row("❌ Errors (technical/CLI)", str(errors))

    console.print()
    console.print(table)
    console.print(f"📄 Index file: [bold]{output_dir / index_filename}[/bold]")
    console.print(f"📁 Output directory: [bold]{output_dir}[/bold]")


# ---------- CLI & main ----------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Upload SBOMs (e.g., Veracode-generated CycloneDX JSON) to Phylum "
            "using the official `phylum analyze` CLI with unique labels per SBOM."
        )
    )
    parser.add_argument(
        "--sbom-dir",
        default="sbom_output",
        help="Directory containing SBOM files from Phase 1 (default: sbom_output).",
    )
    parser.add_argument(
        "--glob-pattern",
        default="*_cyclonedx.json",
        help="Glob pattern to select SBOM files (default: '*_cyclonedx.json').",
    )
    parser.add_argument(
        "--sbom-type",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        help="SBOM format to tell Phylum (default: cyclonedx).",
    )
    parser.add_argument(
        "--project",
        required=True,
        help="Phylum project name to use for all uploads (e.g., fm-project-demo).",
    )
    parser.add_argument(
        "--group",
        required=True,
        help="Phylum group name (e.g., FM-Project-Demo).",
    )
    parser.add_argument(
        "--org",
        required=True,
        help="Phylum organization (e.g., Veracode).",
    )
    parser.add_argument(
        "--label-prefix",
        default="veracode-sbom-",
        help="Prefix for auto-generated labels (default: veracode-sbom-).",
    )
    parser.add_argument(
        "--output-dir",
        default="phylum_output",
        help="Directory to store CLI outputs and index CSV (default: phylum_output).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Per-SBOM timeout in seconds for `phylum analyze` (default: 600).",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sbom_dir = Path(args.sbom_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not sbom_dir.is_dir():
        raise SystemExit(f"SBOM directory does not exist: {sbom_dir}")

    sbom_files = find_sbom_files(sbom_dir, args.glob_pattern)
    if not sbom_files:
        raise SystemExit(
            f"No SBOM files found in {sbom_dir} matching pattern '{args.glob_pattern}'."
        )

    index_rows: List[Dict[str, Any]] = []
    total = len(sbom_files)
    complete_pass = 0
    complete_policy_failure = 0
    pending = 0
    errors = 0

    if RICH_AVAILABLE:
        console.print(
            f"🚀 Starting Phylum uploads for SBOMs in [bold]{sbom_dir}[/bold]...",
            style="bold",
        )
        with Progress(
            SpinnerColumn(style="bold magenta"),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                "Uploading SBOMs to Phylum...", total=total
            )

            for sbom_path in sbom_files:
                entity_type = detect_entity_type(sbom_path)
                base_name = sbom_path.stem

                label = generate_unique_label(sbom_path, prefix=args.label_prefix)

                result = run_phylum_analyze(
                    sbom_path=sbom_path,
                    sbom_type=args.sbom_type,
                    project=args.project,
                    group=args.group,
                    org=args.org,
                    label=label,
                    timeout=args.timeout,
                )

                analysis_status = result["analysis_status"]
                exit_code = result["exit_code"]
                stdout_text = result["stdout"]
                stderr_text = result["stderr"]

                output_json_path = out_dir / f"{base_name}.phylum_output.json"
                cli_output: Dict[str, Any] = {
                    "analysis_status": analysis_status,
                    "exit_code": exit_code,
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                }
                write_json(output_json_path, cli_output)

                if analysis_status == "complete_pass":
                    complete_pass += 1
                elif analysis_status == "complete_policy_failure":
                    complete_policy_failure += 1
                elif analysis_status == "pending":
                    pending += 1
                else:
                    errors += 1

                index_rows.append(
                    {
                        "sbom_path": str(sbom_path),
                        "entity_type": entity_type,
                        "phylum_project": args.project,
                        "phylum_group": args.group,
                        "phylum_org": args.org,
                        "phylum_label": label,
                        "analysis_status": analysis_status,
                        "exit_code": exit_code,
                        "phylum_output_json": str(output_json_path),
                    }
                )

                progress.advance(task)
    else:
        print(f"🚀 Starting Phylum uploads for SBOMs in {sbom_dir}...")
        processed = 0
        for sbom_path in sbom_files:
            entity_type = detect_entity_type(sbom_path)
            base_name = sbom_path.stem

            label = generate_unique_label(sbom_path, prefix=args.label_prefix)

            result = run_phylum_analyze(
                sbom_path=sbom_path,
                sbom_type=args.sbom_type,
                project=args.project,
                group=args.group,
                org=args.org,
                label=label,
                timeout=args.timeout,
            )

            analysis_status = result["analysis_status"]
            exit_code = result["exit_code"]
            stdout_text = result["stdout"]
            stderr_text = result["stderr"]

            output_json_path = out_dir / f"{base_name}.phylum_output.json"
            cli_output: Dict[str, Any] = {
                "analysis_status": analysis_status,
                "exit_code": exit_code,
                "stdout": stdout_text,
                "stderr": stderr_text,
            }
            write_json(output_json_path, cli_output)

            if analysis_status == "complete_pass":
                complete_pass += 1
            elif analysis_status == "complete_policy_failure":
                complete_policy_failure += 1
            elif analysis_status == "pending":
                pending += 1
            else:
                errors += 1

            index_rows.append(
                {
                    "sbom_path": str(sbom_path),
                    "entity_type": entity_type,
                    "phylum_project": args.project,
                    "phylum_group": args.group,
                    "phylum_org": args.org,
                    "phylum_label": label,
                    "analysis_status": analysis_status,
                    "exit_code": exit_code,
                    "phylum_output_json": str(output_json_path),
                }
            )

            processed += 1
            print(f"\r⏳ Processed SBOMs: {processed}/{total}", end="")

        print()

    index_path = out_dir / "phylum_sbom_upload_index.csv"
    write_csv(index_path, index_rows)

    render_summary_table(
        total=total,
        complete_pass=complete_pass,
        complete_policy_failure=complete_policy_failure,
        pending=pending,
        errors=errors,
        output_dir=out_dir,
        index_filename="phylum_sbom_upload_index.csv",
    )


if __name__ == "__main__":
    main()
