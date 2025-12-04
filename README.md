# SBOM to Phylum Portfolio Risk Reporting Pipeline

This repository implements an end-to-end workflow for generating Veracode SBOMs, analyzing them with Phylum, enriching the results, and producing a portfolio-level JSON and PDF risk report.  
It is designed for engineering, AppSec, and DevSecOps teams needing clear, organization-wide supply chain risk visibility.

> All organization (`Veracode`), group (`andrea-test`), and project (`andrea-test-project-01dec`) values shown below are examples only. Replace them with your actual Phylum values.

---

## Overview

The pipeline consists of four major stages:

1. **SBOM Generation (Veracode)**  
   Produce CycloneDX SBOM files for every Veracode application and SCA Agent workspace.

2. **SBOM Upload (Phylum)**  
   Upload SBOMs to Phylum, generate labels, capture job IDs, and store CLI analysis metadata.

3. **Project-Level JSON Aggregation**  
   Enrich each label with Phylum API data, recommendations, and severity/domain mappings.  
   Produce one combined JSON file representing the entire project portfolio.

4. **Portfolio PDF Report**  
   Generate a multi-section PDF including domain definitions, scoring methodology, project-wide summaries, and per-label deep-dive reporting.

---

## Repository Structure

SBOM/

veracode_sbom_portfolio.py

upload_sboms_to_phylum.py

phylum_phase5_project_report.py

phylum_phase5_project_pdf.py

sbom_output/

phylum_output/

reports/

venv/                      (optional virtual environment)

---

## Requirements

### Python Environment

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Required libraries include:

- requests
- python-dateutil
- matplotlib
- reportlab

### Veracode Credentials

export VERACODE_API_KEY_ID=“YOUR_API_ID”
export VERACODE_API_KEY_SECRET=“YOUR_API_KEY”

### Phylum Authentication

phylum auth login
export PHYLUM_API_KEY=“ph0_…”

---

# Phase 1: SBOM Generation

**Script:** `veracode_sbom_portfolio.py`

Generates a CycloneDX SBOM for each Veracode application and each SCA Agent workspace.

### Run

python3 veracode_sbom_portfolio.py 
all 
–format cyclonedx 
–output-dir sbom_output 
–include-linked-agent

### Output

Examples:

- `sbom_output/app_<name>_<uuid>_cyclonedx.json`
- `sbom_output/agent_<workspace>_<project>_<uuid>_cyclonedx.json`
- `sbom_index_apps.csv`
- `sbom_index_agents.csv`

Each SBOM contains the full component inventory, dependency graph, and CycloneDX vulnerability metadata when available.

---

# Phase 2: SBOM Upload to Phylum

**Script:** `upload_sboms_to_phylum.py`

Uploads every SBOM to Phylum using the Phylum CLI and creates the master index that Phase 5 uses.

### Run

python3 upload_sboms_to_phylum.py 
–org Veracode 
–group andrea-test 
–project andrea-test-project-01dec 
–sbom-dir sbom_output 
–output-dir phylum_output

### Output

- `phylum_output/phylum_sbom_upload_index.csv`
- `<SBOM>.phylum_output.json`

The index CSV includes:

- The SBOM path  
- The Phylum label created  
- The Phylum job ID  
- Analysis status (`complete`, `pending`, `policy_failure`, `error`)  
- Path to CLI output JSON  

This file is the authoritative mapping for subsequent enrichment.

---

# Phase 5a: Project-Level JSON Construction

**Script:** `phylum_phase5_project_report.py`

Aggregates and enriches Phylum analysis results for all SBOMs into a single project JSON.

### Run

python3 phylum_phase5_project_report.py 
–org Veracode 
–group andrea-test 
–project andrea-test-project-01dec 
–index-csv phylum_output/phylum_sbom_upload_index.csv 
–output-dir reports 
–project-output reports/project_andrea-test-project-01dec.json

### Operations Performed

For each SBOM entry in the index:

1. Load the CycloneDX SBOM.
2. Load Phylum CLI output and extract the job ID.
3. Query Phylum API:
   - `/data/jobs/{jobId}/policy/input` (full dependency list + issue metadata)
   - `/data/packages/{purl}` (per-package details + recommendations)
4. Enrich each package with:
   - Domain classification (vulnerability, malicious, license, engineering, author)
   - Severity buckets and CVSS details
   - Recommendation text
   - Fixed version (when available)
5. Compute:
   - Fix Priority Score per package
   - Program Risk Score per label
   - Domain and severity distributions
6. Write:
   - One per-label JSON file under `reports/labels/`
   - One combined portfolio JSON under `reports/`

The combined file is the **canonical representation of the entire project**.

---

# Phase 5b: Portfolio PDF Report

**Script:** `phylum_phase5_project_pdf.py`

Generates a multi-section, professional PDF from the combined project JSON.

### Run

python3 phylum_phase5_project_pdf.py 
–project-json reports/project_andrea-test-project-01dec.json 
–output-pdf reports/project_andrea-test-project-01dec.pdf

---

# PDF Contents

### Page 1: Portfolio Dashboard
- Organization / Group / Project metadata  
- Total labels, packages, issues  
- Domain totals  
- Domain Risk Breakdown Radar  

### Page 2: Phylum Domain Model Definitions
Includes precise definitions of:

- Total Issues  
- Vulnerability  
- Malicious  
- License  
- Engineering  
- Author  

### Page 3: Scoring Methodology
Defines:

- Fix Priority Score  
- Program Risk Score  
- Weighting logic  
- Worked example  

### Page 4: Top Risky Components
A portfolio-wide ranking of packages based on Fix Priority Score.

### Page 5: Program Risk by Label
Summaries of each SBOM label:

- Program Risk Score  
- Total Issues  
- Malicious Findings  

### Per-Label Deep Dives (one section per SBOM label)
Each section contains:

- Summary table  
- Program Risk gauge  
- Domain Risk radar  
- Severity and domain bar charts  
- Top risky packages  
- Full findings table (with recommendation text + fixed versions)  
- Package-level details  
- Dependency structure  
- Recommendations by category (malicious, critical vulnerabilities, license risks)  

---

# Full Pipeline Example

Phase 1 — SBOM generation

python3 veracode_sbom_portfolio.py all 
–format cyclonedx 
–output-dir sbom_output 
–include-linked-agent

Phase 2 — Upload to Phylum

python3 upload_sboms_to_phylum.py 
–org Veracode 
–group andrea-test 
–project andrea-test-project-01dec 
–sbom-dir sbom_output 
–output-dir phylum_output

Phase 5a — Portfolio JSON

python3 phylum_phase5_project_report.py 
–org Veracode 
–group andrea-test 
–project andrea-test-project-01dec 
–index-csv phylum_output/phylum_sbom_upload_index.csv 
–output-dir reports 
–project-output reports/project_andrea-test-project-01dec.json

Phase 5b — Final PDF

python3 phylum_phase5_project_pdf.py 
–project-json reports/project_andrea-test-project-01dec.json 
–output-pdf reports/project_andrea-test-project-01dec.pdf

---

# Why This Pipeline Exists

This workflow provides:

- Broad **supply chain visibility** across all Veracode SBOMs  
- Verified **Phylum-grade risk analysis**  
- Unified and predictable **JSON data models**  
- Executive-suitable **PDF reporting**  
- Clear **scoring transparency** and **actionable recommendations**  
- Full coverage for both **apps** and **SCA Agent workspaces**

It is built for teams that need accurate, consistent, and repeatable supply chain risk reporting at scale.


⸻
