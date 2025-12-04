# SBOM to Phylum Portfolio Supply Chain Risk Reporting  
![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-blue)
![Phylum](https://img.shields.io/badge/SupplyChain-Phylum-orange)
![Security](https://img.shields.io/badge/Security-Automated-critical)

This repository implements an end-to-end workflow for:

- Generating CycloneDX SBOMs from Veracode
- Uploading those SBOMs to Phylum for supply-chain risk analysis
- Enriching dependency and vulnerability data using Phylum APIs
- Creating a unified portfolio-level JSON
- Producing an executive-ready multi-label PDF risk report

The pipeline is designed for engineering, AppSec, and DevSecOps teams requiring consistent, accurate, and repeatable visibility into software supply chain risk across a full Veracode portfolio.

> **Note:** All values used for organization (`Veracode`), group (`andrea-test`), and project (`andrea-test-project-01dec`) are *examples only*. Replace them with your actual Phylum values.

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
venv/

---

## Requirements

### Python Environment

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Required packages include:

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

# Phase 1: Generate SBOMs from Veracode  
**Script:** `veracode_sbom_portfolio.py`

Generates CycloneDX JSON SBOMs for:

- All Veracode application profiles
- All SCA Agent workspaces
- Linked agent projects

### Command

python3 veracode_sbom_portfolio.py 

all 

–format cyclonedx 

–output-dir sbom_output 

–include-linked-agent

### Output

- `sbom_output/*.json` — SBOM files  
- `sbom_index_apps.csv`  
- `sbom_index_agents.csv`  

Each SBOM contains:

- Component inventory  
- Dependency graph  
- CycloneDX vulnerability metadata  

---

# Phase 2: Upload SBOMs to Phylum  
**Script:** `upload_sboms_to_phylum.py`

Uploads every SBOM to Phylum and records the job metadata.

### Command

python3 upload_sboms_to_phylum.py 

–org Veracode 

–group andrea-test 

–project andrea-test-project-01dec 

–sbom-dir sbom_output 

–output-dir phylum_output

### Output

- `phylum_sbom_upload_index.csv` — authoritative table listing:  
  - SBOM → Phylum label  
  - Job ID  
  - CLI JSON path  
  - Status (`complete`, `pending`, etc.)

- `<SBOM>.phylum_output.json` — raw results from the Phylum CLI

This index CSV is used in Phase 5 for enrichment.

---

# Phase 5a: Build Portfolio Project JSON  
**Script:** `phylum_phase5_project_report.py`

Aggregates and enriches data across all SBOMs into per-label JSON and one unified project JSON.

### Command

python3 phylum_phase5_project_report.py 

–org Veracode 

–group andrea-test 

–project andrea-test-project-01dec 

–index-csv phylum_output/phylum_sbom_upload_index.csv 

–output-dir reports 

–project-output reports/project_andrea-test-project-01dec.json

### Processing Steps

For each SBOM entry:

1. Load the CycloneDX SBOM  
2. Load Phylum CLI output → extract job ID  
3. Query Phylum API:
   - `/data/jobs/{jobId}/policy/input`
   - `/data/packages/{purl}`
4. Extract & enrich:
   - Issue domains (vulnerability, malicious, license, engineering, author)
   - Severity buckets
   - CVSS and advisory metadata
   - Recommendation text
   - Fixed version (when applicable)
5. Compute:
   - Per-label severity & domain distributions
   - Fix Priority Score (package-level)
   - Program Risk Score (label-level)
6. Output:
   - `reports/labels/<label>.json`
   - `reports/project_<project>.json`

The final portfolio JSON is the canonical model driving the PDF.

---

# Phase 5b: Generate Portfolio PDF  
**Script:** `phylum_phase5_project_pdf.py`

Renders a professional multi-section PDF using the enriched project JSON.

### Command

python3 phylum_phase5_project_pdf.py 

–project-json reports/project_andrea-test-project-01dec.json 

–output-pdf reports/project_andrea-test-project-01dec.pdf

---

# PDF Contents

## Page 1 — Portfolio Dashboard

- Project metadata  
- Total labels, packages, issues  
- Domain totals  
- Domain Risk Breakdown Radar  

## Page 2 — Phylum Domain Definitions

Includes descriptions of:

- Total Issues  
- Vulnerability  
- Malicious  
- License  
- Engineering  
- Author  

## Page 3 — Scoring Methodology

### Fix Priority Score

8 × Critical
5 × High
3 × Medium
1 × Low
	•	5 × Malicious
	•	5 when Direct & Critical present

### Program Risk Score

min(10, average(FixPriorityScores))

Includes a worked example for clarity.

---

## Page 4 — Top Risky Components

Table includes:

- Label  
- Package  
- Version  
- Direct?  
- Fix Priority Score  
- Critical / High / Medium / Low  
- Malicious?  

## Page 5 — Program Risk by Label

Shows:

- Program Risk Score  
- Total Issues  
- Malicious Findings  

---

# Per-Label Deep Dive Sections

Each label section includes:

- Metadata & summary table  
- Program Risk gauge  
- Domain Risk radar  
- Issues by severity (bar chart)  
- Issues by domain (bar chart)  
- Top risky packages  
- Full findings table with recommendation text  
- Package-level details  
- Dependency structure summary  
- Recommendations grouped by risk class  

---

# APIs and CLI Used

## Veracode SBOM API

| Purpose | Endpoint |
|---------|----------|
| List applications | `GET /api/applist/v1/applications` |
| Generate application SBOM | `GET /api/sbom/v1/applications/{guid}/cyclonedx` |
| List SCA workspaces | `GET /api/agent-scanning/v1/workspaces` |
| Generate SCA Agent SBOM | `GET /api/sbom/v1/agentws/{ws_id}/projects/{proj_id}/cyclonedx` |

(Region base URLs depend on your Veracode tenant.)

---

## Phylum CLI Usage

| Purpose | Command |
|---------|---------|
| Authenticate user | `phylum auth login` |
| Submit CycloneDX SBOM | `phylum analyze --type cyclonedx <sbom>` |
| Retrieve CLI token | `phylum auth token` |

Each SBOM submission produces a Phylum **Job ID**, used in the API calls below.

---

## Phylum REST API Endpoints

| Purpose | Endpoint |
|---------|----------|
| Retrieve dependency graph + issues for a job | `/data/jobs/{jobId}/policy/input` |
| Retrieve package metadata + recommendation text | `/data/packages/{purl}` |

These endpoints provide domain classification, severity, CVSS, and full recommendation text.

---

# Full Pipeline Example

---
Phase 1 — SBOM generation

python3 veracode_sbom_portfolio.py 

all 

–format cyclonedx 

–output-dir sbom_output 

–include-linked-agent

---
Phase 2 — Upload SBOMs to Phylum

python3 upload_sboms_to_phylum.py 

–org Veracode 

–group andrea-test 

–project andrea-test-project-01dec 

–sbom-dir sbom_output 

–output-dir phylum_output

---
Phase 5a — Build portfolio JSON

python3 phylum_phase5_project_report.py 

–org Veracode 

–group andrea-test 

–project andrea-test-project-01dec 

–index-csv phylum_output/phylum_sbom_upload_index.csv 

–output-dir reports 

–project-output reports/project_andrea-test-project-01dec.json


Phase 5b — Generate final PDF

python3 phylum_phase5_project_pdf.py 

–project-json reports/project_andrea-test-project-01dec.json 

–output-pdf reports/project_andrea-test-project-01dec.pdf

---

# Why This Pipeline Exists

This system provides:

- End-to-end SBOM visibility across a full Veracode portfolio  
- Deep Phylum analysis with enriched recommendations  
- High-quality JSON artifacts for automation  
- Executive-grade PDF reporting  
- Repeatable, deterministic scoring methodologies  
- Portfolio-wide risk prioritization  

It is designed for organizations that demand reliable, scalable SBOM-to-risk intelligence workflows.


⸻
