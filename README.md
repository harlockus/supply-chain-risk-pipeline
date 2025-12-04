📦 SBOM → Phylum → Portfolio Software Supply Chain Risk Pipeline

Automated SBOM generation, ingestion, enrichment, and multi-label portfolio reporting

This project implements a complete, automated pipeline for producing enterprise-quality supply chain risk reports using:
	•	Veracode — for generating SBOMs (Applications + SCA Agent Workspaces)
	•	Phylum — for deep software supply chain risk analysis
	•	Python — for data enrichment, cross-source normalization, and portfolio-level PDF reporting

It outputs:
	•	Per-application enriched label JSON reports
	•	A combined portfolio JSON report
	•	A professional multi-label PDF risk report suitable for executives, AppSec leaders, and engineering teams

Note: All sample organization (Veracode), group (andrea-test), and project names (andrea-test-project-01dec) are examples only.
Replace them with your actual Phylum organization / group / project.

⸻

🔧 Requirements

Python

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Veracode API Credentials

Export your API ID and Key:

export VERACODE_API_KEY_ID="YOUR_API_ID"
export VERACODE_API_KEY_SECRET="YOUR_API_KEY"

(US region assumed, but easily adapted.)

Phylum

Authenticate:

phylum auth login

Export API key:

export PHYLUM_API_KEY="ph0_..."

Ensure your Phylum organization, group, and project exist.

⸻

📁 Directory Structure

SBOM/
  veracode_sbom_portfolio.py
  upload_sboms_to_phylum.py
  phylum_phase5_project_report.py
  phylum_phase5_project_pdf.py
  sbom_output/              # SBOM files generated here (Phase 1)
  phylum_output/            # Phylum CLI output + index CSV (Phase 2)
  reports/                  # Per-label JSON + final project PDF (Phase 5)
  venv/                     # Optional Python virtual environment


⸻

🚀 Phase 1 — Generate SBOMs from Veracode

Script: veracode_sbom_portfolio.py

Generates CycloneDX SBOMs for:
	•	All Veracode Application Profiles
	•	All SCA Agent Workspaces/Projects

Run:

python3 veracode_sbom_portfolio.py \
  all \
  --format cyclonedx \
  --output-dir sbom_output \
  --include-linked-agent

Output:
	•	CycloneDX .json SBOM files under sbom_output/
	•	Index CSVs:
	•	sbom_output/sbom_index_apps.csv
	•	sbom_output/sbom_index_agents.csv

Each SBOM includes:
	•	Component inventory
	•	Dependency graph
	•	CycloneDX vulnerability metadata

⸻

🚀 Phase 2 — Upload SBOMs to Phylum

Script: upload_sboms_to_phylum.py

Uploads each SBOM to Phylum for supply chain risk analysis.

Run:

python3 upload_sboms_to_phylum.py \
  --org Veracode \
  --group andrea-test \
  --project andrea-test-project-01dec \
  --sbom-dir sbom_output \
  --output-dir phylum_output

What the script does:

For each SBOM:
	•	Calls phylum analyze with a unique label
	•	Captures Phylum CLI JSON output
	•	Categorizes each upload as:
	•	complete
	•	pending
	•	policy_failure
	•	error
	•	Appends results to:

phylum_output/phylum_sbom_upload_index.csv



This CSV is used for downstream job-level enrichment.

⸻

🚀 Phase 5a — Build Portfolio Project JSON

Script: phylum_phase5_project_report.py

This script performs the heavy lifting:

Inputs:
	•	phylum_sbom_upload_index.csv
	•	Original SBOMs (CycloneDX)
	•	Phylum API:
	•	/data/jobs/{jobId}/policy/input
	•	/data/packages/{purl}

Run:

python3 phylum_phase5_project_report.py \
  --org Veracode \
  --group andrea-test \
  --project andrea-test-project-01dec \
  --index-csv phylum_output/phylum_sbom_upload_index.csv \
  --output-dir reports \
  --project-output reports/project_andrea-test-project-01dec.json

Processing steps (per SBOM / label):
	1.	Load CycloneDX SBOM
	2.	Load Phylum CLI output → extract Job ID
	3.	Fetch job policy input (all dependencies & issues)
	4.	Fetch per-package details from Phylum /data/packages/{purl}
	5.	Parse:
	•	Issues with domains (vulnerability, malicious, license, engineering, author)
	•	CVSS metadata
	•	Recommended upgrade text
	•	Fixed versions
	6.	Compute summaries:
	•	Issue counts
	•	Severity distribution
	•	Domain distribution
	7.	Write per-label JSON to:

reports/labels/<label>.json


	8.	Aggregate all labels into a single combined file:

reports/project_<project>.json



This JSON becomes the canonical model for PDF and analytics.

⸻

🚀 Phase 5b — Generate Portfolio PDF Report

Script: phylum_phase5_project_pdf.py

Consumes the combined project JSON and produces a professional multi-label PDF.

Run:

python3 phylum_phase5_project_pdf.py \
  --project-json reports/project_andrea-test-project-01dec.json \
  --output-pdf reports/project_andrea-test-project-01dec.pdf


⸻

📄 PDF Report Structure

Page 1 — Project Dashboard
	•	Org / Group / Project metadata
	•	Total labels, total packages, total issues
	•	Domain totals
	•	Domain Risk Breakdown Radar

Page 2 — Phylum Domain Definitions

Explains:
	•	Total Issues
	•	Vulnerability
	•	Malicious
	•	License
	•	Engineering
	•	Author

(Authoritative definitions derived from Phylum’s model.)

Page 3 — Scoring Methodology

Includes:

Fix Priority Score

8 × Critical  
5 × High  
3 × Medium  
1 × Low  
+ 5 × (malicious findings)  
+ 5 (if Direct AND has Critical)

Program Risk Score

min(10, average(FixPriorityScores))

Worked Example
A numeric example demonstrating both calculations.

⸻

Page 4 — Top Risky Components Across the Portfolio

A table (fully wrapped, no overlapping) showing:
	•	Label
	•	Package
	•	Version
	•	Direct?
	•	Fix Priority
	•	Critical / High / Medium / Low counts
	•	Malicious?

⸻

Page 5 — Program Risk by Label

Another cleanly wrapped table showing:
	•	Label
	•	Program Risk (0–10)
	•	Total Issues
	•	Malicious Findings

⸻

🔍 Per-Label Deep-Dive Sections

For each label (application or SCA Agent):
	•	Summary table
	•	Program Risk gauge
	•	Domain radar chart
	•	Issue severity & domain bar charts
	•	Top risky packages
	•	Full findings (Critical → Low) with:
	•	Severity
	•	Domain
	•	Package
	•	Tag
	•	Direct?
	•	Recommendation (recommendation_text + fixed version)
	•	Package-level details
	•	Dependency structure
	•	Recommendations:
	•	Malicious
	•	Critical
	•	License risk

⸻

🧵 End-to-End Example (Full Pipeline)

# Phase 1 — Generate all SBOMs
python3 veracode_sbom_portfolio.py all \
  --format cyclonedx \
  --output-dir sbom_output \
  --include-linked-agent

# Phase 2 — Upload SBOMs to Phylum
python3 upload_sboms_to_phylum.py \
  --org Veracode \
  --group andrea-test \
  --project andrea-test-project-01dec \
  --sbom-dir sbom_output \
  --output-dir phylum_output

# Phase 5a — Build project-level JSON
python3 phylum_phase5_project_report.py \
  --org Veracode \
  --group andrea-test \
  --project andrea-test-project-01dec \
  --index-csv phylum_output/phylum_sbom_upload_index.csv \
  --output-dir reports \
  --project-output reports/project_andrea-test-project-01dec.json

# Phase 5b — Generate portfolio PDF
python3 phylum_phase5_project_pdf.py \
  --project-json reports/project_andrea-test-project-01dec.json \
  --output-pdf reports/project_andrea-test-project-01dec.pdf


⸻

✔ Summary

This pipeline enables you to:
	•	Automatically generate Veracode SBOMs
	•	Upload to Phylum for supply chain risk analysis
	•	Enrich results with per-package recommendations
	•	Produce a unified portfolio JSON
	•	Generate a polished, multi-label PDF risk report

It delivers full traceability, complete component inventory, domain-level analytics, scoring methodology, and executive-ready reporting.

⸻
