# Evidence Assistant

This is your assistant that automatically scans, validates and organises evidences, or also known as screenshots, against the **Essential 8 Framework**. It aims to help users validate text evidence or screenshots (e.g. Windows environment) against the security strategies using OCR (Tesseract) and keyword rules to generate meaningful **PDF/CSV reports**.

---

## Strategies Supported

1. Application Control
2. Patch Applications
3. Configure Microsoft Office Macro Settings
4. User Application Hardening
5. Restrict Administrative Privileges
6. Patch Operating Systems
7. Multi-Factor Authentication
8. Regular Backups

---

## How It Works

- Provide evidences in common format like JPEG, PNG, PDF, DOCX or text files in the **evidence/** folder
- The tool extracts visible text using **Tesseract OCR** and checks for non-compliance indicators using strategy-specific keyword rules
- Results are saved in the **results/** folder with reports generated in CSV or PDF depending on the mode chosen

---

## Set up and Requirements

- **Python 3.9+**
  For running the Evidence Assistant and manage dependencies
  [Download Python](https://www.python.org/downloads/)

- **Tesseract OCR**
  Required for extracting text from images/screenshots
  Install via:
  - macOS: `brew install tesseract`
  - Ubuntu/Debian: `sudo apt install tesseract-ocr`
  - Windows: [Download installer](https://github.com/tesseract-ocr/tesseract) and add the install folder (e.g., `C:\Program Files\Tesseract-OCR`) to your **System PATH**

---

## Running the Tool

After installing Python and Tesseract, there are two options to run the tool:

**Option 1: Command-Line Interface (CLI)**
- Set up the virtual environment, install all the requirements and run the program
```
python -m venv .venv && source .venv/bin/activate # macOS/Linux
python -m venv .venv && .venv\Scripts\activate # Windows
pip install -r security/requirements.txt
python security/evidenceassistant.py
```
- The CLI provides two modes:
(1) Scanner mode: able to batch scan multiple files and generate a CSV summary
(2) Report Generator mode: able to scan a single file at one time and generate a PDF executive report

**Option 2: Web Interface (UI)**
- Use the AutoAudit product. Evidence scanning is served by the authenticated
  backend at `/v1/evidence` (`backend-api/app/api/v1/evidence.py`), which signs
  you in and checks that the evidence and reports are yours.
- The legacy standalone app in `security/evidence_ui/app.py` is **not a service**.
  It has no authentication on any route, so it is no longer built when the module
  is imported and it must never be exposed on a network or deployed.

---

## Legacy standalone UI (local development only)

The old `evidence_ui` FastAPI app is kept only as a local harness for working on
the scanner itself. It is unauthenticated, so building it requires two deliberate
signals and it refuses to start otherwise:

1. `AUTOAUDIT_EVIDENCE_UI_DEV_SERVER=1` — an explicit opt-in, and
2. `APP_ENV` **explicitly** set to `dev`, `development`, `local` or `test`. An
   unset or empty `APP_ENV` is refused, so a deployed process that inherits the
   opt-in variable still cannot serve the app.

```
python -m venv .venv && source .venv/bin/activate # macOS/Linux
python -m venv .venv && .venv\Scripts\activate # Windows
pip install -r security/requirements.txt
AUTOAUDIT_EVIDENCE_UI_DEV_SERVER=1 APP_ENV=dev python -m uvicorn \
    security.evidence_ui.app:create_app --factory --host 127.0.0.1 --reload
```

Bind it to `127.0.0.1` only. Do not add `--host 0.0.0.0`, do not put it behind a
tunnel, and do not add it to any compose file or image. `security/Dockerfile`
builds the offline CLI and intentionally starts no server.

Importing `security.evidence_ui.app` is safe and side-effect free: it creates no
application, adds no CORS middleware, mounts no directories, probes no OCR binary
and writes no files. That is what lets the authenticated backend reuse its
extraction and scanning helpers.

---

## Folder Structure

AutoAudit/security/
├── evidence_ui/           # Scanner helpers + opt-in local dev harness (not a service)
│   ├── ui.html
│   └── app.py
├── evidence_backend/      # Core OCR + scanner/reportgenerator tools
│   ├── core_ocr.py
│   ├── scanner.py
│   └── reportgenerator.py
├── evidence/             # Place your screenshots/docs here
├── reports/              # Report generation logic
├── results/              # Auto-generated reports and preview documents
│   ├── scan_report.csv
│   ├── reports/
│   └── previews/
├── strategies/           # Detection rules per strategy
├── requirements.txt      # Python dependencies
└── evidenceassistant.py  # CLI wrapper

---

## Documentations and Next Steps

Refer to https://deakin365.sharepoint.com/:x:/r/sites/HardhatEnterprises2/_layouts/15/Doc2.aspx?action=edit&sourcedoc=%7B1279e491-285a-4135-acef-7c28cf2da379%7D&wdOrigin=TEAMS-MAGLEV.teamsSdk_ns.rwc&wdExp=TEAMS-TREATMENT&wdhostclicktime=1758141979506&web=1 for the full documentation of the Evidence Assistant
