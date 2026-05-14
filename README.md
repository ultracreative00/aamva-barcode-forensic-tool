# AAMVA Barcode Forensic Tool

> **A localhost browser-based forensic analysis tool for AAMVA PDF417 driver license barcodes.**
> Decode, parse, and authenticate DL/ID card barcodes from scanned images — no command line required.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![AAMVA](https://img.shields.io/badge/AAMVA-v01–v10-green)](https://www.aamva.org)
[![License](https://img.shields.io/badge/License-MIT-grey)](LICENSE)

---

## Table of Contents

1. [What This Tool Does](#what-this-tool-does)
2. [Architecture Overview](#architecture-overview)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Running the Tool](#running-the-tool)
6. [Using the Browser UI](#using-the-browser-ui)
7. [Understanding the Results](#understanding-the-results)
8. [AAMVA Standard Reference](#aamva-standard-reference)
9. [All 71 Registered IINs](#all-71-registered-iins)
10. [Field Reference](#field-reference)
11. [Troubleshooting](#troubleshooting)
12. [Development Notes](#development-notes)

---

## What This Tool Does

The AAMVA Barcode Forensic Tool decodes PDF417 barcodes from driver license card images and performs a comprehensive structural and standards-compliance analysis against the **AAMVA DL/ID Card Design Standard** (versions 01–10, years 2000–2020).

### Key Capabilities

| Capability | Detail |
|---|---|
| **Multi-file batch upload** | Drop any number of JPG/PNG/BMP card images at once |
| **Barcode decode** | zbarimg (3 preprocessing strategies) → pdf417decoder fallback |
| **AAMVA version support** | Full v01–v10 (2000–2020), all 50 US states + DC + territories + 9 Canadian provinces |
| **IIN registry** | All 71 registered AAMVA Issuer Identification Numbers |
| **Subfile validation** | Verifies DL + Zxx subfile byte-range offsets declared in the header |
| **Mandatory field check** | Per-version mandatory field list (v1 minimal → v5+ full 22-field set) |
| **Field value validation** | Sex, eye colour, hair colour, truncation flags, compliance type, ZIP, height format |
| **Date parsing** | MMDDYYYY, YYYYMMDD, MMYYYY — age, expiry validity, term length |
| **Encoding mode detection** | Binary vs tilde-escape (~XX) anomaly detection |
| **12-point verdict checklist** | State-agnostic authenticity scoring |
| **Side-by-side comparison** | Field diff between any two cards, encoding mismatch flagged |
| **JSON export** | Full forensic results downloadable as timestamped JSON |
| **Light/Dark theme** | Persistent toggle in the browser UI |

---

## Architecture Overview

```
aamva-barcode-forensic-tool/
│
├── app.py                  ← Localhost HTTP server (stdlib only, no Flask)
│   │                         Wraps forensic engine, serves UI, handles multipart uploads
│   └── POST /analyse       ← Accepts multiple image files, returns JSON array of results
│
├── aamva_forensic.py       ← Core forensic engine (all analysis logic lives here)
│   ├── decode_image()        Image → raw barcode string (zbarimg + preprocessing + pdf417decoder)
│   ├── parse_subfiles()      Full AAMVA header + subfile directory parser
│   ├── analyse_mandatory_fields()  Per-version mandatory field check
│   ├── analyse_dates()       Multi-format date parser + validity check
│   ├── analyse_field_values()  Enum validation (sex, eye, hair, ZIP, height)
│   ├── authenticity_verdict()  14-point state-agnostic checklist
│   └── compare_cards()       Field-level diff + encoding mode mismatch
│
├── templates/
│   └── index.html          ← Single-file browser UI (vanilla HTML/CSS/JS, no build step)
│       ├── Drop zone + multi-file picker
│       ├── Batch results grid (collapsible per-file cards)
│       ├── Verdict / Fields / Dates / Subfiles / Raw tabs per card
│       ├── Compare panel (any two cards, field diff table)
│       └── JSON export
│
└── requirements.txt        ← Pillow, pdf417decoder
```

**No framework dependencies.** `app.py` uses Python's built-in `http.server` module only. The browser UI is plain HTML/CSS/JavaScript with no npm, no build step, and no CDN calls — it works fully offline.

---

## Requirements

### System Requirements

| Requirement | Version | Notes |
|---|---|---|
| **Python** | 3.9 or newer | `python3 --version` to check |
| **pip** | Any recent | Comes with Python |
| **zbar-tools** | Any | For barcode image decoding |
| **libzbar0** | Any | zbar shared library |
| **OS** | Linux / macOS / WSL | Windows native supported via WSL |

### Python Packages

| Package | Purpose |
|---|---|
| `Pillow` | Image preprocessing (resize, threshold, invert) for better barcode detection |
| `pdf417decoder` | Fallback PDF417 decoder when zbarimg fails |

---

## Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/ultracreative00/aamva-barcode-forensic-tool.git
cd aamva-barcode-forensic-tool
```

### Step 2 — Install System Dependencies

**Ubuntu / Debian / WSL:**
```bash
sudo apt-get update
sudo apt-get install -y zbar-tools libzbar0
```

**macOS (Homebrew):**
```bash
brew install zbar
```

**Windows (WSL recommended):**
```bash
# Inside WSL Ubuntu terminal:
sudo apt-get update && sudo apt-get install -y zbar-tools libzbar0
```

### Step 3 — Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS/WSL
# OR
venv\Scripts\activate           # Windows CMD (if not using WSL)
```

### Step 4 — Install Python Packages

```bash
pip install -r requirements.txt
```

This installs `Pillow` and `pdf417decoder`. If either is missing at runtime, `app.py` will attempt to install them automatically on startup.

### Step 5 — Verify Installation

```bash
which zbarimg          # should print a path like /usr/bin/zbarimg
python3 -c "import PIL; import pdf417decoder; print('OK')"
```

Both commands should succeed before continuing.

---

## Running the Tool

### Start the Server

```bash
python3 app.py
```

You should see:

```
🔍  AAMVA Forensic Tool  —  http://localhost:8000
    Press Ctrl+C to stop
```

### Open the Browser

Navigate to:

```
http://localhost:8000
```

The UI loads immediately — no login, no configuration required.

### Stop the Server

Press `Ctrl+C` in the terminal where `app.py` is running.

### Custom Port

To run on a different port, edit the `PORT` constant near the top of `app.py`:

```python
PORT = 9000   # change to any available port
```

Then open `http://localhost:9000` in your browser.

---

## Using the Browser UI

### 1. Upload Images

**Drag and Drop**
Drag one or more card images directly onto the drop zone. The zone highlights in teal when a drag is detected.

**Browse Button**
Click **Browse Files** to open the system file picker. Hold `Ctrl` (or `Cmd` on macOS) to select multiple files at once.

**Supported formats:** JPG, JPEG, PNG, BMP

After selecting files, each filename appears as a chip below the drop zone. Click the **✕** on any chip to remove a file before analysing.

### 2. Run Analysis

Click the **🔍 Analyse** button. A spinner appears while the server decodes and analyses each file. Results appear automatically when complete.

### 3. Stats Bar

The summary bar across the top of results shows:

| Metric | Meaning |
|---|---|
| **Files** | Total images submitted |
| **Authentic** | All 12 checks passed |
| **Warnings** | 1–2 checks failed (minor issues) |
| **Failed** | 3+ checks failed (structural problems) |
| **Errors** | Barcode could not be decoded at all |

### 4. Result Cards

Each file gets its own collapsible card. Click the card header to expand or collapse it. Cards default to expanded for the first result.

The coloured badge shows the overall verdict:
- 🟢 **AUTHENTIC** — all checks passed
- 🟡 **WARNING** — 1–2 minor failures
- 🔴 **FAILED** — structural failures detected
- ⚠️ **ERROR** — decode failed, raw error shown

#### Tabs Inside Each Card

| Tab | What It Shows |
|---|---|
| **Verdict** | 12-point checklist (✅/❌ per check), missing mandatory fields, field value errors |
| **Fields** | Complete table of all parsed AAMVA field tags, human-readable labels, and values |
| **Dates** | DOB with calculated age, issue date, expiry date with valid/expired status |
| **Subfiles** | DL and Zxx subfile IDs with declared offsets/lengths and byte-range validity |
| **Raw** | First 400 characters of the decoded payload string |

### 5. Compare Two Cards

Click **↔ Compare** in the stats bar to open the comparison panel.

1. Select **Card A** from the first dropdown
2. Select **Card B** from the second dropdown
3. Click **Compare**

A full field-by-field diff table appears showing values from both cards and a ✅/❌ match indicator per field. If the two cards were encoded differently (binary bytes vs tilde-escape sequences), an orange warning banner highlights the encoding mode mismatch.

### 6. Export JSON

Click **↓ Export JSON** to download a complete machine-readable forensic report for all analysed cards as a timestamped `.json` file (e.g. `aamva-forensic-1715673421000.json`).

---

## Understanding the Results

### The 12-Point Authenticity Checklist

Each card is scored against 12 checks. The verdict is:
- **Authentic** if all 12 pass
- **Warning** if 1–2 fail
- **Failed** if 3 or more fail

| # | Check | What It Tests |
|---|---|---|
| 1 | Binary header bytes | First 4 bytes are exactly `0x40 0x0A 0x1E 0x0D` (`@ LF RS CR`) |
| 2 | IIN registered in AAMVA | The 6-digit IIN is in the official 71-entry AAMVA registry |
| 3 | IIN state matches DAJ field | IIN jurisdiction equals the DAJ (state) field value |
| 4 | AAMVA version 01–10 | Header version byte is in the valid 2000–2020 range |
| 5 | DL subfile present | The `DL` subfile designator exists in the payload |
| 6 | Subfile byte offsets valid | Declared offset+length in the header points to the correct byte position |
| 7 | All mandatory fields present | Version-specific mandatory field set is fully present |
| 8 | No field value errors | Sex, eye colour, truncation flags, height, ZIP pass enum validation |
| 9 | Expiry date in future | DBA expiry date is after today's date |
| 10 | DAK ZIP format correct | 9 digits + 2-char suffix = 11 chars total |
| 11 | DCF document discriminator | Document discriminator field is present |
| 12 | DCG country code valid | Country is `USA`, `CAN`, or `MEX` |

### Encoding Mode

AAMVA barcodes must contain raw binary bytes in the PDF417 symbol:
- `@ 0x0A 0x1E 0x0D ANSI ...` → **Binary** ✅ correct
- `@ ~0a ~1e ~0d ANSI ...` → **Tilde-Escape** ⚠️ anomaly

The tilde-escape anomaly occurs when bwip-js receives **lowercase** escape sequences (`~0a`, `~1e`, `~0d`). bwip-js only resolves **uppercase** `~0A`, `~1E`, `~0D` to actual binary bytes. Lowercase sequences pass through as 3 literal ASCII characters, causing DMV scanners to reject the barcode. The generator (`aam-project`) has been patched to use uppercase escapes.

### AAMVA Version Numbers Explained

| Version | Year | Notes |
|---|---|---|
| v01 | 2000 | Original standard, minimal field set, no subfile offset table |
| v02 | 2003 | Added additional mandatory fields |
| v03 | 2005 | Minor field additions |
| v04 | 2006 | Added DAD (middle name) |
| v05 | 2008 | Major update — added DDA, DDE, DDF, DDG, subfile offset table, eclevel=5 |
| v06 | 2011 | Additional fields |
| v07 | 2012 | Additional fields |
| v08 | 2009 | Most common version in currently-issued US cards |
| v09 | 2013 | Added fields |
| v10 | 2016 | Current AAMVA standard |

---

## AAMVA Standard Reference

### Payload Structure

```
Byte 0:     0x40  '@'  — Compliance indicator
Byte 1:     0x0A  LF   — File separator
Byte 2:     0x1E  RS   — Record separator
Byte 3:     0x0D  CR   — Segment terminator

ANSI IIIIIIVVJJNNXXXXXXXXXX  — Header
│         │││││└── Subfile directory entries (NN entries × "TTOOOOLLL")
│         ││││       TT = 2-char subfile type (DL, ZN, ZC, etc.)
│         ││││       OOOO = 4-digit offset
│         ││││       LLLL = 4-digit length
│         │││└─── NN = number of subfiles (2 digits)
│         ││└──── JJ = jurisdiction version (2 digits)
│         │└───── VV = AAMVA version (2 digits, 01–10)
│         └────── IIIIII = IIN (Issuer Identification Number, 6 digits)
└── literal "ANSI "

DL (subfile designator)
DAQ000044538262\n  — Field: tag (3 chars) + value + LF
DCSSmith\n
...
\r  (CR = end of DL subfile)

0x1D  GS  — Subfile separator (AAMVA §2.2)

ZN (jurisdiction subfile designator)
ZNA...\n
\r
```

### PDF417 Symbol Requirements

| Parameter | AAMVA Requirement | This Tool's Value |
|---|---|---|
| Symbology | PDF417 (ISO/IEC 15438) | PDF417 |
| Error correction | Level 5 (mandatory v5+) | eclevel=5 |
| X-dimension | 0.254–0.508 mm | ~0.38–0.45 mm at card DPI |
| Row height | ≥ 3× X-dimension | Met by template drawImage 4:1 box |
| Quiet zone | ≥ 2× X-module all sides | paddingleft/right/top/bottom=2 |
| Compaction | Binary recommended | forced `compaction=binary` |
| Columns | 1–30 (AAMVA no restriction) | 10 default; NC=13, CT/NV/GA/TX=8 |

---

## All 71 Registered IINs

| IIN | Jurisdiction | IIN | Jurisdiction | IIN | Jurisdiction |
|---|---|---|---|---|---|
| 636000 | AAMVA Test | 636024 | Montana | 636048 | Utah |
| 636001 | Alberta | 636025 | Missouri | 636049 | New Mexico |
| 636002 | British Columbia | 636026 | Tennessee | 636050 | Louisiana |
| 636003 | Manitoba | 636027 | Idaho | 636051 | Kentucky |
| 636004 | North Carolina | 636028 | South Dakota | 636052 | Wyoming |
| 636005 | Saskatchewan | 636029 | Oregon | 636053 | Massachusetts |
| 636006 | Yukon | 636030 | Wisconsin | 636054 | Vermont |
| 636007 | Ontario | 636031 | Indiana | 636055 | New Jersey |
| 636008 | Quebec | 636032 | Maryland | 636056 | Maine |
| 636009 | New Brunswick | 636033 | Washington | 636057 | South Carolina |
| 636010 | Florida | 636034 | Connecticut | 636058 | North Dakota |
| 636011 | Hawaii | 636035 | Iowa | 636059 | DC |
| 636012 | Newfoundland | 636036 | Delaware | 636060 | Alaska |
| 636013 | Nova Scotia | 637037 | Mississippi | 636061 | Alabama |
| 636014 | California | 636038 | Oklahoma | 636062 | Prince Edward Island |
| 636015 | Texas | 636039 | New Hampshire | 636063 | American Samoa |
| 636016 | Nebraska | 636040 | Illinois | 636064 | Guam |
| 636017 | Kansas | 636041 | Nevada | 636065 | US Virgin Islands |
| 636018 | West Virginia | 636042 | Virginia | 636066 | Puerto Rico |
| 636019 | Michigan | 636043 | Arkansas | 636067 | Northwest Territories |
| 636020 | Colorado | 636044 | Georgia | 636068 | Nunavut |
| 636021 | Ohio | 636045 | Pennsylvania | 636069 | Mexico |
| 636022 | Minnesota | 636046 | Arizona | 636070 | US State Dept |
| 636023 | New York | 636047 | Rhode Island | 636071 | AAMVA National |

---

## Field Reference

### Mandatory Fields by AAMVA Version

| Field | Label | v1 | v2 | v3 | v4 | v5+ |
|---|---|---|---|---|---|---|
| DAQ | Driver License Number | ✅ | ✅ | ✅ | ✅ | ✅ |
| DCS | Last Name | ✅ | ✅ | ✅ | ✅ | ✅ |
| DAC | First Name | ✅ | ✅ | ✅ | ✅ | ✅ |
| DAD | Middle Name | — | — | — | ✅ | ✅ |
| DBB | Date of Birth | ✅ | ✅ | ✅ | ✅ | ✅ |
| DBA | Expiry Date | ✅ | ✅ | ✅ | ✅ | ✅ |
| DBD | Issue Date | ✅ | ✅ | ✅ | ✅ | ✅ |
| DBC | Sex | ✅ | ✅ | ✅ | ✅ | ✅ |
| DAU | Height | ✅ | ✅ | ✅ | ✅ | ✅ |
| DAY | Eye Colour | ✅ | ✅ | ✅ | ✅ | ✅ |
| DAG | Street Address | ✅ | ✅ | ✅ | ✅ | ✅ |
| DAI | City | ✅ | ✅ | ✅ | ✅ | ✅ |
| DAJ | State/Province | ✅ | ✅ | ✅ | ✅ | ✅ |
| DAK | ZIP/Postal Code | ✅ | ✅ | ✅ | ✅ | ✅ |
| DCA | Vehicle Class | — | — | — | — | ✅ |
| DCB | Restrictions | — | — | — | — | ✅ |
| DCD | Endorsements | — | — | — | — | ✅ |
| DCF | Document Discriminator | — | — | — | — | ✅ |
| DCG | Country ID | — | — | — | — | ✅ |
| DDA | Compliance Type | — | — | — | — | ✅ |
| DDE | Last Name Truncation | — | — | — | — | ✅ |
| DDF | First Name Truncation | — | — | — | — | ✅ |
| DDG | Middle Name Truncation | — | — | — | — | ✅ |

### Enum Field Values

| Field | Valid Values | Meaning |
|---|---|---|
| **DBC** (Sex) | `1` | Male |
| | `2` | Female |
| | `9` | Not specified |
| **DDA** (Compliance) | `F` | Compliant (REAL ID) |
| | `N` | Not compliant |
| | `U` | Unknown |
| **DDE/DDF/DDG** (Truncation) | `N` | Not truncated |
| | `T` | Truncated |
| | `U` | Unknown |
| **DAY** (Eye Colour) | `BLK BLU BRO GRY GRN HAZ MAR PNK DIC UNK` | Standard AAMVA codes |
| **DAZ** (Hair Colour) | `BAL BLK BLN BRO GRY RED SDY WHI UNK` | Standard AAMVA codes |
| **DAU** (Height) | `NNN in` or `NNN cm` | e.g. `074 in` or `186 cm` |
| **DAK** (ZIP) | 9 digits + 2-char suffix | e.g. `272622119  ` (11 chars total) |

---

## Troubleshooting

### "Could not decode barcode from image"

The image barcode was not readable by any decoder. Try:

1. **Increase image resolution** — scan at ≥ 300 DPI, minimum 1000px wide
2. **Improve contrast** — ensure the barcode is not washed out or over-exposed
3. **Check orientation** — the barcode should be horizontal, not rotated
4. **Verify it is a PDF417** — the tool only decodes PDF417 (the 2D barcode on the back, not the 1D barcode strip)
5. **Try a different image format** — convert to PNG if JPEG compression is destroying fine barcode detail

The tool tries three preprocessing strategies automatically: binary threshold, contrast enhancement, and colour inversion. If all three fail, the image quality is likely too low.

### "zbarimg: command not found"

Install zbar-tools:
```bash
sudo apt-get install -y zbar-tools libzbar0   # Ubuntu/Debian/WSL
brew install zbar                              # macOS
```

### Server not accessible at localhost:8000

- Confirm `app.py` is still running (check the terminal for errors)
- Try `http://127.0.0.1:8000` instead of `localhost`
- Check if something else is using port 8000: `lsof -i :8000`
- Change the port in `app.py` if needed: `PORT = 8080`

### "ModuleNotFoundError: No module named 'PIL'"

The virtual environment may not be activated:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### All fields show "MISSING" in the verdict

The barcode decoded but the AAMVA payload structure is malformed. Check the **Raw** tab — if the decoded string does not begin with `@ LF RS CR ANSI`, the image decoded a different barcode type (e.g., QR code, Code 128) rather than the PDF417 DL barcode.

### IIN shows "UNKNOWN IIN"

The 6-digit IIN in the payload is not in the AAMVA registry. This is a strong indicator that the barcode data is either:
- From a test/training card (IIN `636000` = AAMVA Test)
- From a non-AAMVA jurisdiction
- Corrupted or fabricated

---

## Development Notes

### File Structure

```
aamva_forensic.py    ← All forensic logic; safe to import from app.py or CLI
app.py               ← HTTP wrapper only; no forensic logic here
templates/index.html ← Self-contained UI; all CSS and JS inline
requirements.txt     ← Pinned: Pillow, pdf417decoder
```

### Adding a New State to the IIN Map

Open `aamva_forensic.py` and add an entry to `AAMVA_IIN_MAP`:

```python
AAMVA_IIN_MAP: dict[str, str] = {
    ...
    '636XXX': 'State Name',
    ...
}
```

### Adding a New Mandatory Field for a Future AAMVA Version

Update `AAMVA_MANDATORY_FIELDS` in `aamva_forensic.py`:

```python
AAMVA_MANDATORY_FIELDS: dict[int, list[str]] = {
    ...
    11: [...existing v10 fields..., 'NEW_FIELD_TAG'],
}
```

### Running Forensics from the CLI (Advanced)

The web UI is the recommended interface, but the CLI mode is still available:

```bash
# With real card images
python3 aamva_forensic.py --card1 card1.jpg --card2 card2.jpg

# With embedded raw test strings (no images needed)
python3 aamva_forensic.py --raw-only
```

### Running Tests

If you add unit tests to `__tests__/`, run them with:

```bash
python3 -m pytest __tests__/ -v
```

Key functions to test: `escapeAAMVAForBwipjs()`, `parse_subfiles()`, `validate_subfile_delimiters()`.

---

## Changelog

### v2.0 (May 2026)
- Added full browser-based localhost web UI (`app.py` + `templates/index.html`)
- Multi-file batch upload with drag-and-drop
- Per-file result cards with Verdict / Fields / Dates / Subfiles / Raw tabs
- Side-by-side compare mode with encoding-mode mismatch detection
- JSON export of full forensic results
- Expanded IIN map from 3 states to all 71 registered AAMVA jurisdictions
- Added AAMVA v01–v10 full version range validation (was v08 only)
- Added mandatory field check per AAMVA version (v1 minimal → v5+ full 22-field set)
- Added full subfile byte-range offset validation
- Added DL subfile designator presence check
- Added multi-format date parsing (MMDDYYYY, YYYYMMDD, MMYYYY)
- Added v1–v4 header format support (no offset table)
- Added field value enum validation: sex, eye, hair, truncation, compliance, ZIP, height
- Replaced NC-hardcoded `authenticity_verdict()` with 14-point state-agnostic checklist
- Added jurisdiction subfile parser for all Zxx state codes (was ZN/NC only)
- Added encoding mode mismatch flag in card comparison
- Fixed `DDB` field label (was "Document Issue Revision Date"; correct: "Under-18 Until / Prior Issue Date")

### v1.0 (Initial)
- CLI-only forensic tool
- NC, CA, NY IIN support only
- v08 AAMVA version only
- Basic field parsing and NC-specific verdict

---

*Built for the `aam-project` forensic pipeline. Companion generator lives at [ultracreative00/aam-project](https://github.com/ultracreative00/aam-project).*
