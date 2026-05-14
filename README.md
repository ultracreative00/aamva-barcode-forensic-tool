# AAMVA PDF417 Barcode Forensic Tool  v2.0

Decode, parse and forensically verify AAMVA v1–v10 PDF417 barcodes from driver license images.
Supports **all 50 US states + DC + territories + Canadian provinces** (71 IINs).

## What This Does

| Step | What Happens |
|---|---|
| **Decode** | zbarimg (direct → 3 preprocessing strategies) → pdf417decoder fallback |
| **Parse** | Full subfile directory parser — validates DL/ZN/Zxx byte offsets |
| **Field validation** | Mandatory fields per AAMVA version, enum values, date formats, ZIP format |
| **Forensics** | Header bytes, IIN registry, version range, subfile offsets, DCK audit number |
| **Compare** | Side-by-side field diff with encoding-mode mismatch flagged explicitly |
| **Verdict** | 14-point authenticity checklist, state-agnostic |

## Setup

```bash
pip install -r requirements.txt
```

## Run

```bash
# With real card images:
python aamva_forensic.py
python aamva_forensic.py --card1 /path/to/a.jpg --card2 /path/to/b.jpg

# Without images (uses embedded NC v8 raw strings):
python aamva_forensic.py --raw-only
```

## AAMVA Version Support

| Version | Year | Notes |
|---|---|---|
| v01 | 2000 | Minimal fields, no subfile offset table |
| v02 | 2003 | Added mandatory fields |
| v03 | 2005 | |
| v04 | 2006 | Added DAD (middle name) |
| v05 | 2008 | Added DDA/DDE/DDF/DDG, offset table |
| v06 | 2011 | |
| v07 | 2012 | |
| v08 | 2009 | Currently most common US state |
| v09 | 2013 | |
| v10 | 2016 | Current AAMVA standard |

## Encoding Mode Detection (Card1 vs Card2 Explained)

```
Card1 (correct):  @ 0x0A 0x1E 0x0D ANSI ...  ← binary bytes in barcode symbol
Card2 (broken):   @ ~0a  ~1e  ~0d  ANSI ...  ← ASCII text escape sequences
```

bwip-js only resolves **UPPERCASE** `~1E` → `0x1E`.  
Lowercase `~1e` passes through as 3 literal bytes — DMV scanners reject it.

## All 71 Registered AAMVA IINs Covered

Every US state, DC, territory, Canadian province, and AAMVA special IIN is in the registry.
Unknown IINs are flagged as `❌ UNKNOWN IIN` in the verdict.
