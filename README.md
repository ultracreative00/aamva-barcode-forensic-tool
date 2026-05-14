# AAMVA PDF417 Barcode Forensic Tool

Decode, parse and forensically verify AAMVA v8 PDF417 barcodes from driver license card images.

## What This Does

1. **Decodes** PDF417 barcodes from `card1.jpg` / `card2.jpg` using `pdf417decoder`
2. **Parses** every AAMVA field (DCS, DAC, DAD, DBB, DBA, DAQ …)
3. **Compares** both cards side-by-side, flagging every difference
4. **Forensic deep-dive**: header bytes, control-char encoding mode, date math, DCK audit number, ZN jurisdiction subfile
5. **Authenticity verdict**: binary vs ~XX escape encoding, AAMVA structural compliance

## Setup

```bash
pip install -r requirements.txt
```

## Run

```bash
# Place card1.jpg and card2.jpg in this directory, then:
python aamva_forensic.py

# Or pass paths explicitly:
python aamva_forensic.py --card1 /path/to/card1.jpg --card2 /path/to/card2.jpg

# Skip image decoding (use raw strings directly):
python aamva_forensic.py --raw-only
```

## Output Sections

| Section | What You See |
|---|---|
| DECODE ATTEMPT | zbarimg + pdf417decoder results, return codes, raw bytes |
| RAW OUTPUT | Full `repr()` of decoded bytes from each card |
| HEADER BYTES | Byte-by-byte header analysis (`@`, LF, RS, CR) |
| AAMVA VERSION | IIN, AAMVA version, subfile count, offsets |
| DATE VALIDATION | DOB, issue, expiry, age, term length |
| IDENTITY FIELDS | Name, height, eye/hair colour, address, ZIP |
| LICENSE FIELDS | Class, restrictions, endorsements, audit number |
| ZN SUBFILE | NC jurisdiction-specific extension fields |
| FIELD COMPARISON | Every field diffed card1 vs card2 |
| AUTHENTICITY VERDICT | PASS / FAIL with per-check reasons |

## Encoding Mode — Why Card2 Failed

Card1 contains proper binary control characters:
```
0x40 0x0A 0x1E 0x0D ANSI 636004...
```
Card2 contained `~XX` ASCII escape sequences instead of binary bytes:
```
@~0a~1e~0d ANSI 636004...
```
bwip-js only resolves `~XX` sequences when the hex digits are **UPPERCASE** (`~1E` ✅, `~1e` ❌).
Lowercase escape sequences pass through as literal ASCII — causing scanners to reject the symbol.
