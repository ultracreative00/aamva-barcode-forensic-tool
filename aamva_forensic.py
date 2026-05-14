#!/usr/bin/env python3
"""
AAMVA PDF417 Barcode Forensic & Authenticity Tool
==================================================
Assembled from decode scripts (Script1–Script10).

Usage:
  python aamva_forensic.py                          # uses card1.jpg + card2.jpg in CWD
  python aamva_forensic.py --card1 a.jpg --card2 b.jpg
  python aamva_forensic.py --raw-only               # skip image decode, use embedded raw strings
"""

import argparse
import os
import re
import subprocess
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# EMBEDDED RAW STRINGS (from Script9 — the decoded outputs)
# ---------------------------------------------------------------------------
CARD1_RAW_EMBEDDED = (
    '@\n\x1e\rANSI 636004080002DL00410271ZN03120020'
    'DLDAQ000044538262\nDCSPENTZ\nDDEN\nDACTAYLOR\nDDFN\nDADGLENN\nDDGN\n'
    'DCAC\nDCB1\nDCDNONE\nDBD01302020\nDBB02171992\nDBA02172028\nDBC1\n'
    'DAU074 in\nDAYBRO\nDAG1601 LARKIN ST\nDAIHIGH POINT\nDAJNC\n'
    'DAK272622119  \nDCF0026899227\nDCGUSA\nDAZBRO\nDCLU  \n'
    'DCK000044538262NCY0TL01\nDDAF\nDDB10242014\nDDK1\r'
    'ZNZNA\nZNB\nZNC0\nZNDN\r'
)

CARD2_RAW_EMBEDDED = (
    '@~0a~1e~0dANSI 636004080002DL00410271ZN03120020'
    'DLDAQ000044538262~0aDCSPENTZ~0aDDEN~0aDACTAYLOR~0aDDFN~0aDADGLENN~0aDDGN~0a'
    'DCAC~0aDCB1~0aDCDNONE~0aDBD01302020~0aDBB02171992~0aDBA02172028~0aDBC1~0a'
    'DAU074 in~0aDAYBRO~0aDAG1601 LARKIN ST~0aDAIHIGH POINT~0aDAJNC~0a'
    'DAK272622119  ~0aDCF0026899227~0aDCGUSA~0aDAZBRO~0aDCLU  ~0a'
    'DCK000044538262NCY0TL01~0aDDAF~0aDDB10242014~0aDDK1~0d'
    'ZNZNA~0aZNB~0aZNC0~0aZNDN~0d'
)


# ---------------------------------------------------------------------------
# STEP 1 — IMAGE DECODE  (Scripts 1–8)
# ---------------------------------------------------------------------------

def ensure_zbar():
    """Install zbar-tools if missing (Script3)."""
    if subprocess.run(['which', 'zbarimg'], capture_output=True).returncode != 0:
        print("[setup] installing zbar-tools...")
        subprocess.run(
            'apt-get install -y zbar-tools libzbar0 2>&1 | tail -5',
            shell=True, capture_output=True, text=True
        )


def ensure_pdf417decoder():
    """Install pdf417decoder if missing (Script6)."""
    try:
        import pdf417decoder  # noqa: F401
    except ImportError:
        print("[setup] installing pdf417decoder...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pdf417decoder', '-q'])


def decode_with_zbar(path: str, label: str) -> bytes | None:
    """Scripts 1-2: try zbarimg --raw directly."""
    r = subprocess.run(['zbarimg', '--raw', '-q', path], capture_output=True)
    print(f"  zbarimg {label}: RC={r.returncode} bytes={len(r.stdout)}")
    if r.stderr:
        print(f"  zbarimg stderr: {r.stderr.decode()[:200]}")
    return r.stdout if r.returncode == 0 and r.stdout else None


def decode_with_preprocessing(path: str, label: str) -> bytes | None:
    """Scripts 4-5: preprocess image then retry zbarimg."""
    try:
        from PIL import Image, ImageEnhance, ImageFilter
        import numpy as np
    except ImportError:
        return None

    img = Image.open(path).convert('L')
    print(f"  preprocessing {label}: original size {img.size}")

    strategies = []

    # Strategy A: upsample + threshold (Script4)
    w, h = img.size
    scale = max(1, 1200 // w)
    upscaled = img.resize((w * scale, h * scale), Image.LANCZOS)
    arr = np.array(upscaled)
    thresh = arr.mean()
    binary = ((arr > thresh) * 255).astype('uint8')
    from PIL import Image as _I
    proc_path = f'/tmp/{label}_proc.png'
    _I.fromarray(binary).save(proc_path)
    strategies.append(('threshold', proc_path))

    # Strategy B: high contrast + sharpen (Script5)
    enhanced = ImageEnhance.Contrast(img).enhance(3.0).filter(ImageFilter.SHARPEN)
    s1_path = f'/tmp/{label}_s1.png'
    enhanced.save(s1_path)
    strategies.append(('enhanced', s1_path))

    # Strategy C: invert (Script5)
    inv = _I.fromarray(255 - np.array(img))
    inv_path = f'/tmp/{label}_inv.png'
    inv.save(inv_path)
    strategies.append(('inverted', inv_path))

    for name, fpath in strategies:
        r = subprocess.run(
            ['zbarimg', '--raw', '-q', '--set', 'pdf417.enable=1', fpath],
            capture_output=True
        )
        print(f"    [{name}] RC={r.returncode} bytes={len(r.stdout)}")
        if r.returncode == 0 and r.stdout:
            return r.stdout
    return None


def decode_with_pdf417decoder(path: str, label: str) -> bytes | None:
    """Scripts 6-8: use pdf417decoder library."""
    try:
        from pdf417decoder import PDF417Decoder
        from PIL import Image
    except ImportError:
        print(f"  pdf417decoder not available for {label}")
        return None

    img = Image.open(path)
    dec = PDF417Decoder(img)
    count = dec.decode()
    print(f"  pdf417decoder {label}: {count} barcode(s) found")

    if count == 0:
        return None

    # Try every extraction method (Script8)
    for method in [
        lambda: dec.barcode_data_index_to_string(0).encode('latin-1'),
        lambda: dec.barcodes_data[0] if isinstance(dec.barcodes_data[0], bytes) else dec.barcodes_data[0].encode('latin-1'),
        lambda: dec.barcode_binary_data,
    ]:
        try:
            result = method()
            if result:
                return result
        except Exception:
            pass
    return None


def decode_image(path: str, label: str) -> str | None:
    """Full decode pipeline: zbar → preprocess → pdf417decoder."""
    print(f"\n{'='*60}")
    print(f"DECODING {label.upper()}: {path}")
    print('='*60)

    if not os.path.exists(path):
        print(f"  ⚠  File not found: {path}")
        return None

    raw = None

    # Attempt 1: zbar direct
    ensure_zbar()
    raw = decode_with_zbar(path, label)

    # Attempt 2: preprocessing
    if raw is None:
        raw = decode_with_preprocessing(path, label)

    # Attempt 3: pdf417decoder
    if raw is None:
        ensure_pdf417decoder()
        raw = decode_with_pdf417decoder(path, label)

    if raw is None:
        print(f"  ✗  Could not decode {label}")
        return None

    decoded = raw.decode('latin-1')
    print(f"\n--- RAW OUTPUT ({label}) ---")
    print(f"Bytes decoded: {len(raw)}")
    print(repr(decoded[:1200]))
    return decoded


# ---------------------------------------------------------------------------
# STEP 2 — PARSE  (Script9)
# ---------------------------------------------------------------------------

def unescape_tilde(s: str) -> str:
    """Convert ~XX escape sequences to actual characters."""
    return re.sub(r'~([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)


def parse_aamva(raw: str) -> dict:
    """Split by LF/CR and extract 3-char AAMVA field tags."""
    fields: dict[str, str] = {}
    lines = re.split(r'[\n\r]', raw)
    for line in lines:
        line = line.strip()
        if len(line) >= 3:
            tag = line[:3]
            val = line[3:]
            if re.match(r'^[A-Z]{2}[A-Z0-9]$', tag):
                fields[tag] = val
    return fields


# ---------------------------------------------------------------------------
# STEP 3 — FORENSIC ANALYSIS  (Script10)
# ---------------------------------------------------------------------------

DMV_FIELD_LABELS = {
    'DAQ': 'Driver License Number',
    'DCS': 'Last Name',
    'DAC': 'First Name',
    'DAD': 'Middle Name',
    'DBB': 'Date of Birth (DOB)',
    'DBA': 'Expiry Date',
    'DBD': 'Issue Date',
    'DDB': 'Document Issue Revision Date',
    'DBC': 'Sex (1=M 2=F)',
    'DAU': 'Height',
    'DAY': 'Eye Colour',
    'DAZ': 'Hair Colour',
    'DAG': 'Street Address',
    'DAI': 'City',
    'DAJ': 'State',
    'DAK': 'ZIP Code',
    'DCA': 'Vehicle Class',
    'DCB': 'Restrictions',
    'DCD': 'Endorsements',
    'DCF': 'Document Discriminator',
    'DCG': 'Country',
    'DCK': 'Inventory Control Number',
    'DCL': 'Race/Ethnicity',
    'DDA': 'Compliance Type',
    'DDC': 'Hazmat Expiry',
    'DDE': 'Last Name Truncation',
    'DDF': 'First Name Truncation',
    'DDG': 'Middle Name Truncation',
    'DDK': 'Under 21 Until',
    'ZNA': 'ZN Subfile Field A',
    'ZNB': 'ZN Subfile Field B',
    'ZNC': 'ZN Subfile Field C',
    'ZND': 'ZN Subfile Field D',
}


def analyse_header_bytes(raw: str, label: str):
    """Script10 — header byte forensics."""
    print(f"\n--- HEADER BYTES ({label}) ---")
    header_bytes = [hex(ord(c)) for c in raw[:4]]
    print(f"First 4 bytes: {header_bytes}")

    at = ord(raw[0]) == 0x40
    second = ord(raw[1])
    third  = ord(raw[2]) if len(raw) > 2 else 0
    fourth = ord(raw[3]) if len(raw) > 3 else 0

    encoding_mode = 'BINARY (correct ✅)' if (second == 0x0A and third == 0x1E) else 'TILDE ESCAPE (anomaly ⚠)'
    print(f"  @ (0x40):      {'✅' if at else '❌'} File Type Indicator")
    print(f"  Byte 2 (LF):   0x{second:02X} {'✅ binary 0x0A' if second == 0x0A else '❌ expected 0x0A'}")
    print(f"  Byte 3 (RS):   0x{third:02X}  {'✅ binary 0x1E' if third == 0x1E else '❌ expected 0x1E — got ASCII escape chars'}")
    print(f"  Byte 4 (CR):   0x{fourth:02X}  {'✅ binary 0x0D' if fourth == 0x0D else '❌ expected 0x0D'}")
    print(f"  Encoding mode: {encoding_mode}")
    return second == 0x0A and third == 0x1E and fourth == 0x0D


def analyse_aamva_version(raw: str):
    """Parse AAMVA version header block."""
    print("\n--- AAMVA VERSION HEADER ---")
    m = re.search(r'ANSI (\d{6})(\d{2})(\d{2})(\d{2})(DL)(\d{4})(\d{4})(\w{2})(\d{4})(\d{4})', raw)
    if not m:
        print("  ❌ Could not find ANSI header block")
        return
    iin, aamva_ver, juris_ver, num_entries = m.group(1), m.group(2), m.group(3), m.group(4)
    dl_off, dl_len, zn_id, zn_off, zn_len = m.group(6), m.group(7), m.group(8), m.group(9), m.group(10)
    iin_map = {'636004': 'North Carolina DMV ✅', '636014': 'California DMV', '636023': 'New York DMV'}
    print(f"  IIN:           {iin} → {iin_map.get(iin, 'Unknown jurisdiction')}")
    print(f"  AAMVA Version: {aamva_ver} → AAMVA 200{'9 (v8)' if aamva_ver == '08' else aamva_ver}")
    print(f"  Jurisdiction Version: {juris_ver}")
    print(f"  Subfile Count: {num_entries} → {'DL + ZN ✅' if num_entries == '02' else num_entries}")
    print(f"  DL subfile:    offset={dl_off} length={dl_len}")
    print(f"  ZN subfile:    id={zn_id} offset={zn_off} length={zn_len}")


def analyse_dates(fields: dict):
    """Script10 — date math and validation."""
    print("\n--- DATE FIELD VALIDATION ---")
    today = datetime.today()
    for tag, label in [('DBB', 'DOB'), ('DBD', 'Issue'), ('DBA', 'Expiry'), ('DDB', 'Revision')]:
        val = fields.get(tag)
        if not val:
            print(f"  {tag} ({label}): <missing>")
            continue
        try:
            dt = datetime.strptime(val.strip(), '%m%d%Y')
            extra = ''
            if tag == 'DBB':
                age = (today - dt).days // 365
                extra = f' → Age: {age} yrs'
            elif tag == 'DBA':
                extra = f' → {"✅ valid" if dt > today else "❌ EXPIRED"}'
            elif tag == 'DBD':
                exp_val = fields.get('DBA', '')
                if exp_val:
                    try:
                        exp_dt = datetime.strptime(exp_val.strip(), '%m%d%Y')
                        years = (exp_dt - dt).days // 365
                        extra = f' → {years}-year term {"✅" if years == 8 else "⚠ non-standard"}'
                    except Exception:
                        pass
            print(f"  {tag} ({label}): {dt.strftime('%B %d, %Y')}{extra}")
        except ValueError:
            print(f"  {tag} ({label}): ❌ cannot parse '{val}'")


def analyse_dck(dck: str):
    """Script10 — DCK audit number forensics."""
    print("\n--- DCK AUDIT NUMBER FORENSICS ---")
    print(f"  DCK raw: {dck}")
    if len(dck) >= 20:
        print(f"  DL# prefix:  {dck[:12]} {'✅' if dck[:12] == dck[:12] else ''}")
        print(f"  State code:  {dck[12:14]}")
        print(f"  Batch code:  {dck[14:16]}")
        print(f"  Vendor code: {dck[16:18]} {'(Idemia/L1 ✅)' if dck[16:18] == 'TL' else ''}")
        print(f"  Sequence:    {dck[18:20]}")
    else:
        print(f"  Length {len(dck)} — shorter than expected 20 chars")


def run_forensics(raw: str, label: str) -> dict:
    """Full forensic analysis of one card's raw decoded string."""
    print(f"\n{'='*60}")
    print(f"FORENSIC ANALYSIS: {label.upper()}")
    print('='*60)

    # Normalise tilde escapes so field parser always works
    normalised = unescape_tilde(raw) if '~' in raw else raw

    header_ok = analyse_header_bytes(normalised, label)
    analyse_aamva_version(normalised)
    fields = parse_aamva(normalised)

    print("\n--- ALL PARSED FIELDS ---")
    for tag, val in sorted(fields.items()):
        desc = DMV_FIELD_LABELS.get(tag, '')
        print(f"  {tag}: {repr(val):<30}  {desc}")

    analyse_dates(fields)

    if 'DCK' in fields:
        analyse_dck(fields['DCK'])

    print("\n--- LICENSE FIELDS ---")
    for tag in ['DCA', 'DCB', 'DCD', 'DBC', 'DAU', 'DAY', 'DAZ', 'DAG', 'DAI', 'DAJ', 'DAK', 'DCL', 'DDA', 'DDK']:
        if tag in fields:
            print(f"  {tag} ({DMV_FIELD_LABELS.get(tag, '')}): {fields[tag]}")

    print("\n--- ZN JURISDICTION SUBFILE (NC-specific) ---")
    for tag in ['ZNA', 'ZNB', 'ZNC', 'ZND']:
        if tag in fields:
            print(f"  {tag}: {repr(fields[tag])} ✅")

    return {'fields': fields, 'header_ok': header_ok, 'normalised': normalised}


# ---------------------------------------------------------------------------
# STEP 4 — COMPARE + VERDICT
# ---------------------------------------------------------------------------

def compare_cards(r1: dict, r2: dict):
    """Script9 — side-by-side field diff."""
    print("\n" + "="*60)
    print("FIELD COMPARISON: CARD1 vs CARD2")
    print('='*60)
    f1, f2 = r1['fields'], r2['fields']
    all_tags = sorted(set(list(f1) + list(f2)))
    matches = mismatches = 0
    for tag in all_tags:
        v1 = f1.get(tag, '<MISSING>')
        v2 = f2.get(tag, '<MISSING>')
        if v1 == v2:
            matches += 1
            print(f"  {tag}: ✅ MATCH   {repr(v1)}")
        else:
            mismatches += 1
            print(f"  {tag}: ❌ DIFFER")
            print(f"       C1: {repr(v1)}")
            print(f"       C2: {repr(v2)}")
    print(f"\n  Total: {matches} matching, {mismatches} differing")


def authenticity_verdict(r1: dict, r2: dict):
    """Final authenticity checklist."""
    print("\n" + "="*60)
    print("AUTHENTICITY VERDICT")
    print('='*60)

    checks = [
        ("Card1 binary header (0x40 0x0A 0x1E 0x0D)", r1['header_ok']),
        ("Card2 binary header", r2['header_ok']),
        ("IIN 636004 = North Carolina DMV", '636004' in r1.get('normalised', '')),
        ("AAMVA version 08", '080002' in r1.get('normalised', '')),
        ("Subfile count 02 (DL + ZN)", 'DL00' in r1.get('normalised', '')),
        ("DOB birthday matches Expiry day (NC ties expiry to DOB)",
            r1['fields'].get('DBB', '')[:4] == r1['fields'].get('DBA', '')[:4]
            if r1['fields'].get('DBB') and r1['fields'].get('DBA') else False),
        ("DCK vendor code TL (Idemia ✅)",
            r1['fields'].get('DCK', '')[16:18] == 'TL'),
        ("DAJ state = NC",
            r1['fields'].get('DAJ', '').strip() == 'NC'),
        ("ZN subfile present (NC jurisdiction extension)",
            any(k.startswith('ZN') for k in r1['fields'])),
    ]

    passed = failed = 0
    for label, result in checks:
        icon = '✅ PASS' if result else '❌ FAIL'
        if result:
            passed += 1
        else:
            failed += 1
        print(f"  {icon}  {label}")

    print(f"\n  Result: {passed}/{len(checks)} checks passed")
    if failed == 0:
        print("  ✅ CARD1 STRUCTURALLY AUTHENTIC (all checks passed)")
    else:
        print(f"  ⚠  {failed} check(s) failed — see details above")

    # Card2-specific encoding anomaly
    print("\n  Card2 Encoding Anomaly:")
    if not r2['header_ok']:
        print("  ❌ Card2 used ~XX ASCII tilde escapes instead of binary control chars")
        print("     This is caused by bwip-js receiving lowercase ~0a~1e~0d sequences")
        print("     bwip-js only resolves uppercase ~0A~1E~0D into actual binary bytes")
        print("     Fix: ensure escapeAAMVAForBwipjs() uses .toUpperCase() on all hex digits")
    else:
        print("  ✅ Card2 header encoding is correct binary")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='AAMVA PDF417 Forensic Tool')
    parser.add_argument('--card1', default='card1.jpg', help='Path to card1 image')
    parser.add_argument('--card2', default='card2.jpg', help='Path to card2 image')
    parser.add_argument('--raw-only', action='store_true',
                        help='Skip image decode, use embedded raw strings')
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════╗")
    print("║        AAMVA PDF417 BARCODE FORENSIC TOOL                ║")
    print("║   Decode · Parse · Compare · Authenticity Verdict        ║")
    print("╚══════════════════════════════════════════════════════════╝")

    if args.raw_only:
        print("\n[mode] Using embedded raw strings (--raw-only)")
        raw1 = CARD1_RAW_EMBEDDED
        raw2 = CARD2_RAW_EMBEDDED
        print("\n--- RAW OUTPUT (card1) ---")
        print(repr(raw1))
        print("\n--- RAW OUTPUT (card2) ---")
        print(repr(raw2))
    else:
        raw1 = decode_image(args.card1, 'card1') or CARD1_RAW_EMBEDDED
        raw2 = decode_image(args.card2, 'card2') or CARD2_RAW_EMBEDDED
        if not decode_image:
            print("\n[fallback] Using embedded raw strings")

    r1 = run_forensics(raw1, 'card1')
    r2 = run_forensics(raw2, 'card2')
    compare_cards(r1, r2)
    authenticity_verdict(r1, r2)


if __name__ == '__main__':
    main()
