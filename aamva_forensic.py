#!/usr/bin/env python3
"""
AAMVA PDF417 Barcode Forensic & Authenticity Tool  v3.1
========================================================
Full AAMVA DL/ID Card Design Standard 2000–2020 compliance.
Supports AAMVA versions 01–10, all 50 states + DC + territories.

Reference Benchmark: NC AAMVA v08 barcode (32 fields, binary header).
Tilde-escape encoding is treated as a hard FAIL — authentic barcodes
MUST contain raw binary bytes 0x40 0x0A 0x1E 0x0D as the header.

KEY FIX v3.1:
  - analyse_header_bytes() is now called on the ORIGINAL raw string,
    NOT the tilde-unescaped (normalised) version.
  - This ensures tilde-escape is always detected as header_ok=False,
    so check #1 in authenticity_verdict() always FAILs for Card2.
  - Previously, unescape_tilde() was applied before the header check,
    making ~0a~1e~0d look like binary bytes → incorrect PASS.

Usage:
  python aamva_forensic.py                          # card1.jpg + card2.jpg in CWD
  python aamva_forensic.py --card1 a.jpg --card2 b.jpg
  python aamva_forensic.py --raw-only               # use embedded raw strings
"""

import argparse
import os
import re
import subprocess
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# AAMVA IIN TABLE — all 71 registered jurisdictions
# ---------------------------------------------------------------------------
AAMVA_IIN_MAP: dict[str, str] = {
    '636000': 'AAMVAtest', '636001': 'Alberta', '636002': 'British Columbia',
    '636003': 'Manitoba',  '636004': 'North Carolina', '636005': 'Saskatchewan',
    '636006': 'Yukon',     '636007': 'Ontario',        '636008': 'Quebec',
    '636009': 'New Brunswick', '636010': 'Florida',    '636011': 'Hawaii',
    '636012': 'Newfoundland',  '636013': 'Nova Scotia', '636014': 'California',
    '636015': 'Texas',    '636016': 'Nebraska',  '636017': 'Kansas',
    '636018': 'West Virginia', '636019': 'Michigan', '636020': 'Colorado',
    '636021': 'Ohio',     '636022': 'Minnesota',  '636023': 'New York',
    '636024': 'Montana',  '636025': 'Missouri',   '636026': 'Tennessee',
    '636027': 'Idaho',    '636028': 'South Dakota', '636029': 'Oregon',
    '636030': 'Wisconsin', '636031': 'Indiana',   '636032': 'Maryland',
    '636033': 'Washington', '636034': 'Connecticut', '636035': 'Iowa',
    '636036': 'Delaware', '636037': 'Mississippi', '636038': 'Oklahoma',
    '636039': 'New Hampshire', '636040': 'Illinois', '636041': 'Nevada',
    '636042': 'Virginia', '636043': 'Arkansas',   '636044': 'Georgia',
    '636045': 'Pennsylvania', '636046': 'Arizona', '636047': 'Rhode Island',
    '636048': 'Utah',     '636049': 'New Mexico', '636050': 'Louisiana',
    '636051': 'Kentucky', '636052': 'Wyoming',    '636053': 'Massachusetts',
    '636054': 'Vermont',  '636055': 'New Jersey', '636056': 'Maine',
    '636057': 'South Carolina', '636058': 'North Dakota', '636059': 'DC',
    '636060': 'Alaska',   '636061': 'Alabama',    '636062': 'Prince Edward Island',
    '636063': 'American Samoa', '636064': 'Guam', '636065': 'US Virgin Islands',
    '636066': 'Puerto Rico',    '636067': 'Northwest Territories',
    '636068': 'Nunavut',  '636069': 'Mexico',     '636070': 'US State Dept',
    '636071': 'AAMVA National',
}

# ---------------------------------------------------------------------------
# AAMVA VERSION → mandatory DL fields
# ---------------------------------------------------------------------------
AAMVA_MANDATORY_FIELDS: dict[int, list[str]] = {
    1: ['DAQ','DCS','DAC','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK'],
    2: ['DAQ','DCS','DAC','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK'],
    3: ['DAQ','DCS','DAC','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK'],
    4: ['DAQ','DCS','DAC','DAD','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK'],
    5: ['DAQ','DCS','DAC','DAD','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK',
        'DCA','DCB','DCD','DCF','DCG','DDE','DDF','DDG'],
    6: ['DAQ','DCS','DAC','DAD','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK',
        'DCA','DCB','DCD','DCF','DCG','DDA','DDE','DDF','DDG'],
    7: ['DAQ','DCS','DAC','DAD','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK',
        'DCA','DCB','DCD','DCF','DCG','DDA','DDE','DDF','DDG'],
    8: ['DAQ','DCS','DAC','DAD','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK',
        'DCA','DCB','DCD','DCF','DCG','DDA','DDE','DDF','DDG'],
    9: ['DAQ','DCS','DAC','DAD','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK',
        'DCA','DCB','DCD','DCF','DCG','DDA','DDE','DDF','DDG'],
    10:['DAQ','DCS','DAC','DAD','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK',
        'DCA','DCB','DCD','DCF','DCG','DDA','DDE','DDF','DDG'],
}

# ---------------------------------------------------------------------------
# VALIDATION TABLES
# ---------------------------------------------------------------------------
VALID_TRUNCATION  = {'N', 'T', 'U'}
VALID_SEX         = {'1', '2', '9'}
VALID_COMPLIANCE  = {'F', 'N', 'U'}
VALID_EYE_CODES   = {'BLK','BLU','BRO','GRY','GRN','HAZ','MAR','PNK','DIC','UNK'}
VALID_HAIR_CODES  = {'BAL','BLK','BLN','BRO','GRY','RED','SDY','WHI','UNK'}
VALID_ORGAN_DONOR = {'0', '1'}
VALID_VETERAN     = {'1', '2', '9', ''}
VALID_RACE_CODES  = {'AI','AP','BK','H','O','U','W'}

DCK_VENDOR_MAP = {
    'TL': 'Idemia/L1',
    'DL': 'Digimarc',
    'HO': 'HID Global',
    'DM': 'DataCard',
    'PC': 'Polaroid',
    'DE': 'De La Rue',
    'AM': 'American Banknote',
    'GP': 'Giesecke+Devrient',
}

NC_ZN_FIELDS = {
    'ZNA': 'NC Replacement Indicator (blank=original)',
    'ZNB': 'NC Limited-Term Indicator (blank=full-term)',
    'ZNC': 'NC Under-21 Indicator (0=No, 1=Yes)',
    'ZND': 'NC Non-Resident CDL (N=not CDL, Y=CDL)',
    'ZNE': 'NC Selective Service (Y/N)',
    'ZNF': 'NC Veteran Indicator (Y/N)',
    'ZNG': 'NC Medical Indicator',
    'ZNH': 'NC Volunteer Fire/Rescue',
    'ZNI': 'NC Non-Compliant Reason',
    'ZNJ': 'NC Audit Number Suffix',
    'ZNK': 'NC Customer Sequence',
}

DMV_FIELD_LABELS: dict[str, str] = {
    'DAQ': 'Driver License / ID Number',
    'DCS': 'Last Name (Family Name)',
    'DAC': 'First Name (Given Name)',
    'DAD': 'Middle Name or Initial',
    'DBB': 'Date of Birth (MMDDYYYY)',
    'DBA': 'Document Expiry Date (MMDDYYYY)',
    'DBD': 'Document Issue Date (MMDDYYYY)',
    'DDB': 'Card Revision / Prior Issue Date (MMDDYYYY)',
    'DDH': 'Under 18 Until (MMDDYYYY)',
    'DDI': 'Under 19 Until (MMDDYYYY)',
    'DDJ': 'Under 21 Until (MMDDYYYY)',
    'DBC': 'Sex (1=Male, 2=Female, 9=Not Specified)',
    'DAU': 'Height (NNN in | NNN cm)',
    'DAY': 'Eye Colour (AAMVA 3-char code)',
    'DAZ': 'Hair Colour (AAMVA 3-char code)',
    'DAW': 'Weight (lbs)',
    'DAX': 'Weight Range',
    'DAG': 'Street Address Line 1',
    'DAH': 'Street Address Line 2',
    'DAI': 'City',
    'DAJ': 'State / Province Abbreviation',
    'DAK': 'ZIP / Postal Code (fixed 11 chars: 9 digits + 2 spaces)',
    'DCG': 'Country Identifier (USA/CAN/MEX)',
    'DCA': 'Vehicle Class',
    'DCB': 'Restriction Codes',
    'DCD': 'Endorsement Codes',
    'DCF': 'Document Discriminator (unique per document)',
    'DCK': 'Inventory Control Number / Audit Number (20 chars)',
    'DCL': 'Race / Ethnicity (3-char fixed-width)',
    'DDA': 'Compliance Type (F=Full, N=Non-compliant, U=Unknown)',
    'DDE': 'Last Name Truncation (N=No, T=Truncated, U=Unknown)',
    'DDF': 'First Name Truncation (N=No, T=Truncated, U=Unknown)',
    'DDG': 'Middle Name Truncation (N=No, T=Truncated, U=Unknown)',
    'DDC': 'Hazmat Endorsement Expiry Date',
    'DDK': 'Organ Donor Indicator (0=No, 1=Yes)',
    'DDL': 'Veteran Indicator (1=Vet, 2=Non-vet, 9=N/A)',
    'DCH': 'Federal Commercial Vehicle Codes',
    'DCM': 'AAMVA Version Number (inside subfile)',
    'DCN': 'Jurisdiction-specific Vehicle Class',
    'DCO': 'Permit Classification Code',
    'DCP': 'Permit Expiration Date',
    'DCQ': 'Permit Identifier',
    'DCR': 'Permit Issue Date',
    'DCU': 'Name Suffix (JR/SR/I/II/III)',
    'DAB': 'Last Name (old v1 alias)',
    'DAE': 'Name Suffix (old v1 alias)',
    'DAF': 'Name Prefix (old v1 alias)',
    'DAN': 'Alias / AKA Last Name',
    'DAO': 'Alias / AKA First Name',
    'DAP': 'Alias / AKA Middle Name',
    'DAR': 'License Classification Code (v1)',
    'DAS': 'Restriction Code (v1)',
    'DAT': 'Endorsement Code (v1)',
    'DAV': 'Height in CM (v1)',
    'ZNA': 'NC Replacement Indicator',
    'ZNB': 'NC Limited-Term Indicator',
    'ZNC': 'NC Under-21 Indicator (0=No, 1=Yes)',
    'ZND': 'NC Non-Resident CDL (N/Y)',
    'ZNE': 'NC Selective Service',
    'ZNF': 'NC Veteran Indicator',
    'ZNG': 'NC Medical Indicator',
    'ZNH': 'NC Volunteer Fire/Rescue',
    'ZNI': 'NC Non-Compliant Reason',
    'ZNJ': 'NC Audit Number Suffix',
    'ZNK': 'NC Customer Sequence',
}

# ---------------------------------------------------------------------------
# EMBEDDED RAW STRINGS  (reference barcode = CARD1, tilde-escaped = CARD2)
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


# ===========================================================================
# STEP 1 — IMAGE DECODE
# ===========================================================================

def ensure_zbar():
    if subprocess.run(['which', 'zbarimg'], capture_output=True).returncode != 0:
        subprocess.run('apt-get install -y zbar-tools libzbar0 2>&1 | tail -3',
                       shell=True, capture_output=True, text=True)

def ensure_pdf417decoder():
    try:
        import pdf417decoder  # noqa
    except ImportError:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pdf417decoder', '-q'])

def _decode_zbar(path: str, label: str) -> bytes | None:
    r = subprocess.run(['zbarimg', '--raw', '-q', path], capture_output=True)
    print(f'  zbarimg {label}: RC={r.returncode} bytes={len(r.stdout)}')
    return r.stdout if r.returncode == 0 and r.stdout else None

def _decode_preprocessed(path: str, label: str) -> bytes | None:
    try:
        from PIL import Image, ImageEnhance, ImageFilter
        import numpy as np
    except ImportError:
        return None
    img = Image.open(path).convert('L')
    w, h = img.size
    scale = max(1, 1200 // w)
    up  = img.resize((w * scale, h * scale), Image.LANCZOS)
    arr = np.array(up)
    for name, proc in [
        ('threshold', Image.fromarray(((arr > arr.mean()) * 255).astype('uint8'))),
        ('enhanced',  ImageEnhance.Contrast(img).enhance(3.0).filter(ImageFilter.SHARPEN)),
        ('inverted',  Image.fromarray(255 - arr)),
    ]:
        p = f'/tmp/{label}_{name}.png'
        proc.save(p)
        r = subprocess.run(['zbarimg', '--raw', '-q', '--set', 'pdf417.enable=1', p],
                           capture_output=True)
        print(f'    [{name}] RC={r.returncode} bytes={len(r.stdout)}')
        if r.returncode == 0 and r.stdout:
            return r.stdout
    return None

def _decode_pdf417decoder(path: str, label: str) -> bytes | None:
    try:
        from pdf417decoder import PDF417Decoder
        from PIL import Image
    except ImportError:
        return None
    dec = PDF417Decoder(Image.open(path))
    n = dec.decode()
    print(f'  pdf417decoder {label}: {n} barcode(s)')
    if n == 0:
        return None
    for fn in [
        lambda: dec.barcode_data_index_to_string(0).encode('latin-1'),
        lambda: (dec.barcodes_data[0] if isinstance(dec.barcodes_data[0], bytes)
                 else dec.barcodes_data[0].encode('latin-1')),
    ]:
        try:
            r = fn()
            if r:
                return r
        except Exception:
            pass
    return None

def decode_image(path: str, label: str) -> str | None:
    print(f"\n{'='*60}\nDECODING {label.upper()}: {path}\n{'='*60}")
    if not os.path.exists(path):
        print(f'  ⚠  File not found: {path}')
        return None
    ensure_zbar()
    raw = _decode_zbar(path, label)
    if raw is None:
        raw = _decode_preprocessed(path, label)
    if raw is None:
        ensure_pdf417decoder()
        raw = _decode_pdf417decoder(path, label)
    if raw is None:
        print(f'  ✗  Could not decode {label}')
        return None
    decoded = raw.decode('latin-1')
    print(f'Bytes decoded: {len(raw)}')
    print(repr(decoded[:1200]))
    return decoded


# ===========================================================================
# STEP 2 — PARSE
# ===========================================================================

def unescape_tilde(s: str) -> str:
    return re.sub(r'~([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)

def detect_encoding_mode(raw: str) -> str:
    """
    Detect encoding mode from the ORIGINAL (pre-unescape) first bytes.

    AAMVA spec requires the header to be raw binary bytes:
        0x40 ('@')  File Type
        0x0A (LF)   Data Element Separator
        0x1E (RS)   Record Separator
        0x0D (CR)   Segment Terminator

    CRITICAL: This function must ALWAYS be called on the original raw string,
    never on the tilde-unescaped version. Calling it on normalised bytes
    would make tilde-escape look like binary — the root cause of the v3.0 bug.

    Returns: 'binary' | 'tilde_escape' | 'unknown'
    """
    if len(raw) < 4:
        return 'unknown'
    b0, b1, b2, b3 = ord(raw[0]), ord(raw[1]), ord(raw[2]), ord(raw[3])
    if b0 == 0x40 and b1 == 0x0A and b2 == 0x1E and b3 == 0x0D:
        return 'binary'
    # Check for ~XX tilde-escape (uppercase or lowercase hex)
    if re.match(r'^@~[0-9a-fA-F]{2}~[0-9a-fA-F]{2}~[0-9a-fA-F]{2}', raw):
        return 'tilde_escape'
    return 'unknown'

def parse_subfiles(raw: str) -> dict:
    result = {
        'header_match': None, 'iin': '', 'aamva_ver': 0, 'juris_ver': 0,
        'num_subfiles': 0, 'subfiles': [], 'fields': {},
        'offsets_valid': True, 'dl_subfile_found': False,
    }
    m = re.search(
        r'ANSI (\d{6})(\d{2})(\d{2})(\d{2})((?:[A-Z]{2}\d{4}\d{4})+)', raw
    )
    if m:
        result.update({
            'header_match': m.group(0),
            'iin':          m.group(1),
            'aamva_ver':    int(m.group(2)),
            'juris_ver':    int(m.group(3)),
            'num_subfiles': int(m.group(4)),
        })
        entries    = re.findall(r'([A-Z]{2})(\d{4})(\d{4})', m.group(5))
        header_end = m.end(0)
        for sf_id, sf_off, sf_len in entries:
            off    = int(sf_off)
            length = int(sf_len)
            actual = raw.find(sf_id, header_end)
            in_rng = abs(actual - off) <= 5 if actual != -1 else False
            text   = raw[actual:actual + length] if actual != -1 else ''
            fields = _parse_fields(text)
            result['subfiles'].append({
                'id': sf_id, 'declared_offset': off, 'declared_length': length,
                'actual_start': actual, 'offset_valid': in_rng, 'fields': fields,
            })
            result['fields'].update(fields)
            if sf_id == 'DL':
                result['dl_subfile_found'] = True
            if not in_rng:
                result['offsets_valid'] = False
    else:
        m4 = re.search(r'ANSI (\d{6})(\d{2})(\d{2})', raw)
        if m4:
            result.update({
                'header_match': m4.group(0),
                'iin':       m4.group(1),
                'aamva_ver': int(m4.group(2)),
                'juris_ver': int(m4.group(3)),
            })
        result['fields'] = _parse_fields(raw)
        result['dl_subfile_found'] = 'DAQ' in result['fields']
    return result

def _parse_fields(text: str) -> dict:
    """
    FIX 1: Strip the 2-char subfile designator (e.g. 'DL', 'ZN') from the
    start of the block so 'DLDAQ...' yields tag 'DAQ' not 'DLD'.

    FIX 2: Only strip null bytes and line terminators, NOT spaces.
    Trailing spaces are mandatory in fixed-width fields (DAK=11, DCL=3).
    """
    fields: dict[str, str] = {}
    if len(text) >= 5 and re.match(r'^[A-Z]{2}[A-Z]{2}[A-Z0-9]', text):
        text = text[2:]
    for line in re.split(r'[\n\r\x1c\x1d\x1e]', text):
        line = line.lstrip('\x00').rstrip('\r\n')
        if len(line) >= 3:
            tag = line[:3]
            val = line[3:]
            if re.match(r'^[A-Z]{2}[A-Z0-9]$', tag):
                fields[tag] = val
    return fields


# ===========================================================================
# STEP 3 — FORENSIC ANALYSIS
# ===========================================================================

def analyse_header_bytes(raw: str, label: str) -> tuple[bool, str]:
    """
    Binary header check — MUST be called on the ORIGINAL raw string.

    *** v3.1 FIX: We no longer accept the normalised (tilde-unescaped)
    string here. Tilde-escape is a hard FAIL regardless of field content. ***

    An authentic AAMVA barcode MUST have binary 0x0A, 0x1E, 0x0D.
    Tilde-escape (~0a, ~1e, ~0d) means the encoder did NOT write actual
    binary control bytes — this is structurally non-compliant.
    """
    print(f'\n--- HEADER BYTES ({label}) ---')
    mode = detect_encoding_mode(raw)
    b = [ord(raw[i]) if i < len(raw) else 0 for i in range(4)]
    expected = [0x40, 0x0A, 0x1E, 0x0D]
    labels   = ['@ (File Type)', 'LF 0x0A (Data Sep)', 'RS 0x1E (Rec Sep)', 'CR 0x0D (Seg Term)']
    for i, (got, exp, lbl) in enumerate(zip(b, expected, labels)):
        ok = got == exp
        print(f'  Byte {i} {lbl}: 0x{got:02X}  {"✅" if ok else "❌ expected 0x" + f"{exp:02X}"}')
    # header_ok is True ONLY when all 4 bytes match AND mode is binary
    # (not tilde_escape — unescape would make ~0a look like 0x0A)
    header_ok = (mode == 'binary') and all(b[i] == expected[i] for i in range(4))
    print(f'  Encoding mode:  {mode}')
    if mode == 'tilde_escape':
        print(f'  ❌ TILDE-ESCAPE DETECTED — hard FAIL')
        print(f'     Authentic barcodes encode control bytes as raw binary.')
        print(f'     ~XX ASCII sequences indicate an incorrectly configured encoder.')
        print(f'     Common cause: bwip-js with lowercase ~0a/~1e/~0d escapes.')
    elif mode == 'binary':
        print(f'  ✅ Raw binary header — PASS')
    else:
        print(f'  ⚠  Unknown encoding mode')
    return header_ok, mode

def analyse_aamva_version(parsed: dict):
    print('\n--- AAMVA VERSION HEADER ---')
    if not parsed.get('header_match'):
        print('  ❌ ANSI header not found')
        return
    iin  = parsed['iin']
    ver  = parsed['aamva_ver']
    jver = parsed['juris_ver']
    nsf  = parsed['num_subfiles']
    state = AAMVA_IIN_MAP.get(iin, '❌ UNKNOWN')
    print(f'  IIN:           {iin} → {state}')
    print(f'  AAMVA Version: {ver:02d} v{ver} ({_ver_year(ver)}) {"✅" if 1 <= ver <= 10 else "❌ invalid"}')
    print(f'  Juris Version: {jver:02d}')
    print(f'  Subfiles:      {nsf}')
    for sf in parsed['subfiles']:
        ok = '✅' if sf['offset_valid'] else '⚠ offset mismatch'
        print(f'    {sf["id"]}: off={sf["declared_offset"]} len={sf["declared_length"]} '
              f'actual={sf["actual_start"]} {ok}')
    icon = '✅' if parsed.get('dl_subfile_found') else '❌ NOT FOUND'
    print(f'  DL subfile: {icon}')

def _ver_year(v: int) -> str:
    return {1:'2000',2:'2003',3:'2005',4:'2006',5:'2008',
            6:'2011',7:'2012',8:'2009',9:'2013',10:'2016'}.get(v, '?')

def analyse_mandatory_fields(fields: dict, aamva_ver: int) -> list[str]:
    print(f'\n--- MANDATORY FIELD CHECK (AAMVA v{aamva_ver:02d}) ---')
    ver  = min(max(aamva_ver, 1), 10)
    mandatory = AAMVA_MANDATORY_FIELDS.get(ver, AAMVA_MANDATORY_FIELDS[8])
    missing = []
    for tag in mandatory:
        present = tag in fields
        desc    = DMV_FIELD_LABELS.get(tag, '')
        print(f'  {tag} ({desc}): {"✅" if present else "❌ MISSING"}')
        if not present:
            missing.append(tag)
    if missing:
        print(f'  ❌ {len(missing)} missing: {", ".join(missing)}')
    else:
        print(f'  ✅ All {len(mandatory)} mandatory fields present')
    return missing

def _parse_date(val: str, tag: str) -> datetime | None:
    for fmt in ('%m%d%Y', '%Y%m%d', '%m%Y'):
        try:
            return datetime.strptime(val.strip(), fmt)
        except ValueError:
            pass
    print(f'  {tag}: ❌ unrecognised date format: {repr(val)}')
    return None

def analyse_dates(fields: dict, aamva_ver: int):
    print('\n--- DATE FIELD VALIDATION ---')
    today = datetime.today()
    iss_dt = exp_dt = dob_dt = None
    for tag, lbl in [('DBB','DOB'), ('DBD','Issue Date'), ('DBA','Expiry Date'),
                     ('DDB','Card Revision/Prior-Issue Date'),
                     ('DDH','Under-18 Until'), ('DDI','Under-19 Until'),
                     ('DDJ','Under-21 Until')]:
        val = fields.get(tag)
        if not val or not val.strip():
            continue
        dt = _parse_date(val, tag)
        if dt is None:
            continue
        extra = ''
        if tag == 'DBB':
            dob_dt = dt
            age = (today - dt).days // 365
            extra = f' → Age {age} yrs'
        elif tag == 'DBA':
            exp_dt = dt
            extra = f' → {"✅ valid" if dt > today else "❌ EXPIRED"}'
        elif tag == 'DBD':
            iss_dt = dt
        elif tag == 'DDB':
            role = 'Card Revision' if aamva_ver >= 5 else 'Under-18 Until'
            extra = f' → [{role}]'
        print(f'  {tag} ({lbl}): {dt.strftime("%B %d, %Y")}{extra}')
    if iss_dt and exp_dt:
        yrs = (exp_dt - iss_dt).days / 365.25
        ok  = 4 <= yrs <= 10
        print(f'  Term (Issue→Expiry): {yrs:.1f} yrs {"✅" if ok else "⚠ unusual (<4 or >10 years)"}')
    dob_val = fields.get('DBB', '')
    exp_val = fields.get('DBA', '')
    if dob_val and exp_val and len(dob_val) >= 4 and len(exp_val) >= 4:
        if dob_val[:4] == exp_val[:4]:
            print(f'  ✅ Expiry month/day matches DOB ({dob_val[:4]}) — birthday-linked')

def analyse_field_values(fields: dict):
    print('\n--- FIELD VALUE VALIDATION ---')

    def chk(tag, valid_set, label):
        val = fields.get(tag, '').strip()
        if not val:
            return
        ok = val in valid_set
        print(f'  {tag} ({label}): {repr(val)} {"✅" if ok else "❌ invalid " + repr(sorted(valid_set))}')

    chk('DBC', VALID_SEX,        'Sex')
    chk('DDA', VALID_COMPLIANCE, 'Compliance Type')
    chk('DDE', VALID_TRUNCATION, 'Last Name Trunc')
    chk('DDF', VALID_TRUNCATION, 'First Name Trunc')
    chk('DDG', VALID_TRUNCATION, 'Middle Name Trunc')
    chk('DAY', VALID_EYE_CODES,  'Eye Colour')
    chk('DAZ', VALID_HAIR_CODES, 'Hair Colour')
    chk('DDK', VALID_ORGAN_DONOR,'Organ Donor')
    chk('DDL', VALID_VETERAN,    'Veteran Indicator')

    dau = fields.get('DAU', '').strip()
    if dau:
        if re.match(r'^\d{3} (in|cm)$', dau):
            print(f'  DAU (Height): {repr(dau)} ✅')
        else:
            print(f'  DAU (Height): {repr(dau)} ❌ expected "NNN in" or "NNN cm"')

    dak = fields.get('DAK', '')
    if dak:
        if re.match(r'^\d{9}[\s0]{2}$', dak):
            print(f'  DAK (ZIP 9+2): {repr(dak)} ✅ ({len(dak)} chars)')
        elif re.match(r'^[A-Z]\d[A-Z] \d[A-Z]\d', dak.strip()):
            print(f'  DAK (Postal Canadian): {repr(dak)} ✅')
        else:
            print(f'  DAK: {repr(dak)} ❌ expected 11-char fixed-width (9 digits + 2 pad chars)')

    dcl = fields.get('DCL', '')
    if dcl:
        dcl_stripped = dcl.strip()
        if len(dcl) == 3 and dcl_stripped in VALID_RACE_CODES:
            print(f'  DCL (Race 3-char): {repr(dcl)} ✅ ({dcl_stripped})')
        elif dcl_stripped in VALID_RACE_CODES:
            print(f'  DCL (Race): {repr(dcl)} ⚠ valid code but wrong width ({len(dcl)} chars, expected 3)')
        else:
            print(f'  DCL (Race): {repr(dcl)} ❌ unknown code. Valid: {sorted(VALID_RACE_CODES)}')

    dcg = fields.get('DCG', '').strip()
    if dcg and dcg not in ('USA', 'CAN', 'MEX'):
        print(f'  DCG (Country): {repr(dcg)} ⚠ unusual country code')
    elif dcg:
        print(f'  DCG (Country): {repr(dcg)} ✅')

    dcf = fields.get('DCF', '').strip()
    if dcf:
        if 8 <= len(dcf) <= 25:
            print(f'  DCF (Doc Discriminator): {repr(dcf)} ✅ (len={len(dcf)})')
        else:
            print(f'  DCF (Doc Discriminator): {repr(dcf)} ⚠ unusual length ({len(dcf)})')

def analyse_dck(dck: str, iin: str = ''):
    print('\n--- DCK AUDIT NUMBER FORENSICS ---')
    dck = dck.strip()
    print(f'  DCK raw: {repr(dck)}  (len={len(dck)})')
    if len(dck) < 12:
        print('  ⚠  DCK shorter than expected (min 12 chars)')
        return
    dl_prefix  = dck[:12]
    state_code = dck[12:14] if len(dck) >= 14 else ''
    batch_code = dck[14:16] if len(dck) >= 16 else ''
    vendor     = dck[16:18] if len(dck) >= 18 else ''
    sequence   = dck[18:20] if len(dck) >= 20 else ''
    print(f'  [00:12] DL# prefix:    {dl_prefix}')
    if state_code:
        print(f'  [12:14] State code:    {state_code}')
    if batch_code:
        print(f'  [14:16] Batch code:    {batch_code}')
    if vendor:
        vendor_name = DCK_VENDOR_MAP.get(vendor, 'unknown')
        print(f'  [16:18] Vendor code:   {vendor} ({vendor_name})')
    if sequence:
        print(f'  [18:20] Sequence:      {sequence}')
    return dl_prefix

def analyse_dck_vs_daq(dck_prefix: str, daq: str):
    if not dck_prefix or not daq:
        return
    daq_stripped = daq.strip().lstrip('0')
    dck_stripped = dck_prefix.strip().lstrip('0')
    if daq_stripped == dck_stripped:
        print(f'  ✅ DCK prefix matches DAQ ({daq_stripped})')
    else:
        print(f'  ❌ DCK prefix MISMATCH: DAQ={repr(daq)} DCK_prefix={repr(dck_prefix)}')

def analyse_zn_subfile(fields: dict, iin: str):
    print('\n--- JURISDICTION SUBFILE FORENSICS ---')
    state = AAMVA_IIN_MAP.get(iin, 'Unknown')
    print(f'  Issuing State: {state} (IIN {iin})')
    z_fields = {k: v for k, v in sorted(fields.items()) if k.startswith('Z')}
    if not z_fields:
        print('  (no jurisdiction fields found)')
        return
    for tag, val in z_fields.items():
        desc = DMV_FIELD_LABELS.get(tag, NC_ZN_FIELDS.get(tag, 'Unknown jurisdiction field'))
        note = ''
        if tag == 'ZNA':
            note = '(Replacement)' if val.strip() else '✅ (Original document)'
        elif tag == 'ZNB':
            note = '(Limited-term)' if val.strip() else '✅ (Full-term)'
        elif tag == 'ZNC':
            note = '✅ Under-21' if val.strip() == '1' else ('✅ 21+' if val.strip() == '0' else '⚠')
        elif tag == 'ZND':
            note = ('✅ Non-resident CDL' if val.strip() == 'Y'
                    else ('✅ Not CDL' if val.strip() == 'N' else '⚠'))
        print(f'  {tag}: {repr(val):<12}  {desc}  {note}')

def run_forensics(raw: str, label: str) -> dict:
    print(f"\n{'='*60}\nFORENSIC ANALYSIS: {label.upper()}\n{'='*60}")

    # -----------------------------------------------------------------------
    # v3.1 FIX: detect encoding mode and check header bytes on the ORIGINAL
    # raw string BEFORE any normalisation/unescape. This ensures tilde-escape
    # always produces header_ok=False. Previously analyse_header_bytes was
    # called on `normalised` which made ~0a look like 0x0A → wrong PASS.
    # -----------------------------------------------------------------------
    mode       = detect_encoding_mode(raw)
    header_ok, enc_mode = analyse_header_bytes(raw, label)

    # Normalise ONLY for field parsing — header verdict already locked above
    normalised = unescape_tilde(raw) if '~' in raw else raw

    parsed = parse_subfiles(normalised)
    analyse_aamva_version(parsed)
    fields = parsed['fields']

    print('\n--- ALL PARSED FIELDS ---')
    for tag, val in sorted(fields.items()):
        desc = DMV_FIELD_LABELS.get(tag, '')
        print(f'  {tag}: {repr(val):<34}  {desc}')

    missing = analyse_mandatory_fields(fields, parsed['aamva_ver'] or 8)
    analyse_dates(fields, parsed['aamva_ver'] or 8)
    analyse_field_values(fields)

    dck_prefix = None
    if 'DCK' in fields:
        dck_prefix = analyse_dck(fields['DCK'], parsed['iin'])
        analyse_dck_vs_daq(dck_prefix, fields.get('DAQ', ''))

    analyse_zn_subfile(fields, parsed['iin'])

    return {
        'fields':            fields,
        'header_ok':         header_ok,
        'normalised':        normalised,
        'parsed':            parsed,
        'missing_mandatory': missing,
        'encoding_mode':     mode,
    }


# ===========================================================================
# STEP 4 — COMPARE + VERDICT
# ===========================================================================

def compare_cards(r1: dict, r2: dict):
    print(f"\n{'='*60}\nFIELD COMPARISON: CARD1 vs CARD2\n{'='*60}")
    if r1['encoding_mode'] != r2['encoding_mode']:
        print(f'  ⚠  ENCODING MODE MISMATCH')
        print(f'     Card1: {r1["encoding_mode"]}')
        print(f'     Card2: {r2["encoding_mode"]}')
        print()
    f1, f2 = r1['fields'], r2['fields']
    all_tags = sorted(set(list(f1) + list(f2)))
    matches = mismatches = 0
    for tag in all_tags:
        v1 = f1.get(tag, '<MISSING>')
        v2 = f2.get(tag, '<MISSING>')
        if v1 == v2:
            matches += 1
            print(f'  {tag}: ✅ MATCH   {repr(v1)}')
        else:
            mismatches += 1
            print(f'  {tag}: ❌ DIFFER')
            print(f'       C1: {repr(v1)}')
            print(f'       C2: {repr(v2)}')
    print(f'\n  {matches} matching, {mismatches} differing')


def authenticity_verdict(r1: dict, r2: dict):
    print(f"\n{'='*60}\nAUTHENTICITY VERDICT\n{'='*60}")
    for card_label, r in [('CARD1', r1), ('CARD2', r2)]:
        print(f'\n  --- {card_label} ({r["encoding_mode"].upper()}) ---')
        p  = r['parsed']
        f  = r['fields']
        iin= p.get('iin', '')
        ver= p.get('aamva_ver', 0)
        state_name = AAMVA_IIN_MAP.get(iin, 'Unknown')
        state_code = f.get('DAJ', '').strip()

        checks = [
            # ——  CHECK #1: CRITICAL — encoding gate  ——
            # header_ok is already False for tilde-escape (v3.1 fix)
            ('Encoding: raw binary header (0x40 0x0A 0x1E 0x0D)',
             r['header_ok'] and r['encoding_mode'] == 'binary'),

            ('IIN registered in AAMVA registry',
             iin in AAMVA_IIN_MAP),
            ('IIN state matches DAJ field',
             state_name.lower() == _state_abbr_to_name(state_code).lower() if state_code else False),
            ('AAMVA version 01–10',
             1 <= ver <= 10),
            ('DL subfile present',
             p.get('dl_subfile_found', False)),
            ('Subfile byte-range offsets valid',
             p.get('offsets_valid', False)),
            ('All mandatory fields present',
             len(r['missing_mandatory']) == 0),
            ('DBC sex code valid (1/2/9)',
             f.get('DBC','').strip() in VALID_SEX),
            ('DAY eye colour code valid',
             f.get('DAY','').strip() in VALID_EYE_CODES),
            ('DAZ hair colour code valid',
             f.get('DAZ','').strip() in VALID_HAIR_CODES if 'DAZ' in f else True),
            ('DAU height format (NNN in/cm)',
             bool(re.match(r'^\d{3} (in|cm)$', f.get('DAU','').strip()))),
            ('DBA expiry date in future',
             (lambda v: bool(v) and _parse_date(v,'DBA') is not None
              and _parse_date(v,'DBA') > datetime.today())(f.get('DBA',''))),
            ('DAK ZIP format (11-char fixed-width)',
             bool(re.match(r'^\d{9}[\s0]{2}$', f.get('DAK','')))),
            ('DCF document discriminator present',
             bool(f.get('DCF','').strip())),
            ('DCG country code (USA/CAN/MEX)',
             f.get('DCG','').strip() in ('USA','CAN','MEX')),
            ('DDA compliance type valid (F/N/U)',
             f.get('DDA','').strip() in VALID_COMPLIANCE if 'DDA' in f else True),
            ('DDE last-name truncation flag valid',
             f.get('DDE','').strip() in VALID_TRUNCATION if 'DDE' in f else True),
            ('DDF first-name truncation flag valid',
             f.get('DDF','').strip() in VALID_TRUNCATION if 'DDF' in f else True),
            ('DDG middle-name truncation flag valid',
             f.get('DDG','').strip() in VALID_TRUNCATION if 'DDG' in f else True),
            ('DCL race/ethnicity 3-char width',
             len(f.get('DCL','')) == 3 if 'DCL' in f else True),
            ('DCK audit number present',
             bool(f.get('DCK','').strip())),
            ('DDK organ donor valid (0/1)',
             f.get('DDK','').strip() in VALID_ORGAN_DONOR if 'DDK' in f else True),
        ]

        passed = failed = 0
        for lbl, result in checks:
            icon = '✅ PASS' if result else '❌ FAIL'
            if result:
                passed += 1
            else:
                failed += 1
            print(f'    {icon}  {lbl}')

        total = len(checks)
        print(f'\n    Result: {passed}/{total} checks passed')
        if r['encoding_mode'] == 'tilde_escape':
            print(f'    ❌ {card_label} FAILED — tilde-escape encoding is NOT a valid AAMVA barcode')
            print(f'       Authentic barcodes require raw binary bytes 0x0A 0x1E 0x0D in the header.')
        elif failed == 0:
            print(f'    ✅ {card_label} STRUCTURALLY AUTHENTIC [{state_name}, AAMVA v{ver:02d}]')
        else:
            print(f'    ⚠  {card_label} PARTIAL — {failed} check(s) failed')


def _state_abbr_to_name(abbr: str) -> str:
    _map = {
        'AL':'Alabama','AK':'Alaska','AZ':'Arizona','AR':'Arkansas','CA':'California',
        'CO':'Colorado','CT':'Connecticut','DC':'DC','DE':'Delaware','FL':'Florida',
        'GA':'Georgia','HI':'Hawaii','ID':'Idaho','IL':'Illinois','IN':'Indiana',
        'IA':'Iowa','KS':'Kansas','KY':'Kentucky','LA':'Louisiana','ME':'Maine',
        'MD':'Maryland','MA':'Massachusetts','MI':'Michigan','MN':'Minnesota',
        'MS':'Mississippi','MO':'Missouri','MT':'Montana','NE':'Nebraska','NV':'Nevada',
        'NH':'New Hampshire','NJ':'New Jersey','NM':'New Mexico','NY':'New York',
        'NC':'North Carolina','ND':'North Dakota','OH':'Ohio','OK':'Oklahoma',
        'OR':'Oregon','PA':'Pennsylvania','RI':'Rhode Island','SC':'South Carolina',
        'SD':'South Dakota','TN':'Tennessee','TX':'Texas','UT':'Utah','VT':'Vermont',
        'VA':'Virginia','WA':'Washington','WV':'West Virginia','WI':'Wisconsin','WY':'Wyoming',
    }
    return _map.get(abbr.upper(), '')


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description='AAMVA PDF417 Forensic Tool v3.1')
    parser.add_argument('--card1', default='card1.jpg')
    parser.add_argument('--card2', default='card2.jpg')
    parser.add_argument('--raw-only', action='store_true')
    args = parser.parse_args()

    print('╔' + '═' * 58 + '╗')
    print('║  AAMVA PDF417 BARCODE FORENSIC TOOL  v3.1                ║')
    print('║  All 50 states · AAMVA v01–10 · Tilde-escape = FAIL      ║')
    print('║  v3.1: header checked on original raw bytes (not escape)  ║')
    print('╚' + '═' * 58 + '╝')

    if args.raw_only:
        raw1, raw2 = CARD1_RAW_EMBEDDED, CARD2_RAW_EMBEDDED
    else:
        raw1 = decode_image(args.card1, 'card1') or CARD1_RAW_EMBEDDED
        raw2 = decode_image(args.card2, 'card2') or CARD2_RAW_EMBEDDED

    r1 = run_forensics(raw1, 'card1')
    r2 = run_forensics(raw2, 'card2')
    compare_cards(r1, r2)
    authenticity_verdict(r1, r2)


if __name__ == '__main__':
    main()
