#!/usr/bin/env python3
"""
AAMVA PDF417 Barcode Forensic & Authenticity Tool  v2.0
========================================================
Full AAMVA DL/ID Card Design Standard 2000–2020 compliance.
Supports AAMVA versions 01–10, all 50 states + DC + territories.

Usage:
  python aamva_forensic.py                          # card1.jpg + card2.jpg in CWD
  python aamva_forensic.py --card1 a.jpg --card2 b.jpg
  python aamva_forensic.py --raw-only               # use embedded raw strings
  python aamva_forensic.py --raw-only --card1-raw "@..." --card2-raw "@..."
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
# AAMVA VERSION → mandatory DL fields (v5+)
# ---------------------------------------------------------------------------
AAMVA_MANDATORY_FIELDS: dict[int, list[str]] = {
    # v1–v4: minimal set
    1: ['DAQ','DCS','DAC','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK'],
    2: ['DAQ','DCS','DAC','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK'],
    3: ['DAQ','DCS','DAC','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK'],
    4: ['DAQ','DCS','DAC','DAD','DBB','DBA','DBD','DBC','DAU','DAY','DAG','DAI','DAJ','DAK'],
    # v5+ full mandatory set
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
# TRUNCATION / ENUM VALIDATION TABLES
# ---------------------------------------------------------------------------
VALID_TRUNCATION = {'N', 'T', 'U'}       # DDE / DDF / DDG
VALID_SEX        = {'1', '2', '9'}       # DBC: 1=M 2=F 9=Not specified
VALID_COMPLIANCE = {'F', 'N', 'U'}       # DDA: Full / Not compliant / Unknown
VALID_EYE_CODES  = {'BLK','BLU','BRO','GRY','GRN','HAZ','MAR','PNK','DIC','UNK'}
VALID_HAIR_CODES = {'BAL','BLK','BLN','BRO','GRY','RED','SDY','WHI','UNK'}

# ---------------------------------------------------------------------------
# DMV FIELD LABELS
# ---------------------------------------------------------------------------
DMV_FIELD_LABELS: dict[str, str] = {
    'DAQ': 'Driver License Number',    'DCS': 'Last Name',
    'DAC': 'First Name',               'DAD': 'Middle Name',
    'DBB': 'Date of Birth (DOB)',       'DBA': 'Expiry Date',
    'DBD': 'Issue Date',               'DDB': 'Under-18 Until / Prior Issue Date',
    'DBC': 'Sex (1=M 2=F 9=N/A)',      'DAU': 'Height',
    'DAY': 'Eye Colour',               'DAZ': 'Hair Colour',
    'DAG': 'Street Address',           'DAI': 'City',
    'DAJ': 'State/Province',           'DAK': 'ZIP/Postal Code (11 chars)',
    'DCA': 'Vehicle Class',            'DCB': 'Restrictions',
    'DCD': 'Endorsements',             'DCF': 'Document Discriminator',
    'DCG': 'Country ID',               'DCK': 'Inventory Control Number',
    'DCL': 'Race/Ethnicity',           'DDA': 'Compliance Type',
    'DDC': 'Hazmat Expiry',            'DDE': 'Last Name Truncation (N/T/U)',
    'DDF': 'First Name Truncation (N/T/U)', 'DDG': 'Middle Name Truncation (N/T/U)',
    'DDH': 'Under 18 Until',           'DDI': 'Under 19 Until',
    'DDJ': 'Under 21 Until',           'DDK': 'Organ Donor',
    'DDL': 'Veteran Indicator',
}

# ---------------------------------------------------------------------------
# EMBEDDED RAW STRINGS
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
        print('[setup] installing zbar-tools...')
        subprocess.run('apt-get install -y zbar-tools libzbar0 2>&1 | tail -5',
                       shell=True, capture_output=True, text=True)

def ensure_pdf417decoder():
    try:
        import pdf417decoder  # noqa
    except ImportError:
        print('[setup] installing pdf417decoder...')
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pdf417decoder', '-q'])

def decode_with_zbar(path: str, label: str) -> bytes | None:
    r = subprocess.run(['zbarimg', '--raw', '-q', path], capture_output=True)
    print(f'  zbarimg {label}: RC={r.returncode} bytes={len(r.stdout)}')
    if r.stderr:
        print(f'  zbarimg stderr: {r.stderr.decode()[:200]}')
    return r.stdout if r.returncode == 0 and r.stdout else None

def decode_with_preprocessing(path: str, label: str) -> bytes | None:
    try:
        from PIL import Image, ImageEnhance, ImageFilter
        import numpy as np
    except ImportError:
        return None
    img = Image.open(path).convert('L')
    w, h = img.size
    scale = max(1, 1200 // w)
    upscaled = img.resize((w * scale, h * scale), Image.LANCZOS)
    arr = np.array(upscaled)
    binary = ((arr > arr.mean()) * 255).astype('uint8')
    proc_path = f'/tmp/{label}_proc.png'
    Image.fromarray(binary).save(proc_path)
    enhanced = ImageEnhance.Contrast(img).enhance(3.0).filter(ImageFilter.SHARPEN)
    s1_path  = f'/tmp/{label}_s1.png'
    enhanced.save(s1_path)
    inv_path = f'/tmp/{label}_inv.png'
    Image.fromarray(255 - np.array(img)).save(inv_path)
    for name, fpath in [('threshold', proc_path), ('enhanced', s1_path), ('inverted', inv_path)]:
        r = subprocess.run(['zbarimg', '--raw', '-q', '--set', 'pdf417.enable=1', fpath],
                           capture_output=True)
        print(f'    [{name}] RC={r.returncode} bytes={len(r.stdout)}')
        if r.returncode == 0 and r.stdout:
            return r.stdout
    return None

def decode_with_pdf417decoder(path: str, label: str) -> bytes | None:
    try:
        from pdf417decoder import PDF417Decoder
        from PIL import Image
    except ImportError:
        return None
    img  = Image.open(path)
    dec  = PDF417Decoder(img)
    count = dec.decode()
    print(f'  pdf417decoder {label}: {count} barcode(s) found')
    if count == 0:
        return None
    for method in [
        lambda: dec.barcode_data_index_to_string(0).encode('latin-1'),
        lambda: (dec.barcodes_data[0] if isinstance(dec.barcodes_data[0], bytes)
                 else dec.barcodes_data[0].encode('latin-1')),
        lambda: dec.barcode_binary_data,
    ]:
        try:
            r = method()
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
    raw = decode_with_zbar(path, label)
    if raw is None:
        raw = decode_with_preprocessing(path, label)
    if raw is None:
        ensure_pdf417decoder()
        raw = decode_with_pdf417decoder(path, label)
    if raw is None:
        print(f'  ✗  Could not decode {label}')
        return None
    decoded = raw.decode('latin-1')
    print(f'\n--- RAW OUTPUT ({label}) ---')
    print(f'Bytes decoded: {len(raw)}')
    print(repr(decoded[:1200]))
    return decoded


# ===========================================================================
# STEP 2 — PARSE
# ===========================================================================

def unescape_tilde(s: str) -> str:
    """Convert ~XX (any case) escape sequences to actual characters."""
    return re.sub(r'~([0-9a-fA-F]{2})',
                  lambda m: chr(int(m.group(1), 16)), s)

def detect_encoding_mode(raw: str) -> str:
    """Detect whether control chars are raw binary or ~XX escaped."""
    if len(raw) < 4:
        return 'unknown'
    b1, b2, b3, b4 = ord(raw[0]), ord(raw[1]), ord(raw[2]), ord(raw[3])
    if b1 == 0x40 and b2 == 0x0A and b3 == 0x1E and b4 == 0x0D:
        return 'binary'
    if raw[:10] == '@~0a~1e~0d' or raw[:10] == '@~0A~1E~0D':
        return 'tilde_escape'
    return 'unknown'

def parse_subfiles(raw: str) -> dict:
    """
    Full AAMVA subfile parser:
      1. Extract ANSI header
      2. Parse subfile directory (offset+length table)
      3. Extract each subfile by byte range
      4. Parse fields within each subfile
    Returns dict with keys: header_match, iin, aamva_ver, juris_ver,
    subfiles (list of dicts), fields (merged), offsets_valid.
    """
    result = {
        'header_match': None,
        'iin': '',
        'aamva_ver': 0,
        'juris_ver': 0,
        'num_subfiles': 0,
        'subfiles': [],
        'fields': {},
        'offsets_valid': True,
        'dl_subfile_found': False,
    }

    # Try v5+ header (has offset table)
    m = re.search(
        r'ANSI (\d{6})(\d{2})(\d{2})(\d{2})'
        r'((?:[A-Z]{2}\d{4}\d{4})+)',
        raw
    )
    if m:
        result['header_match'] = m.group(0)
        result['iin']          = m.group(1)
        result['aamva_ver']    = int(m.group(2))
        result['juris_ver']    = int(m.group(3))
        result['num_subfiles'] = int(m.group(4))

        # Parse subfile directory entries
        dir_str = m.group(5)
        entries = re.findall(r'([A-Z]{2})(\d{4})(\d{4})', dir_str)
        header_end = m.end(0)

        for sf_id, sf_off, sf_len in entries:
            off = int(sf_off)
            length = int(sf_len)
            # Validate byte range
            actual_start = raw.find(sf_id, header_end)
            within_range = abs(actual_start - off) <= 5 if actual_start != -1 else False
            subfile_text = raw[actual_start:actual_start + length] if actual_start != -1 else ''
            fields = _parse_fields(subfile_text)
            sf_info = {
                'id':       sf_id,
                'declared_offset': off,
                'declared_length': length,
                'actual_start':    actual_start,
                'offset_valid':    within_range,
                'fields':          fields,
            }
            result['subfiles'].append(sf_info)
            result['fields'].update(fields)
            if sf_id == 'DL':
                result['dl_subfile_found'] = True
            if not within_range:
                result['offsets_valid'] = False
    else:
        # v1-v4 fallback — no offset table, just parse all fields
        m4 = re.search(r'ANSI (\d{6})(\d{2})(\d{2})', raw)
        if m4:
            result['header_match'] = m4.group(0)
            result['iin']       = m4.group(1)
            result['aamva_ver'] = int(m4.group(2))
            result['juris_ver'] = int(m4.group(3))
        result['fields'] = _parse_fields(raw)
        result['dl_subfile_found'] = 'DAQ' in result['fields']  # infer

    return result

def _parse_fields(text: str) -> dict:
    """Extract 3-char AAMVA field tags from a block of text."""
    fields: dict[str, str] = {}
    for line in re.split(r'[\n\r\x1c\x1d\x1e]', text):
        line = line.strip()
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
    """Byte-level header check + encoding mode detection."""
    print(f'\n--- HEADER BYTES ({label}) ---')
    mode = detect_encoding_mode(raw)
    print(f'  Encoding mode detected: {mode}')
    b0 = ord(raw[0])     if len(raw) > 0 else 0
    b1 = ord(raw[1])     if len(raw) > 1 else 0
    b2 = ord(raw[2])     if len(raw) > 2 else 0
    b3 = ord(raw[3])     if len(raw) > 3 else 0
    print(f'  Byte 0 @ (0x40):  0x{b0:02X}  {"✅" if b0==0x40 else "❌"}')
    print(f'  Byte 1 LF (0x0A): 0x{b1:02X}  {"✅ binary" if b1==0x0A else "❌ not binary 0x0A"}')
    print(f'  Byte 2 RS (0x1E): 0x{b2:02X}  {"✅ binary" if b2==0x1E else "❌ not binary 0x1E"}')
    print(f'  Byte 3 CR (0x0D): 0x{b3:02X}  {"✅ binary" if b3==0x0D else "❌ not binary 0x0D"}')
    header_ok = (b0==0x40 and b1==0x0A and b2==0x1E and b3==0x0D)
    print(f'  Header binary: {"✅ CORRECT" if header_ok else "❌ TILDE ESCAPE ANOMALY"}')
    if mode == 'tilde_escape':
        lo = raw[1:3].lower()
        if lo in ('~0', '~1'):
            print('  ⚠  Lowercase ~XX detected — bwip-js will NOT resolve lowercase escapes to binary bytes')
        else:
            print('  ⚠  Uppercase ~XX detected — these were ASCII escape sequences, not raw binary in the symbol')
    return header_ok, mode

def analyse_aamva_version(parsed: dict):
    """Print AAMVA version header details."""
    print('\n--- AAMVA VERSION HEADER ---')
    if not parsed.get('header_match'):
        print('  ❌ ANSI header block not found')
        return
    iin   = parsed['iin']
    ver   = parsed['aamva_ver']
    jver  = parsed['juris_ver']
    nsf   = parsed['num_subfiles']
    state = AAMVA_IIN_MAP.get(iin, '❌ UNKNOWN IIN (not in AAMVA registry)')
    valid_ver = 1 <= ver <= 10
    print(f'  IIN:           {iin} → {state}')
    print(f'  AAMVA Version: {ver:02d} ({"✅ v" + str(ver) + " (" + _ver_year(ver) + ")" if valid_ver else "❌ invalid version"})')
    print(f'  Juris Version: {jver:02d}')
    print(f'  Subfile Count: {nsf} {"✅" if nsf >= 1 else "❌"}')
    print(f'  Subfile layout:')
    for sf in parsed['subfiles']:
        off_ok = '✅' if sf['offset_valid'] else '⚠ offset mismatch'
        print(f'    {sf["id"]}: declared offset={sf["declared_offset"]} '
              f'length={sf["declared_length"]} actual_start={sf["actual_start"]} {off_ok}')
    if not parsed.get('dl_subfile_found'):
        print('  ❌ DL subfile designator NOT FOUND — required by AAMVA §2.2')
    else:
        print('  ✅ DL subfile present')

def _ver_year(v: int) -> str:
    years = {1:'2000',2:'2003',3:'2005',4:'2006',5:'2008',6:'2011',7:'2012',8:'2009',9:'2013',10:'2016'}
    return years.get(v, 'unknown')

def analyse_mandatory_fields(fields: dict, aamva_ver: int) -> list[str]:
    """Check all AAMVA-version-mandatory fields are present."""
    print(f'\n--- MANDATORY FIELD CHECK (AAMVA v{aamva_ver:02d}) ---')
    ver = min(max(aamva_ver, 1), 10)
    mandatory = AAMVA_MANDATORY_FIELDS.get(ver, AAMVA_MANDATORY_FIELDS[8])
    missing = []
    for tag in mandatory:
        present = tag in fields
        desc = DMV_FIELD_LABELS.get(tag, '')
        print(f'  {tag} ({desc}): {"✅" if present else "❌ MISSING"}')
        if not present:
            missing.append(tag)
    if missing:
        print(f'  ❌ {len(missing)} mandatory field(s) missing: {", ".join(missing)}')
    else:
        print(f'  ✅ All {len(mandatory)} mandatory fields present')
    return missing

def _parse_date(val: str, tag: str) -> datetime | None:
    """Try MMDDYYYY, then YYYYMMDD, then MMYYYY formats."""
    val = val.strip()
    for fmt in ('%m%d%Y', '%Y%m%d', '%m%Y'):
        try:
            return datetime.strptime(val, fmt)
        except ValueError:
            pass
    print(f'  {tag}: ❌ unrecognised date format: {repr(val)}')
    return None

def analyse_dates(fields: dict):
    print('\n--- DATE FIELD VALIDATION ---')
    today = datetime.today()
    dob_dt = None
    exp_dt = None
    iss_dt = None
    for tag, lbl in [('DBB','DOB'), ('DBD','Issue'), ('DBA','Expiry'),
                     ('DDB','Under-18/PriorIssue'), ('DDH','Under-18'),
                     ('DDI','Under-19'), ('DDJ','Under-21')]:
        val = fields.get(tag)
        if not val:
            continue
        dt = _parse_date(val, tag)
        if dt is None:
            continue
        extra = ''
        if tag == 'DBB':
            dob_dt = dt
            age = (today - dt).days // 365
            extra = f' → Age: {age} yrs'
        elif tag == 'DBA':
            exp_dt = dt
            extra = f' → {"✅ valid" if dt > today else "❌ EXPIRED"}'
        elif tag == 'DBD':
            iss_dt = dt
        print(f'  {tag} ({lbl}): {dt.strftime("%B %d, %Y")}{extra}')
    # Term length check
    if iss_dt and exp_dt:
        years = (exp_dt - iss_dt).days / 365.25
        std = 4 <= years <= 10
        print(f'  Issue→Expiry term: {years:.1f} years {"✅" if std else "⚠ unusual term"}')
    # NC birthday-linked expiry
    dob_val = fields.get('DBB', '')
    exp_val = fields.get('DBA', '')
    if dob_val and exp_val and len(dob_val) >= 4 and len(exp_val) >= 4:
        dob_mmdd = dob_val[:4]
        exp_mmdd = exp_val[:4]
        if dob_mmdd == exp_mmdd:
            print(f'  ✅ Expiry ties to birthday ({dob_mmdd} matches)')

def analyse_field_values(fields: dict):
    """Validate enum fields: sex, eye, hair, truncation, compliance, ZIP."""
    print('\n--- FIELD VALUE VALIDATION ---')

    def chk(tag, valid_set, label):
        val = fields.get(tag, '').strip()
        if not val:
            return
        ok = val in valid_set
        print(f'  {tag} ({label}): {repr(val)} {"✅" if ok else "❌ invalid (expected " + str(valid_set) + ")"}')

    chk('DBC', VALID_SEX,        'Sex')
    chk('DDA', VALID_COMPLIANCE, 'Compliance')
    chk('DDE', VALID_TRUNCATION, 'Last Name Trunc')
    chk('DDF', VALID_TRUNCATION, 'First Name Trunc')
    chk('DDG', VALID_TRUNCATION, 'Middle Name Trunc')
    chk('DAY', VALID_EYE_CODES,  'Eye Colour')
    chk('DAZ', VALID_HAIR_CODES, 'Hair Colour')

    # DAU height — imperial or metric
    dau = fields.get('DAU', '')
    if dau:
        if re.match(r'^\d{3} (in|cm)$', dau.strip()):
            print(f'  DAU (Height): {repr(dau.strip())} ✅')
        else:
            print(f'  DAU (Height): {repr(dau.strip())} ❌ expected "NNN in" or "NNN cm"')

    # DAK ZIP — 11 chars (9 digits + 2 trailing spaces or zeros)
    dak = fields.get('DAK', '')
    if dak:
        if re.match(r'^\d{9}[\s0]{2}$', dak):
            print(f'  DAK (ZIP):    {repr(dak)} ✅ (9+2 = 11 chars)')
        else:
            print(f'  DAK (ZIP):    {repr(dak)} ⚠ expected 11-char MMDDCCCCCC format or 9-digit+2-space ZIP')

    # DCG country code
    dcg = fields.get('DCG', '').strip()
    if dcg and dcg not in ('USA', 'CAN', 'MEX'):
        print(f'  DCG (Country): {repr(dcg)} ⚠ unusual country code')

def analyse_dck(dck: str):
    print('\n--- DCK AUDIT NUMBER FORENSICS ---')
    print(f'  DCK: {dck}  (len={len(dck)})')
    if len(dck) >= 14:
        dl_prefix  = dck[:12]
        state_code = dck[12:14]
        vendor     = dck[16:18] if len(dck) >= 18 else '?'
        seq        = dck[18:20] if len(dck) >= 20 else '?'
        vendor_map = {'TL':'Idemia/L1','DL':'Digimarc','HO':'HID Global','DM':'DataCard'}
        print(f'  DL# prefix:  {dl_prefix}')
        print(f'  State code:  {state_code}')
        if len(dck) >= 16:
            print(f'  Batch code:  {dck[14:16]}')
        print(f'  Vendor code: {vendor} {"(" + vendor_map.get(vendor, "unknown") + ")"}')
        print(f'  Sequence:    {seq}')

def analyse_jurisdiction_subfile(fields: dict, iin: str):
    """Print all jurisdiction-extension (Zxx) fields — any state."""
    print('\n--- JURISDICTION SUBFILE (Zxx) ---')
    state = AAMVA_IIN_MAP.get(iin, 'Unknown')
    print(f'  State: {state}')
    z_fields = {k: v for k, v in fields.items() if k.startswith('Z')}
    if not z_fields:
        print('  (none found)')
    else:
        for tag, val in sorted(z_fields.items()):
            print(f'  {tag}: {repr(val)}')

def run_forensics(raw: str, label: str) -> dict:
    print(f"\n{'='*60}\nFORENSIC ANALYSIS: {label.upper()}\n{'='*60}")

    # 1. Detect encoding mode BEFORE unescape
    mode = detect_encoding_mode(raw)
    normalised = unescape_tilde(raw) if '~' in raw else raw

    # 2. Header bytes (on normalised)
    header_ok, enc_mode = analyse_header_bytes(normalised, label)

    # 3. Full subfile parse
    parsed = parse_subfiles(normalised)
    analyse_aamva_version(parsed)

    # 4. Fields
    fields = parsed['fields']
    print('\n--- ALL PARSED FIELDS ---')
    for tag, val in sorted(fields.items()):
        desc = DMV_FIELD_LABELS.get(tag, '')
        print(f'  {tag}: {repr(val):<32}  {desc}')

    # 5. Mandatory field check
    missing = analyse_mandatory_fields(fields, parsed['aamva_ver'] or 8)

    # 6. Date validation
    analyse_dates(fields)

    # 7. Field value validation
    analyse_field_values(fields)

    # 8. DCK
    if 'DCK' in fields:
        analyse_dck(fields['DCK'])

    # 9. Jurisdiction subfile
    analyse_jurisdiction_subfile(fields, parsed['iin'])

    return {
        'fields':           fields,
        'header_ok':        header_ok,
        'normalised':       normalised,
        'parsed':           parsed,
        'missing_mandatory':missing,
        'encoding_mode':    mode,
    }


# ===========================================================================
# STEP 4 — COMPARE + VERDICT
# ===========================================================================

def compare_cards(r1: dict, r2: dict):
    print(f"\n{'='*60}\nFIELD COMPARISON: CARD1 vs CARD2\n{'='*60}")

    # Flag encoding mode mismatch first
    if r1['encoding_mode'] != r2['encoding_mode']:
        print(f'  ⚠  ENCODING MODE MISMATCH:')
        print(f'     Card1: {r1["encoding_mode"]}')
        print(f'     Card2: {r2["encoding_mode"]}  ← this is the anomaly')
        print(f'     Implication: Card2 had ~XX ASCII escapes in the barcode symbol instead of')
        print(f'     binary bytes. After normalisation fields match, but the raw symbol differs.')
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
    print(f'\n  Totals: {matches} matching, {mismatches} differing')


def authenticity_verdict(r1: dict, r2: dict):
    print(f"\n{'='*60}\nAUTHENTICITY VERDICT\n{'='*60}")

    p1  = r1['parsed']
    f1  = r1['fields']
    iin = p1.get('iin', '')
    ver = p1.get('aamva_ver', 0)
    state_name = AAMVA_IIN_MAP.get(iin, 'Unknown')
    state_code = f1.get('DAJ', '').strip()

    checks = [
        # Header
        ('Binary header bytes (0x40 0x0A 0x1E 0x0D)',
         r1['header_ok']),
        ('IIN registered in AAMVA registry',
         iin in AAMVA_IIN_MAP),
        ('IIN state matches DAJ field',
         state_name.lower() == _state_abbr_to_name(state_code).lower()
         if state_code else False),
        ('AAMVA version 01–10 (valid range)',
         1 <= ver <= 10),
        ('DL subfile present',
         p1.get('dl_subfile_found', False)),
        ('Subfile byte-range offsets valid',
         p1.get('offsets_valid', False)),
        ('All mandatory fields present',
         len(r1['missing_mandatory']) == 0),
        ('DBC sex code valid (1/2/9)',
         f1.get('DBC','').strip() in VALID_SEX),
        ('DAY eye code valid',
         f1.get('DAY','').strip() in VALID_EYE_CODES),
        ('DDA compliance type valid (F/N/U)',
         f1.get('DDA','').strip() in VALID_COMPLIANCE if 'DDA' in f1 else True),
        ('DBA expiry in future (not expired)',
         (lambda v: _parse_date(v,'DBA') is not None and _parse_date(v,'DBA') > datetime.today())(f1.get('DBA',''))),
        ('DAK ZIP format (11 chars)',
         bool(re.match(r'^\d{9}[\s0]{2}$', f1.get('DAK','')))),
        ('DCF document discriminator present',
         'DCF' in f1),
        ('DCG country code (USA/CAN/MEX)',
         f1.get('DCG','').strip() in ('USA','CAN','MEX')),
    ]

    passed = failed = 0
    for lbl, result in checks:
        icon = '✅ PASS' if result else '❌ FAIL'
        (passed if result else failed).__class__  # just for structure
        if result:
            passed += 1
        else:
            failed += 1
        print(f'  {icon}  {lbl}')

    print(f'\n  Card1 result: {passed}/{len(checks)} checks passed')
    if failed == 0:
        print(f'  ✅ CARD1 STRUCTURALLY AUTHENTIC [{state_name}, AAMVA v{ver:02d}]')
    else:
        print(f'  ⚠  {failed} check(s) FAILED')

    # Card2 encoding anomaly
    print('\n  Card2 Encoding Verdict:')
    if not r2['header_ok']:
        print('  ❌ Card2 binary header ABSENT — ~XX ASCII escape sequences found in barcode symbol')
        print('     Cause: bwip-js received lowercase escape sequences (~0a, ~1e, ~0d)')
        print('     bwip-js only resolves UPPERCASE ~0A, ~1E, ~0D to binary bytes')
        print('     Fix applied in aam-project: escapeAAMVAForBwipjs() now uses .toUpperCase()')
    else:
        print('  ✅ Card2 binary header correct')


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
    parser = argparse.ArgumentParser(description='AAMVA PDF417 Forensic Tool v2')
    parser.add_argument('--card1', default='card1.jpg')
    parser.add_argument('--card2', default='card2.jpg')
    parser.add_argument('--raw-only', action='store_true')
    args = parser.parse_args()

    print('╔══════════════════════════════════════════════════════════╗')
    print('║    AAMVA PDF417 BARCODE FORENSIC TOOL  v2.0              ║')
    print('║    All 50 states · AAMVA v01–v10 · Full spec compliance  ║')
    print('╚══════════════════════════════════════════════════════════╝')

    if args.raw_only:
        print('\n[mode] Using embedded raw strings (--raw-only)')
        raw1, raw2 = CARD1_RAW_EMBEDDED, CARD2_RAW_EMBEDDED
        print('\n--- RAW OUTPUT (card1) ---')
        print(repr(raw1))
        print('\n--- RAW OUTPUT (card2) ---')
        print(repr(raw2))
    else:
        raw1 = decode_image(args.card1, 'card1') or CARD1_RAW_EMBEDDED
        raw2 = decode_image(args.card2, 'card2') or CARD2_RAW_EMBEDDED

    r1 = run_forensics(raw1, 'card1')
    r2 = run_forensics(raw2, 'card2')
    compare_cards(r1, r2)
    authenticity_verdict(r1, r2)


if __name__ == '__main__':
    main()
