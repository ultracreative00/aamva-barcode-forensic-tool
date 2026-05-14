#!/usr/bin/env python3
"""
AAMVA Forensic Tool — Localhost Web UI
Run:  python app.py
Open: http://localhost:8000

Multipart parsing uses the stdlib `email` package (Python 3.0+) instead of
the deprecated `cgi` module (removed in Python 3.13).
"""
import io
import sys
import json
import traceback
import tempfile
import os
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from email import message_from_bytes
from email.policy import HTTP as HTTPPolicy

# ── bootstrap deps ────────────────────────────────────────────────
for pkg, name in [('PIL', 'Pillow'), ('pdf417decoder', 'pdf417decoder')]:
    try:
        __import__(pkg)
    except ImportError:
        import subprocess
        subprocess.run([sys.executable, '-m', 'pip', 'install', name, '-q'])

# ── import forensic engine ─────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from aamva_forensic import (
    decode_image,
    unescape_tilde,
    detect_encoding_mode,
    parse_subfiles,
    AAMVA_IIN_MAP,
    DMV_FIELD_LABELS,
    VALID_SEX, VALID_EYE_CODES, VALID_HAIR_CODES,
    VALID_TRUNCATION, VALID_COMPLIANCE,
    _state_abbr_to_name,
    AAMVA_MANDATORY_FIELDS,
)
import re
from datetime import datetime

PORT = 8000
TEMPLATES = Path(__file__).parent / 'templates'


# ── multipart parser (no cgi dependency) ─────────────────────────
def parse_multipart(content_type: str, body: bytes) -> list:
    """
    Parse multipart/form-data body without the deprecated `cgi` module.
    Returns list of (filename, file_bytes) tuples for every uploaded file.
    """
    # Build a minimal RFC-2822 message so email.message_from_bytes can parse it
    raw = b'Content-Type: ' + content_type.encode() + b'\r\n\r\n' + body
    msg = message_from_bytes(raw, policy=HTTPPolicy)
    files = []
    for part in msg.walk():
        cd = part.get('Content-Disposition', '')
        if 'filename' not in cd:
            continue
        # extract filename from Content-Disposition
        fname = None
        for token in cd.split(';'):
            token = token.strip()
            if token.lower().startswith('filename='):
                fname = token.split('=', 1)[1].strip().strip('"')
        if fname:
            files.append((fname, part.get_payload(decode=True) or b''))
    return files


def analyse_card(path: str, label: str) -> dict:
    """Run full forensic analysis on one file; return JSON-safe dict."""
    result = {
        'label':   label,
        'file':    Path(path).name,
        'status':  'error',
        'error':   None,
        'encoding_mode': 'unknown',
        'header_ok': False,
        'iin': '',
        'state_name': '',
        'aamva_ver': 0,
        'juris_ver': 0,
        'num_subfiles': 0,
        'dl_subfile_found': False,
        'offsets_valid': True,
        'subfiles': [],
        'fields': {},
        'missing_mandatory': [],
        'field_errors': [],
        'dates': [],
        'verdict_checks': [],
        'verdict_passed': 0,
        'verdict_failed': 0,
        'raw_preview': '',
    }
    try:
        raw = decode_image(path, label)
        if not raw:
            result['error'] = 'Could not decode barcode from image (zbar/pdf417decoder found no PDF417 symbol)'
            return result

        mode = detect_encoding_mode(raw)
        result['encoding_mode'] = mode
        normalised = unescape_tilde(raw) if '~' in raw else raw
        result['raw_preview'] = repr(normalised[:400])

        b0 = ord(normalised[0]) if len(normalised) > 0 else 0
        b1 = ord(normalised[1]) if len(normalised) > 1 else 0
        b2 = ord(normalised[2]) if len(normalised) > 2 else 0
        b3 = ord(normalised[3]) if len(normalised) > 3 else 0
        header_ok = (b0 == 0x40 and b1 == 0x0A and b2 == 0x1E and b3 == 0x0D)
        result['header_ok'] = header_ok

        parsed = parse_subfiles(normalised)
        result['iin']             = parsed.get('iin', '')
        result['aamva_ver']       = parsed.get('aamva_ver', 0)
        result['juris_ver']       = parsed.get('juris_ver', 0)
        result['num_subfiles']    = parsed.get('num_subfiles', 0)
        result['dl_subfile_found']= parsed.get('dl_subfile_found', False)
        result['offsets_valid']   = parsed.get('offsets_valid', True)
        result['state_name']      = AAMVA_IIN_MAP.get(result['iin'], 'Unknown')

        sf_list = []
        for sf in parsed.get('subfiles', []):
            sf_list.append({
                'id':     sf['id'],
                'offset': sf['declared_offset'],
                'length': sf['declared_length'],
                'valid':  sf['offset_valid'],
            })
        result['subfiles'] = sf_list

        fields = parsed.get('fields', {})
        result['fields'] = {
            k: {'val': v, 'label': DMV_FIELD_LABELS.get(k, '')}
            for k, v in sorted(fields.items())
        }

        ver = min(max(result['aamva_ver'], 1), 10)
        mandatory = AAMVA_MANDATORY_FIELDS.get(ver, AAMVA_MANDATORY_FIELDS[8])
        missing = [t for t in mandatory if t not in fields]
        result['missing_mandatory'] = missing

        errs = []
        def chk(tag, valid_set):
            val = fields.get(tag, '').strip()
            if val and val not in valid_set:
                errs.append(f'{tag}={repr(val)} invalid (expected {sorted(valid_set)})')
        chk('DBC', VALID_SEX)
        chk('DDA', VALID_COMPLIANCE)
        chk('DDE', VALID_TRUNCATION)
        chk('DDF', VALID_TRUNCATION)
        chk('DDG', VALID_TRUNCATION)
        chk('DAY', VALID_EYE_CODES)
        chk('DAZ', VALID_HAIR_CODES)
        dau = fields.get('DAU', '')
        if dau and not re.match(r'^\d{3} (in|cm)$', dau.strip()):
            errs.append(f'DAU={repr(dau)} invalid height format')
        dak = fields.get('DAK', '')
        if dak and not re.match(r'^\d{9}[\s0]{2}$', dak):
            errs.append(f'DAK={repr(dak)} invalid ZIP format (expected 11 chars)')
        result['field_errors'] = errs

        today = datetime.today()
        date_rows = []
        for tag, lbl in [('DBB','DOB'), ('DBD','Issue Date'), ('DBA','Expiry'),
                         ('DDB','Under-18/Prior'), ('DDH','Under-18'), ('DDJ','Under-21')]:
            val = fields.get(tag)
            if not val:
                continue
            dt = None
            for fmt in ('%m%d%Y', '%Y%m%d', '%m%Y'):
                try:
                    dt = datetime.strptime(val.strip(), fmt)
                    break
                except ValueError:
                    pass
            if dt:
                extra = ''
                if tag == 'DBB':
                    extra = f'Age {(today-dt).days//365}'
                elif tag == 'DBA':
                    extra = 'Valid' if dt > today else '\u26a0 EXPIRED'
                date_rows.append({'tag': tag, 'label': lbl,
                                  'date': dt.strftime('%b %d, %Y'), 'note': extra})
        result['dates'] = date_rows

        iin_ok = result['iin'] in AAMVA_IIN_MAP
        state_code = fields.get('DAJ', '').strip()
        iin_state_match = (
            result['state_name'].lower() == _state_abbr_to_name(state_code).lower()
            if state_code else False
        )
        exp_val = fields.get('DBA', '')
        exp_ok = False
        if exp_val:
            for fmt in ('%m%d%Y', '%Y%m%d'):
                try:
                    exp_ok = datetime.strptime(exp_val.strip(), fmt) > today
                    break
                except ValueError:
                    pass

        checks = [
            ('Binary header (0x40 0x0A 0x1E 0x0D)',  header_ok),
            ('IIN registered in AAMVA',               iin_ok),
            ('IIN state matches DAJ field',           iin_state_match),
            ('AAMVA version 01\u201310',              1 <= result['aamva_ver'] <= 10),
            ('DL subfile present',                    result['dl_subfile_found']),
            ('Subfile byte offsets valid',             result['offsets_valid']),
            ('All mandatory fields present',          len(missing) == 0),
            ('No field value errors',                 len(errs) == 0),
            ('Expiry date in future',                 exp_ok),
            ('DAK ZIP format correct',                len([e for e in errs if 'DAK' in e]) == 0),
            ('DCF document discriminator present',    'DCF' in fields),
            ('DCG country code valid',                fields.get('DCG','').strip() in ('USA','CAN','MEX')),
        ]
        passed = sum(1 for _, v in checks if v)
        failed = len(checks) - passed
        result['verdict_checks'] = [{'label': l, 'ok': v} for l, v in checks]
        result['verdict_passed'] = passed
        result['verdict_failed'] = failed
        result['status'] = 'authentic' if failed == 0 else ('warn' if failed <= 2 else 'fail')

    except Exception:
        result['error'] = traceback.format_exc()
        result['status'] = 'error'

    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f'[{self.address_string()}] {fmt % args}')

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            html = (TEMPLATES / 'index.html').read_text(encoding='utf-8')
            self.respond(200, 'text/html; charset=utf-8', html.encode('utf-8'))
        else:
            self.respond(404, 'text/plain', b'Not found')

    def do_POST(self):
        if self.path == '/analyse':
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' not in content_type:
                self.respond(400, 'application/json',
                             json.dumps({'error': 'Expected multipart/form-data'}).encode())
                return

            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)

            try:
                uploaded = parse_multipart(content_type, body)
            except Exception as e:
                self.respond(400, 'application/json',
                             json.dumps({'error': f'Multipart parse error: {e}'}).encode())
                return

            if not uploaded:
                self.respond(400, 'application/json',
                             json.dumps({'error': 'No files received — check form field name is "files"'}).encode())
                return

            results = []
            for fname, fbytes in uploaded:
                suffix = Path(fname).suffix or '.jpg'
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                    tmp.write(fbytes)
                    tmp_path = tmp.name
                try:
                    r = analyse_card(tmp_path, fname)
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                results.append(r)

            self.respond(200, 'application/json', json.dumps(results).encode())
        else:
            self.respond(404, 'application/json', b'{"error":"not found"}')

    def respond(self, code: int, ctype: str, body: bytes):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    TEMPLATES.mkdir(exist_ok=True)
    print(f'\n\U0001f50d  AAMVA Forensic Tool  \u2014 http://localhost:{PORT}')
    print(f'    Press Ctrl+C to stop\n')
    HTTPServer(('localhost', PORT), Handler).serve_forever()
