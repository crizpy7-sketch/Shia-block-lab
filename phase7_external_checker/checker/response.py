"""Bounded inert HTTP response normalization; no raw remote values escape."""
import re

HEADER_CAP = 8192
BODY_CAP = 16384
TOTAL_CAP = HEADER_CAP + BODY_CAP + 1
FIELD_CAP = 64
LOGIN_URL = b'https://michel-pr20-377eb54-2-24-81-191.sslip.io/authelia/'
MARKERS = (
    b'MP20_PROTECTED_HTML_377eb54', b'MP20_PROTECTED_ASSET_377eb54',
    b'MP20_PROTECTED_JSON_377eb54', b'MP20_READY_377eb54',
)
ERROR_CODES = frozenset({
    'INPUT_TYPE', 'TOTAL_CAP', 'HEADER_CAP', 'INCOMPLETE_HEADER', 'EARLY_EOF',
    'BAD_LINE_ENDING', 'STATUS_LINE', 'HEADER_COUNT', 'HEADER_FORMAT',
    'HEADER_CONTROL', 'DUPLICATE_HEADER', 'AMBIGUOUS_FRAMING',
    'UNSUPPORTED_TRANSFER_ENCODING', 'UNSUPPORTED_CONTENT_ENCODING',
    'CONTENT_LENGTH', 'BODY_CAP', 'EXTRA_DATA', 'BODY_FORBIDDEN',
    'INTERIM_UNSUPPORTED',
})


class ParseError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in ERROR_CODES else 'INPUT_TYPE'
        super().__init__(self.code)


def scan_markers(data):
    """Positive markers in partial bytes are exposure; absence is not success."""
    if type(data) is not bytes:
        raise ParseError('INPUT_TYPE')
    if len(data) > TOTAL_CAP:
        raise ParseError('TOTAL_CAP')
    return [marker in data for marker in MARKERS]


def _cache_flags(value):
    # Commas in extension quoted-strings must not manufacture a bare private
    # directive. Unknown/malformed cache syntax never earns positive flags.
    parts = []
    start = 0
    quoted = escaped = False
    for index, byte in enumerate(value):
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte == 44:
            parts.append(value[start:index].strip(b' ').lower())
            start = index + 1
    if quoted or escaped:
        return False, False
    parts.append(value[start:].strip(b' ').lower())
    return b'private' in parts, b'no-store' in parts


def parse_response(data, eof):
    """Normalize one bounded HTTP/1.0 or HTTP/1.1 response.

    Complete Content-Length bodies are recognized without requiring EOF here;
    the fixed network reader conservatively also waits for a clean EOF. Partial
    EOF-delimited input is never complete. Unsupported framing is inconclusive.
    """
    if type(data) is not bytes or type(eof) is not bool:
        raise ParseError('INPUT_TYPE')
    if len(data) > TOTAL_CAP:
        raise ParseError('TOTAL_CAP')
    end = data.find(b'\r\n\r\n')
    if end < 0:
        # Missing terminator never makes a partial header eligible.
        if len(data) > HEADER_CAP:
            raise ParseError('HEADER_CAP')
        residual = data.replace(b'\r\n', b'')
        # A last CR may be the first half of the next CRLF fragment.
        if b'\n' in residual or b'\r' in residual[:-1]:
            raise ParseError('BAD_LINE_ENDING')
        raise ParseError('EARLY_EOF' if eof else 'INCOMPLETE_HEADER')
    header_size = end + 4
    if header_size > HEADER_CAP:
        raise ParseError('HEADER_CAP')
    header = data[:end]
    if b'\r' in header.replace(b'\r\n', b'') or b'\n' in header.replace(b'\r\n', b''):
        raise ParseError('BAD_LINE_ENDING')
    lines = header.split(b'\r\n')
    match = re.fullmatch(br'HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?', lines[0])
    if match is None:
        raise ParseError('STATUS_LINE')
    status = int(match.group(1))
    if 100 <= status < 200:
        raise ParseError('INTERIM_UNSUPPORTED')
    if len(lines) - 1 > FIELD_CAP:
        raise ParseError('HEADER_COUNT')
    fields = {}
    duplicate = False
    for line in lines[1:]:
        if not line or line[:1] in (b' ', b'\t') or b':' not in line:
            raise ParseError('HEADER_FORMAT')
        name, value = line.split(b':', 1)
        if re.fullmatch(br"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
            raise ParseError('HEADER_FORMAT')
        if any(byte < 32 or byte == 127 for byte in value):
            raise ParseError('HEADER_CONTROL')
        name = name.lower()
        if name in fields:
            duplicate = True
        else:
            fields[name] = value.strip(b' ')
    if b'content-length' in fields and b'transfer-encoding' in fields:
        raise ParseError('AMBIGUOUS_FRAMING')
    if b'transfer-encoding' in fields:
        raise ParseError('UNSUPPORTED_TRANSFER_ENCODING')
    if duplicate:
        raise ParseError('DUPLICATE_HEADER')
    if b'content-encoding' in fields and fields[b'content-encoding'].lower() != b'identity':
        raise ParseError('UNSUPPORTED_CONTENT_ENCODING')
    body = data[header_size:]
    if len(body) > BODY_CAP:
        raise ParseError('BODY_CAP')
    length = None
    if b'content-length' in fields:
        token = fields[b'content-length']
        if not token or len(token) > 5 or re.fullmatch(br'[0-9]+', token) is None:
            raise ParseError('CONTENT_LENGTH')
        length = int(token)
        if length > BODY_CAP:
            raise ParseError('BODY_CAP')
        if len(body) > length:
            raise ParseError('EXTRA_DATA')
        if eof and len(body) != length:
            raise ParseError('EARLY_EOF')
    if status in (204, 304):
        if body or length not in (None, 0):
            raise ParseError('BODY_FORBIDDEN')
        complete = True
    else:
        complete = len(body) == length if length is not None else eof
    private, no_store = _cache_flags(fields.get(b'cache-control', b''))
    location = ('ABSENT' if b'location' not in fields else
                'EXACT_LOGIN' if fields[b'location'] == LOGIN_URL else 'OTHER')
    age = ('ABSENT' if b'age' not in fields else
           'ZERO' if fields[b'age'] == b'0' else 'OTHER')
    return {'status': status, 'private': private, 'no_store': no_store,
            'location': location, 'age': age, 'markers': scan_markers(data),
            'complete': complete}
