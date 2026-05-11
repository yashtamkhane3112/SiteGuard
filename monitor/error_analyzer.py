import re
from collections import OrderedDict

from django.db import transaction

from .models import ParsedError


TRACEBACK_START_RE = re.compile(r'^Traceback \(most recent call last\):')
KEYWORD_ERROR_RE = re.compile(
    r'(?i)\b('
    r'OperationalError|IntegrityError|ValueError|TypeError|KeyError|IndexError|'
    r'AttributeError|RuntimeError|AssertionError|PermissionError|TimeoutError|'
    r'ConnectionError|RefusedError|DeniedError|Error|Exception'
    r')\b'
)
HTTP_STATUS_RE = re.compile(r'(?<!\d)(500|404)(?!\d)')
ERROR_SIGNAL_RE = re.compile(
    r'(?i)('
    r'Traceback|Exception:|Error:|OperationalError|IntegrityError|500|404|timeout|'
    r'failed|denied|refused'
    r')'
)


def normalize_error_line(raw_line):
    return re.sub(r'\s+', ' ', (raw_line or '').strip())


def get_error_type(raw_line):
    line = normalize_error_line(raw_line)
    http_match = HTTP_STATUS_RE.search(line)
    if http_match:
        return f"HTTP {http_match.group(1)}"

    lowered = line.lower()
    for keyword in ('timeout', 'refused', 'denied', 'failed'):
        if keyword in lowered:
            return keyword

    keyword_match = KEYWORD_ERROR_RE.search(line)
    if keyword_match:
        return keyword_match.group(1)
    return 'Unknown Error'


def iter_error_entries(log_text):
    lines = (log_text or '').splitlines()
    index = 0
    while index < len(lines):
        current_line = lines[index].rstrip()
        stripped = current_line.strip()

        if TRACEBACK_START_RE.match(stripped):
            block_lines = [stripped]
            first_seen_line = index + 1
            index += 1
            while index < len(lines):
                next_line = lines[index].rstrip()
                next_stripped = next_line.strip()
                if not next_stripped:
                    index += 1
                    break
                block_lines.append(next_stripped)
                index += 1
                if (
                    not next_line.startswith((' ', '\t'))
                    and (
                        KEYWORD_ERROR_RE.search(next_stripped)
                        or next_stripped.endswith('Error:')
                        or next_stripped.endswith('Exception:')
                    )
                ):
                    break

            terminal_line = next(
                (line for line in reversed(block_lines) if line and line != 'Traceback (most recent call last):'),
                'Traceback (most recent call last):',
            )
            yield {
                'error_type': get_error_type(terminal_line),
                'raw_line': normalize_error_line(terminal_line),
                'first_seen_line': first_seen_line,
            }
            continue

        if stripped and ERROR_SIGNAL_RE.search(stripped):
            yield {
                'error_type': get_error_type(stripped),
                'raw_line': normalize_error_line(stripped),
                'first_seen_line': index + 1,
            }

        index += 1


def parse_log_content(log_text):
    grouped_errors = OrderedDict()
    total_detected_errors = 0

    for entry in iter_error_entries(log_text):
        total_detected_errors += 1
        group_key = (entry['error_type'], entry['raw_line'])
        if group_key not in grouped_errors:
            grouped_errors[group_key] = {
                'error_type': entry['error_type'],
                'raw_line': entry['raw_line'],
                'count': 1,
                'first_seen_line': entry['first_seen_line'],
            }
            continue

        grouped_errors[group_key]['count'] += 1
        grouped_errors[group_key]['first_seen_line'] = min(
            grouped_errors[group_key]['first_seen_line'],
            entry['first_seen_line'],
        )

    parsed_errors = sorted(
        grouped_errors.values(),
        key=lambda item: (-item['count'], item['first_seen_line'], item['error_type']),
    )
    return {
        'total_detected_errors': total_detected_errors,
        'parsed_errors': parsed_errors,
    }


@transaction.atomic
def process_uploaded_log(uploaded_log):
    uploaded_log.parsed_errors.all().delete()

    uploaded_log.file.open('rb')
    try:
        log_bytes = uploaded_log.file.read()
    finally:
        uploaded_log.file.close()

    log_text = log_bytes.decode('utf-8', errors='replace')
    parsed_result = parse_log_content(log_text)

    ParsedError.objects.bulk_create([
        ParsedError(
            uploaded_log=uploaded_log,
            error_type=entry['error_type'],
            raw_line=entry['raw_line'],
            count=entry['count'],
            first_seen_line=entry['first_seen_line'],
        )
        for entry in parsed_result['parsed_errors']
    ])

    uploaded_log.processed = True
    uploaded_log.save(update_fields=['processed'])
    return parsed_result
