import re
from collections import Counter, OrderedDict, defaultdict

from django.db import transaction

from .models import ParsedError


TRACEBACK_START_RE = re.compile(r'^Traceback \(most recent call last\):')
KEYWORD_ERROR_RE = re.compile(
    r'(?i)\b('
    r'OperationalError|IntegrityError|ValueError|TypeError|KeyError|IndexError|'
    r'AttributeError|RuntimeError|AssertionError|PermissionError|TimeoutError|'
    r'ConnectionError|RefusedError|DeniedError|ProgrammingError|ImproperlyConfigured|'
    r'AuthenticationFailed|PermissionDenied|DoesNotExist|ValidationError|SyntaxError|'
    r'ImportError|ModuleNotFoundError|Error|Exception'
    r')\b'
)
HTTP_STATUS_RE = re.compile(r'(?<!\d)(500|404|401|403|502|503|504)(?!\d)')
ERROR_SIGNAL_RE = re.compile(
    r'(?i)('
    r'Traceback|Exception:|Error:|OperationalError|IntegrityError|500|404|401|403|502|503|504|'
    r'timeout|failed|denied|refused|forbidden|unauthorized|network|django'
    r')'
)


DIAGNOSTIC_RULES = [
    {
        'pattern': re.compile(r'(?i)(OperationalError|ProgrammingError|database is locked|could not connect to server|psycopg|sqlite|mysql|postgres)'),
        'category': ParsedError.CATEGORY_DATABASE,
        'severity': ParsedError.SEVERITY_CRITICAL,
        'probable_cause': 'Database connectivity or schema state is preventing the request from completing.',
        'suggested_checks': [
            'Check the configured database connection and credentials.',
            'Run pending migrations and confirm the target schema is current.',
            'Inspect database availability, locks, and connection pool limits.',
        ],
        'remediation_tips': [
            'Verify DB host, port, and environment variables.',
            'Run `python manage.py migrate` if schema drift is suspected.',
            'Review recent deploys for broken queries or missing tables.',
        ],
    },
    {
        'pattern': re.compile(r'(?i)(IntegrityError|unique constraint|foreign key constraint|not null constraint)'),
        'category': ParsedError.CATEGORY_DATABASE,
        'severity': ParsedError.SEVERITY_HIGH,
        'probable_cause': 'Persisted data violated an integrity rule or relational constraint.',
        'suggested_checks': [
            'Inspect the payload being written to the database.',
            'Review uniqueness, nullability, and foreign-key expectations.',
            'Look for duplicate inserts or missing dependent records.',
        ],
        'remediation_tips': [
            'Add validation before writes when input is user controlled.',
            'Review recent migrations for changed constraints.',
            'Backfill or clean inconsistent records if the issue is historical.',
        ],
    },
    {
        'pattern': re.compile(r'(?i)(timeout|timed out|TimeoutError|gateway timeout|deadline exceeded)'),
        'category': ParsedError.CATEGORY_TIMEOUT,
        'severity': ParsedError.SEVERITY_MEDIUM,
        'probable_cause': 'The request exceeded an expected execution or network timeout window.',
        'suggested_checks': [
            'Inspect upstream latency and endpoint response times.',
            'Review firewall, proxy, or DNS behavior along the request path.',
            'Confirm timeout thresholds are appropriate for the workload.',
        ],
        'remediation_tips': [
            'Reduce slow downstream dependencies where possible.',
            'Raise timeout settings only after confirming the bottleneck.',
            'Capture timing metrics around the failing endpoint.',
        ],
    },
    {
        'pattern': re.compile(r'(?i)(401|403|AuthenticationFailed|PermissionDenied|forbidden|unauthorized|invalid token|login required|access denied)'),
        'category': ParsedError.CATEGORY_AUTHENTICATION,
        'severity': ParsedError.SEVERITY_HIGH,
        'probable_cause': 'Authentication or authorization rules blocked access to the requested resource.',
        'suggested_checks': [
            'Verify session, token, or credential validity.',
            'Review permission checks and role assignments.',
            'Confirm protected routes are using the intended auth flow.',
        ],
        'remediation_tips': [
            'Refresh expired credentials or tokens.',
            'Inspect auth middleware and permission decorators.',
            'Audit recent auth-related config changes.',
        ],
    },
    {
        'pattern': re.compile(r'(?i)(404|not found|NoReverseMatch|DoesNotExist)'),
        'category': ParsedError.CATEGORY_HTTP,
        'severity': ParsedError.SEVERITY_LOW,
        'probable_cause': 'The requested route, object, or resource could not be resolved.',
        'suggested_checks': [
            'Verify the route, slug, or object identifier exists.',
            'Inspect frontend links and server-side URL generation.',
            'Check whether the resource was deleted or renamed.',
        ],
        'remediation_tips': [
            'Restore or redirect missing routes where appropriate.',
            'Add guardrails for missing objects in the view layer.',
            'Update stale links in the UI or emails.',
        ],
    },
    {
        'pattern': re.compile(r'(?i)(500|502|503|504|bad gateway|service unavailable)'),
        'category': ParsedError.CATEGORY_HTTP,
        'severity': ParsedError.SEVERITY_HIGH,
        'probable_cause': 'A server-side request failed while handling or proxying the response.',
        'suggested_checks': [
            'Inspect application logs around the upstream or handler failure.',
            'Verify dependent services are healthy.',
            'Check whether deploy-time configuration changed unexpectedly.',
        ],
        'remediation_tips': [
            'Trace the upstream dependency returning the failure.',
            'Review error rates and deploy rollouts around the same timestamp.',
            'Add targeted retries only where the failure mode is transient.',
        ],
    },
    {
        'pattern': re.compile(r'(?i)(ConnectionError|RefusedError|network|socket|dns|refused|reset by peer|connection aborted|name or service not known|failed to resolve)'),
        'category': ParsedError.CATEGORY_NETWORK,
        'severity': ParsedError.SEVERITY_HIGH,
        'probable_cause': 'The application could not establish or sustain a network connection.',
        'suggested_checks': [
            'Inspect DNS resolution, firewall, and proxy configuration.',
            'Verify the target service is reachable from the runtime environment.',
            'Check whether connection limits or network policies changed.',
        ],
        'remediation_tips': [
            'Validate outbound connectivity from the host or container.',
            'Review retry storms or circuit-breaker settings.',
            'Confirm upstream hostnames and ports are still correct.',
        ],
    },
    {
        'pattern': re.compile(r'(?i)(ImproperlyConfigured|TemplateSyntaxError|FieldError|ValidationError|ModuleNotFoundError|ImportError|AttributeError|django)'),
        'category': ParsedError.CATEGORY_DJANGO,
        'severity': ParsedError.SEVERITY_MEDIUM,
        'probable_cause': 'Application configuration, imports, or Django-level assumptions are out of sync with runtime behavior.',
        'suggested_checks': [
            'Inspect settings, imports, and template usage around the failing path.',
            'Review recent model, form, or template changes.',
            'Confirm dependencies and environment variables are present.',
        ],
        'remediation_tips': [
            'Run Django checks and verify the intended settings module.',
            'Compare local and deployment environments for drift.',
            'Add targeted tests around the failing view or form.',
        ],
    },
    {
        'pattern': re.compile(r'(?i)(javascript|TypeError: Cannot|ReferenceError|frontend|react|vue|webpack|chunk load)'),
        'category': ParsedError.CATEGORY_FRONTEND,
        'severity': ParsedError.SEVERITY_MEDIUM,
        'probable_cause': 'Client-side code failed to load, execute, or locate the expected DOM or asset state.',
        'suggested_checks': [
            'Inspect browser console logs and asset loading behavior.',
            'Verify routes reference valid scripts and static assets.',
            'Check whether the expected DOM elements exist before JS runs.',
        ],
        'remediation_tips': [
            'Harden client-side guards around optional UI elements.',
            'Verify collectstatic output and cache invalidation.',
            'Review recently changed template IDs or event hooks.',
        ],
    },
    {
        'pattern': re.compile(r'(?i)(csrf|xss|ssl|tls|certificate|permission denied|forbidden host|securityerror)'),
        'category': ParsedError.CATEGORY_SECURITY,
        'severity': ParsedError.SEVERITY_HIGH,
        'probable_cause': 'A security control, certificate issue, or policy check blocked the operation.',
        'suggested_checks': [
            'Inspect CSRF, SSL, and host validation settings.',
            'Review certificate validity and trusted origin configuration.',
            'Check whether a permission policy is intentionally denying the request.',
        ],
        'remediation_tips': [
            'Align trusted origins and host settings with the deployed domain.',
            'Rotate expired certificates or invalid keys.',
            'Review security middleware and proxy headers.',
        ],
    },
]


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
            return keyword.title()

    keyword_match = KEYWORD_ERROR_RE.search(line)
    if keyword_match:
        return keyword_match.group(1)
    return 'Unknown Error'


def classify_error(error_type, raw_line):
    haystack = f"{error_type} {normalize_error_line(raw_line)}"
    for rule in DIAGNOSTIC_RULES:
        if rule['pattern'].search(haystack):
            return {
                'category': rule['category'],
                'severity': rule['severity'],
                'probable_cause': rule['probable_cause'],
                'suggested_checks': list(rule['suggested_checks']),
                'remediation_tips': list(rule['remediation_tips']),
            }

    return {
        'category': ParsedError.CATEGORY_UNKNOWN,
        'severity': ParsedError.SEVERITY_LOW,
        'probable_cause': 'The current parser matched an error signal but could not classify the underlying subsystem confidently.',
        'suggested_checks': [
            'Inspect the surrounding stack trace and neighboring log lines.',
            'Search for repeated patterns across multiple uploads.',
            'Compare this failure with recent deploys or config changes.',
        ],
        'remediation_tips': [
            'Add a new signature rule when this pattern becomes common.',
            'Capture more contextual lines around the error source.',
            'Promote the issue to a named category once the root cause is clearer.',
        ],
    }


def get_error_diagnostics(parsed_error):
    return classify_error(parsed_error.error_type, parsed_error.raw_line)


def iter_error_entries(log_text):
    lines = (log_text or '').splitlines()
    index = 0
    while index < len(lines):
        current_line = lines[index].rstrip()
        stripped = current_line.strip()

        if TRACEBACK_START_RE.match(stripped):
            block_lines = [stripped]
            first_seen_line = index + 1
            last_seen_line = first_seen_line
            index += 1
            while index < len(lines):
                next_line = lines[index].rstrip()
                next_stripped = next_line.strip()
                if not next_stripped:
                    index += 1
                    break
                block_lines.append(next_stripped)
                last_seen_line = index + 1
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
                'last_seen_line': last_seen_line,
            }
            continue

        if stripped and ERROR_SIGNAL_RE.search(stripped):
            line_number = index + 1
            yield {
                'error_type': get_error_type(stripped),
                'raw_line': normalize_error_line(stripped),
                'first_seen_line': line_number,
                'last_seen_line': line_number,
            }

        index += 1


def parse_log_content(log_text):
    grouped_errors = OrderedDict()
    total_detected_errors = 0

    for entry in iter_error_entries(log_text):
        total_detected_errors += 1
        group_key = (entry['error_type'], entry['raw_line'])
        diagnostics = classify_error(entry['error_type'], entry['raw_line'])
        if group_key not in grouped_errors:
            grouped_errors[group_key] = {
                'error_type': entry['error_type'],
                'raw_line': entry['raw_line'],
                'count': 1,
                'first_seen_line': entry['first_seen_line'],
                'last_seen_line': entry['last_seen_line'],
                'category': diagnostics['category'],
                'severity': diagnostics['severity'],
            }
            continue

        grouped_errors[group_key]['count'] += 1
        grouped_errors[group_key]['first_seen_line'] = min(
            grouped_errors[group_key]['first_seen_line'],
            entry['first_seen_line'],
        )
        grouped_errors[group_key]['last_seen_line'] = max(
            grouped_errors[group_key]['last_seen_line'],
            entry['last_seen_line'],
        )

    parsed_errors = sorted(
        grouped_errors.values(),
        key=lambda item: (-item['count'], item['first_seen_line'], item['error_type']),
    )
    return {
        'total_detected_errors': total_detected_errors,
        'parsed_errors': parsed_errors,
    }


def build_upload_analytics(uploaded_log):
    parsed_errors = list(uploaded_log.parsed_errors.all().order_by('-count', 'first_seen_line', 'id'))
    total_occurrences = sum(item.count for item in parsed_errors)
    severity_counter = Counter(item.severity for item in parsed_errors)
    category_counter = Counter(item.category for item in parsed_errors)
    recurring_errors = [item for item in parsed_errors if item.count > 1]
    top_recurring_errors = recurring_errors[:5]

    grouped_by_error_type = defaultdict(lambda: {'total_count': 0, 'max_severity': ParsedError.SEVERITY_LOW, 'categories': Counter()})
    severity_rank = {
        ParsedError.SEVERITY_CRITICAL: 4,
        ParsedError.SEVERITY_HIGH: 3,
        ParsedError.SEVERITY_MEDIUM: 2,
        ParsedError.SEVERITY_LOW: 1,
    }
    for item in parsed_errors:
        bucket = grouped_by_error_type[item.error_type]
        bucket['total_count'] += item.count
        bucket['categories'][item.category] += item.count
        if severity_rank[item.severity] > severity_rank[bucket['max_severity']]:
            bucket['max_severity'] = item.severity

    grouped_results = []
    for error_type, data in sorted(grouped_by_error_type.items(), key=lambda pair: (-pair[1]['total_count'], pair[0].lower())):
        dominant_category = data['categories'].most_common(1)[0][0] if data['categories'] else ParsedError.CATEGORY_UNKNOWN
        grouped_results.append({
            'error_type': error_type,
            'total_count': data['total_count'],
            'severity': data['max_severity'],
            'category': dominant_category,
        })

    severity_rows = [
        {
            'key': severity_key,
            'label': dict(ParsedError.SEVERITY_CHOICES)[severity_key],
            'count': severity_counter.get(severity_key, 0),
        }
        for severity_key in (
            ParsedError.SEVERITY_CRITICAL,
            ParsedError.SEVERITY_HIGH,
            ParsedError.SEVERITY_MEDIUM,
            ParsedError.SEVERITY_LOW,
        )
    ]
    category_rows = [
        {
            'key': category_key,
            'label': dict(ParsedError.CATEGORY_CHOICES)[category_key],
            'count': category_counter.get(category_key, 0),
        }
        for category_key in (
            ParsedError.CATEGORY_DATABASE,
            ParsedError.CATEGORY_AUTHENTICATION,
            ParsedError.CATEGORY_TIMEOUT,
            ParsedError.CATEGORY_HTTP,
            ParsedError.CATEGORY_NETWORK,
            ParsedError.CATEGORY_DJANGO,
            ParsedError.CATEGORY_FRONTEND,
            ParsedError.CATEGORY_SECURITY,
            ParsedError.CATEGORY_UNKNOWN,
        )
        if category_counter.get(category_key, 0)
    ]

    return {
        'parsed_errors': parsed_errors,
        'total_detected_errors': total_occurrences,
        'recurring_errors_count': len(recurring_errors),
        'most_common_error': parsed_errors[0] if parsed_errors else None,
        'grouped_results': grouped_results,
        'severity_rows': severity_rows,
        'category_rows': category_rows,
        'top_recurring_errors': top_recurring_errors,
        'line_span_count': len({(item.first_seen_line, item.last_seen_line) for item in parsed_errors}),
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
            last_seen_line=entry['last_seen_line'],
            category=entry['category'],
            severity=entry['severity'],
        )
        for entry in parsed_result['parsed_errors']
    ])

    uploaded_log.processed = True
    uploaded_log.save(update_fields=['processed'])
    return parsed_result
