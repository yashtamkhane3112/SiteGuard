import json
import re


MAX_FIELD_LENGTH = 420
MAX_INPUT_LENGTH = 9000


AI_JSON_SCHEMA_DESCRIPTION = {
    'summary': 'Concise operational summary.',
    'suggested_fixes': ['Recommendation strings.'],
    'trends': ['Operational trend strings.'],
    'frequent_issues': ['Frequent issue or recurring pattern strings.'],
    'likely_causes': ['Cautious likely/probable/suspected cause strings.'],
}


def sanitize_text(value, limit=MAX_FIELD_LENGTH):
    text = str(value or '')
    text = re.sub(r'[\w.+-]+@[\w-]+\.[\w.-]+', '[email]', text)
    text = re.sub(r'(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*\S+', r'\1=[redacted]', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) > limit:
        return f'{text[:limit].rstrip()}...'
    return text


def bounded_json(data):
    payload = json.dumps(data, sort_keys=True, default=str)
    if len(payload) > MAX_INPUT_LENGTH:
        payload = payload[:MAX_INPUT_LENGTH] + '...'
    return payload


def build_ai_instructions():
    return (
        'You are SiteGuard operational intelligence. Analyze only the provided structured monitoring, '
        'incident, alert, report, and parsed-error data. You are read-only. Do not instruct the system '
        'to trigger alerts, create incidents, delete data, decide uptime, or mutate monitoring state. '
        'Give cautious operational guidance. Label suggestions as recommendations or possible fixes. '
        'Label root-cause content as suspected, probable, or likely. Do not present speculation as certainty. '
        'Return STRICT RAW JSON ONLY. No markdown. No code fences. No explanations. No commentary. No prose before or after the JSON. '
        'Do not wrap the JSON in backticks, headings, labels, or any surrounding text. '
        'Return exactly one compact JSON object with these keys and no additional top-level keys: '
        f'{json.dumps(AI_JSON_SCHEMA_DESCRIPTION)}'
    )


def build_report_prompt(report_payload):
    return 'Analyze this SiteGuard report payload:\n' + bounded_json(report_payload)


def build_error_upload_prompt(error_payload):
    return 'Explain this SiteGuard parsed error upload payload:\n' + bounded_json(error_payload)


def build_incident_prompt(incident_payload):
    return 'Analyze this SiteGuard incident payload:\n' + bounded_json(incident_payload)
