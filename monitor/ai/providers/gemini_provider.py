import json
import logging
import time

import requests
from django.conf import settings

from .base import AIProviderError, AIProviderUnavailable, BaseAIProvider


logger = logging.getLogger(__name__)

TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}

REQUIRED_AI_KEYS = {
    'summary',
    'outage_narrative',
    'availability_interpretation',
    'latency_interpretation',
    'suggested_fixes',
    'trends',
    'recurring_patterns',
    'risk_indicators',
    'root_cause_hints',
}

LIST_AI_KEYS = {
    'suggested_fixes',
    'trends',
    'recurring_patterns',
    'risk_indicators',
    'root_cause_hints',
}


class GeminiProvider(BaseAIProvider):
    provider_name = 'gemini'
    api_base_url = 'https://generativelanguage.googleapis.com/v1beta'

    def __init__(self):
        self.api_key = (getattr(settings, 'GEMINI_API_KEY', '') or '').strip()
        self.model = (getattr(settings, 'GEMINI_MODEL', '') or 'gemini-1.5-flash').strip()
        self.timeout = max(int(getattr(settings, 'AI_REQUEST_TIMEOUT', 20) or 20), 1)
        self.max_tokens = max(int(getattr(settings, 'AI_MAX_TOKENS', 900) or 900), 100)
        self.retry_attempts = max(int(getattr(settings, 'AI_RETRY_ATTEMPTS', 2) or 2), 0)
        self.retry_backoff_seconds = max(float(getattr(settings, 'AI_RETRY_BACKOFF_SECONDS', 0.5) or 0.5), 0)

    @property
    def configured(self):
        return bool(self.api_key and self.model)

    def generate_json(self, *, instructions, input_text):
        if not self.configured:
            raise AIProviderUnavailable('Gemini is not configured.')

        payload = {
            'systemInstruction': {
                'parts': [{'text': instructions}],
            },
            'contents': [
                {
                    'role': 'user',
                    'parts': [{'text': input_text}],
                },
            ],
            'generationConfig': {
                'responseMimeType': 'application/json',
                'maxOutputTokens': self.max_tokens,
            },
        }
        response = self._post_with_retries(payload)

        output_text = self._extract_output_text(response.json())
        if not output_text:
            raise AIProviderError('Gemini response did not include output text.')

        return self._parse_json_output(output_text)

    def _generate_content_url(self):
        model_path = self.model if self.model.startswith('models/') else f'models/{self.model}'
        return f'{self.api_base_url}/{model_path}:generateContent'

    def _post_with_retries(self, payload):
        max_attempts = self.retry_attempts + 1
        last_error = None

        for attempt_number in range(1, max_attempts + 1):
            try:
                response = requests.post(
                    self._generate_content_url(),
                    headers={
                        'Content-Type': 'application/json',
                        'x-goog-api-key': self.api_key,
                    },
                    json=payload,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                if attempt_number > 1:
                    logger.info(
                        "Gemini AI request recovered after retry.",
                        extra={
                            'provider': self.provider_name,
                            'model': self.model,
                            'attempt': attempt_number,
                            'retry_attempts': attempt_number - 1,
                            'status_code': getattr(response, 'status_code', None),
                        },
                    )
                return response
            except requests.Timeout as exc:
                last_error = exc
                self._log_retryable_failure(
                    attempt_number=attempt_number,
                    max_attempts=max_attempts,
                    status_code=None,
                    cause='timeout',
                    error=exc,
                )
            except requests.HTTPError as exc:
                status_code = getattr(getattr(exc, 'response', None), 'status_code', None)
                last_error = exc
                if status_code not in TRANSIENT_STATUS_CODES:
                    raise AIProviderError(
                        f'Gemini request failed with status {status_code or "unknown"}.'
                    ) from exc
                self._log_retryable_failure(
                    attempt_number=attempt_number,
                    max_attempts=max_attempts,
                    status_code=status_code,
                    cause='transient_http',
                    error=exc,
                )
            except requests.RequestException as exc:
                raise AIProviderError(str(exc)) from exc

            if attempt_number < max_attempts:
                time.sleep(self._backoff_delay(attempt_number))

        raise AIProviderError(self._format_retry_failure(last_error, max_attempts)) from last_error

    def _backoff_delay(self, attempt_number):
        return self.retry_backoff_seconds * (2 ** (attempt_number - 1))

    def _log_retryable_failure(self, *, attempt_number, max_attempts, status_code, cause, error):
        logger.warning(
            "Gemini AI request attempt failed.",
            extra={
                'provider': self.provider_name,
                'model': self.model,
                'attempt': attempt_number,
                'max_attempts': max_attempts,
                'status_code': status_code,
                'retry_attempts_remaining': max_attempts - attempt_number,
                'timeout_seconds': self.timeout,
                'cause': cause,
                'error': str(error),
            },
        )

    def _format_retry_failure(self, error, max_attempts):
        if isinstance(error, requests.Timeout):
            return f'Gemini request timed out after {max_attempts} attempt(s).'
        status_code = getattr(getattr(error, 'response', None), 'status_code', None)
        if status_code:
            return f'Gemini request failed with transient status {status_code} after {max_attempts} attempt(s).'
        return f'Gemini request failed after {max_attempts} attempt(s).'

    def _extract_output_text(self, data):
        chunks = []
        for candidate in data.get('candidates', []) or []:
            content = candidate.get('content') or {}
            for part in content.get('parts', []) or []:
                text = part.get('text')
                if text:
                    chunks.append(text)
        return ''.join(chunks).strip()

    def _parse_json_output(self, output_text):
        cleaned_text = self._strip_markdown_fence(output_text)
        parsed = self._decode_first_json_object(cleaned_text)
        if not isinstance(parsed, dict):
            raise AIProviderError('Gemini response did not contain a JSON object.')
        return self._validate_json_object(parsed)

    def _strip_markdown_fence(self, output_text):
        text = (output_text or '').strip()
        if not text.startswith('```'):
            return text

        lines = text.splitlines()
        if not lines:
            return text
        opening = lines[0].strip().lower()
        if opening not in {'```', '```json'}:
            return text
        if len(lines) > 1 and lines[-1].strip() == '```':
            return '\n'.join(lines[1:-1]).strip()
        return '\n'.join(lines[1:]).strip()

    def _decode_first_json_object(self, output_text):
        decoder = json.JSONDecoder()
        text = (output_text or '').strip()
        for index, character in enumerate(text):
            if character != '{':
                continue
            try:
                parsed, _end_index = decoder.raw_decode(text[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
        raise AIProviderError('Gemini response was not valid JSON.')

    def _validate_json_object(self, parsed):
        validated = {}
        for key in REQUIRED_AI_KEYS:
            value = parsed.get(key)
            if key in LIST_AI_KEYS:
                if isinstance(value, list):
                    validated[key] = value
                elif value:
                    validated[key] = [value]
                else:
                    validated[key] = []
            else:
                validated[key] = value if isinstance(value, str) else ''
        return validated
