import json
import logging
import re
import time
import warnings
from difflib import get_close_matches

from django.conf import settings

from .base import AIProviderError, AIProviderUnavailable, BaseAIProvider

try:
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', FutureWarning)
        import google.generativeai as genai
    from google.api_core import exceptions as google_exceptions
except ImportError:  # pragma: no cover - only hit when dependencies were not installed.
    genai = None
    google_exceptions = None


logger = logging.getLogger(__name__)

TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}
NON_RETRYABLE_STATUS_CODES = {400, 401, 403, 404}
MODEL_NAME_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')

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

    def __init__(self):
        self.api_key = self._normalize_text(getattr(settings, 'GEMINI_API_KEY', ''))
        self.model = self._normalize_text(getattr(settings, 'GEMINI_MODEL', ''), default='gemini-1.5-flash')
        self.timeout = max(int(getattr(settings, 'AI_REQUEST_TIMEOUT', 20) or 20), 1)
        self.max_tokens = max(int(getattr(settings, 'AI_MAX_TOKENS', 900) or 900), 100)
        retry_attempts = getattr(settings, 'AI_RETRY_ATTEMPTS', 2)
        retry_backoff_seconds = getattr(settings, 'AI_RETRY_BACKOFF_SECONDS', 0.5)
        self.retry_attempts = max(int(2 if retry_attempts in {'', None} else retry_attempts), 0)
        self.retry_backoff_seconds = max(float(0.5 if retry_backoff_seconds in {'', None} else retry_backoff_seconds), 0)
        self._client_model = None
        self._diagnostics = {}
        self._log_initialization()

    @property
    def configured(self):
        return bool(self.api_key and self.model)

    def get_startup_diagnostics(self):
        return {
            'provider': self.provider_name,
            'ai_features_enabled': bool(getattr(settings, 'AI_FEATURES_ENABLED', False)),
            'configured_provider': (getattr(settings, 'AI_PROVIDER', 'gemini') or 'gemini').strip().lower(),
            'configured_model': self.model,
            'resolved_model': self._safe_resolved_model_path(),
            'api_key_present': bool(self.api_key),
            'retry_attempts': self.retry_attempts,
            'timeout_seconds': self.timeout,
        }

    def get_last_diagnostics(self):
        return dict(self._diagnostics)

    def generate_json(self, *, instructions, input_text):
        if not self.configured:
            raise AIProviderUnavailable('Gemini is not configured.')

        response = self._generate_with_retries(instructions=instructions, input_text=input_text)
        output_text = self._extract_output_text(response)
        if not output_text:
            raise AIProviderError('Gemini response did not include output text.')

        return self._parse_json_output(output_text)

    def _normalized_model_name(self):
        model = self._normalize_text(self.model)
        if model.startswith('models/'):
            model = model.removeprefix('models/')
        if not model or not MODEL_NAME_PATTERN.fullmatch(model):
            raise AIProviderUnavailable('Gemini model configuration is invalid.')
        return model

    def _normalize_text(self, value, *, default=''):
        text = '' if value is None else str(value)
        text = text.strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
            text = text[1:-1].strip()
        return text or default

    def _resolved_model_path(self):
        return f'models/{self._normalized_model_name()}'

    def _safe_resolved_model_path(self):
        try:
            return self._resolved_model_path()
        except AIProviderError:
            return None

    def _get_client_model(self, instructions):
        if genai is None:
            raise AIProviderUnavailable('Gemini SDK is not installed.')
        if self._client_model is None:
            genai.configure(api_key=self.api_key)
            self._client_model = genai.GenerativeModel(
                self._resolved_model_path(),
                system_instruction=instructions,
            )
        return self._client_model

    def _generation_config(self):
        if genai is None:
            raise AIProviderUnavailable('Gemini SDK is not installed.')
        return genai.types.GenerationConfig(
            response_mime_type='application/json',
            max_output_tokens=self.max_tokens,
        )

    def _generate_with_retries(self, *, instructions, input_text):
        max_attempts = self.retry_attempts + 1
        last_error = None
        resolved_model = self._normalized_model_name()
        resolved_model_path = self._resolved_model_path()

        logger.debug(
            "Resolved Gemini AI SDK model.",
            extra={
                'provider': self.provider_name,
                'model': resolved_model_path,
            },
        )

        for attempt_number in range(1, max_attempts + 1):
            try:
                response = self._get_client_model(instructions).generate_content(
                    input_text,
                    generation_config=self._generation_config(),
                    request_options={'timeout': self.timeout},
                )
                if attempt_number > 1:
                    logger.info(
                        "Gemini AI request recovered after retry.",
                        extra={
                            'provider': self.provider_name,
                            'model': resolved_model_path,
                            'attempt': attempt_number,
                            'retry_attempts': attempt_number - 1,
                        },
                    )
                return response
            except self._retryable_timeout_exceptions() as exc:
                last_error = exc
                self._log_retryable_failure(
                    attempt_number=attempt_number,
                    max_attempts=max_attempts,
                    status_code=None,
                    cause='timeout',
                    error=exc,
                    resolved_model=resolved_model_path,
                )
            except Exception as exc:
                status_code = self._status_code_from_exception(exc)
                last_error = exc
                if self._is_non_retryable_provider_error(exc, status_code):
                    logger.warning(
                        "Gemini AI request failed with non-retryable status.",
                        extra={
                            'provider': self.provider_name,
                            'model': resolved_model_path,
                            'status_code': status_code,
                            'attempt': attempt_number,
                            'error': str(exc),
                        },
                    )
                    raise self._provider_error_for_exception(exc, status_code, resolved_model_path) from exc
                if self._is_retryable_provider_error(exc, status_code):
                    self._log_retryable_failure(
                        attempt_number=attempt_number,
                        max_attempts=max_attempts,
                        status_code=status_code,
                        cause='transient_provider_error',
                        error=exc,
                        resolved_model=resolved_model_path,
                    )
                else:
                    raise AIProviderError(str(exc)) from exc

            if attempt_number < max_attempts:
                time.sleep(self._backoff_delay(attempt_number))

        raise AIProviderError(self._format_retry_failure(last_error, max_attempts)) from last_error

    def _backoff_delay(self, attempt_number):
        return self.retry_backoff_seconds * (2 ** (attempt_number - 1))

    def _retryable_timeout_exceptions(self):
        exceptions = [TimeoutError]
        if google_exceptions is not None:
            exceptions.append(google_exceptions.DeadlineExceeded)
        return tuple(exceptions)

    def _status_code_from_exception(self, error):
        code = getattr(error, 'code', None)
        if code:
            return int(code)
        response = getattr(error, 'response', None)
        status_code = getattr(response, 'status_code', None) or getattr(response, 'status', None)
        return int(status_code) if status_code else None

    def _is_retryable_provider_error(self, error, status_code):
        if status_code in TRANSIENT_STATUS_CODES:
            return True
        if google_exceptions is None:
            return False
        return isinstance(error, self._google_exception_types(
            'ResourceExhausted',
            'InternalServerError',
            'BadGateway',
            'ServiceUnavailable',
            'GatewayTimeout',
        ))

    def _is_non_retryable_provider_error(self, error, status_code):
        if status_code in NON_RETRYABLE_STATUS_CODES:
            return True
        if google_exceptions is None:
            return False
        return isinstance(error, self._google_exception_types(
            'InvalidArgument',
            'Unauthenticated',
            'PermissionDenied',
            'NotFound',
        ))

    def _google_exception_types(self, *names):
        return tuple(
            exception_type
            for name in names
            for exception_type in [getattr(google_exceptions, name, None)]
            if exception_type is not None
        )

    def _provider_error_for_exception(self, error, status_code, resolved_model):
        if status_code in {401, 403}:
            return AIProviderUnavailable('Gemini authentication failed.')
        if status_code == 404:
            self._populate_unavailable_model_diagnostics(resolved_model)
            return AIProviderUnavailable(f'Gemini model {resolved_model} is unavailable.')
        if status_code == 429:
            return AIProviderError('Gemini quota was exceeded.')
        return AIProviderError(
            f'Gemini request failed with status {status_code or "unknown"} for model {resolved_model}.'
        )

    def list_compatible_models(self):
        if genai is None:
            raise AIProviderUnavailable('Gemini SDK is not installed.')
        genai.configure(api_key=self.api_key)

        compatible_models = []
        for model in genai.list_models():
            supported_methods = set(self._get_value(model, 'supported_generation_methods') or [])
            if 'generateContent' not in supported_methods:
                continue
            model_name = self._get_value(model, 'name')
            if not model_name:
                continue
            compatible_models.append(model_name)
        return sorted(set(compatible_models))

    def suggest_model(self, available_models=None):
        available_models = available_models or []
        target = self._safe_resolved_model_path() or self.model
        matches = get_close_matches(target, available_models, n=1, cutoff=0.5)
        return matches[0] if matches else None

    def _populate_unavailable_model_diagnostics(self, resolved_model):
        available_models = []
        suggested_model = None
        list_error = None
        try:
            available_models = self.list_compatible_models()
            suggested_model = self.suggest_model(available_models)
        except Exception as exc:  # pragma: no cover - defensive path for live diagnostics only.
            list_error = str(exc)

        self._diagnostics.update({
            'configured_model': self.model,
            'resolved_model': resolved_model,
            'available_models': available_models,
            'suggested_model': suggested_model,
            'list_models_error': list_error,
        })
        logger.warning(
            "Gemini configured model is unavailable.",
            extra={
                'provider': self.provider_name,
                'configured_model': self.model,
                'resolved_model': resolved_model,
                'available_models': available_models[:10],
                'suggested_model': suggested_model,
                'list_models_error': list_error,
            },
        )

    def _log_initialization(self):
        diagnostics = self.get_startup_diagnostics()
        logger.info(
            "AI provider initialized: provider=%s model=%s api_key_present=%s",
            diagnostics['provider'],
            diagnostics['resolved_model'] or diagnostics['configured_model'],
            diagnostics['api_key_present'],
            extra=diagnostics,
        )

    def _log_retryable_failure(self, *, attempt_number, max_attempts, status_code, cause, error, resolved_model):
        logger.warning(
            "Gemini AI request attempt failed.",
            extra={
                'provider': self.provider_name,
                'model': resolved_model,
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
        if isinstance(error, self._retryable_timeout_exceptions()):
            return f'Gemini request timed out after {max_attempts} attempt(s).'
        status_code = self._status_code_from_exception(error)
        if status_code == 429:
            return f'Gemini quota was exceeded after {max_attempts} attempt(s).'
        if status_code:
            return f'Gemini request failed with transient status {status_code} after {max_attempts} attempt(s).'
        return f'Gemini request failed after {max_attempts} attempt(s).'

    def _extract_output_text(self, response):
        text = getattr(response, 'text', None)
        if isinstance(text, str) and text.strip():
            return text.strip()

        chunks = []
        for candidate in getattr(response, 'candidates', []) or []:
            content = self._get_value(candidate, 'content') or {}
            for part in self._get_value(content, 'parts') or []:
                text = self._get_value(part, 'text')
                if text:
                    chunks.append(text)
        return ''.join(chunks).strip()

    def _get_value(self, data, key):
        if isinstance(data, dict):
            return data.get(key)
        return getattr(data, key, None)

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
