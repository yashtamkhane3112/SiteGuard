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
RAW_OUTPUT_PREVIEW_LIMIT = 320
RAW_DEBUG_PREVIEW_LIMIT = 1000

# TODO: Migrate this provider to google.genai once the runtime contract is stable in production.

REQUIRED_AI_KEYS = {
    'summary',
    'likely_root_cause',
    'impact',
    'recommendations',
    'confidence',
}

LIST_AI_KEYS = {
    'recommendations',
    'trends',
    'frequent_issues',
    'likely_causes',
}

CONFIDENCE_LEVELS = {'low', 'medium', 'high'}


class GeminiProvider(BaseAIProvider):
    provider_name = 'gemini'

    def __init__(self):
        self.api_key = self._normalize_text(getattr(settings, 'GEMINI_API_KEY', ''))
        self.model = self._normalize_text(getattr(settings, 'GEMINI_MODEL', ''), default='gemini-1.5-flash')
        self.timeout = max(int(getattr(settings, 'AI_REQUEST_TIMEOUT', 20) or 20), 1)
        self.max_tokens = max(int(getattr(settings, 'AI_MAX_TOKENS', 900) or 900), 100)
        self.debug_raw_output = bool(getattr(settings, 'AI_DEBUG_RAW_OUTPUT', False))
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
            self._log_fallback_activation('', reason='empty_output_text')
            return self._fallback_payload(reason='empty_output_text')
        self._log_output_diagnostics(response, output_text)

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
            candidate_count=1,
            temperature=0,
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
        response_type = type(response).__name__
        text = getattr(response, 'text', None)
        if isinstance(text, str) and text.strip():
            logger.debug(
                "Gemini text extraction succeeded.",
                extra={
                    'provider': self.provider_name,
                    'response_type': response_type,
                    'candidate_count': self._safe_candidate_count(response),
                    'text_extraction_path': 'response.text',
                },
            )
            return text.strip()

        candidate_count = self._safe_candidate_count(response)
        chunks = []
        for candidate in getattr(response, 'candidates', []) or []:
            content = self._get_value(candidate, 'content') or {}
            for part in self._get_value(content, 'parts') or []:
                text = self._get_value(part, 'text')
                if text:
                    chunks.append(text)
        extracted = ''.join(chunks).strip()
        logger.debug(
            "Gemini text extraction completed.",
            extra={
                'provider': self.provider_name,
                'response_type': response_type,
                'candidate_count': candidate_count,
                'text_extraction_path': 'candidates.parts' if extracted else 'none',
            },
        )
        return extracted

    def _log_output_diagnostics(self, response, output_text):
        logger.debug(
            "Gemini raw response diagnostics.",
            extra={
                'provider': self.provider_name,
                'response_type': type(response).__name__,
                'candidate_count': self._safe_candidate_count(response),
                'raw_response_length': len(output_text or ''),
                'extracted_text_length': len(output_text or ''),
                'raw_output_preview': self._debug_preview(output_text) if self.debug_raw_output else '',
                'raw_output_debug_enabled': self.debug_raw_output,
            },
        )

    def _get_value(self, data, key):
        if isinstance(data, dict):
            return data.get(key)
        return getattr(data, key, None)

    def _safe_candidate_count(self, response):
        candidates = getattr(response, 'candidates', None)
        if isinstance(candidates, (list, tuple)):
            return len(candidates)
        return 0

    def _parse_json_output(self, output_text):
        parsed, strategy, fallback_activated = self._decode_json_object(output_text)
        if not isinstance(parsed, dict):
            self._log_fallback_activation(output_text, reason='non_object_json')
            return self._fallback_payload(reason='non_object_json')
        return self._validate_json_object(parsed, strategy=strategy, fallback_activated=fallback_activated)

    def _sanitize_output_text(self, output_text):
        text = self._normalize_text(output_text)
        text = text.lstrip('\ufeff')
        text = text.replace('\r\n', '\n').replace('\r', '\n')
        return text.strip()

    def _decode_json_object(self, output_text):
        text = self._sanitize_output_text(output_text)
        direct_parse = self._load_json_object(text, source='direct_raw')
        if direct_parse is not None:
            return direct_parse, 'direct_raw', False

        candidate_specs = self._candidate_json_blocks(text)
        parse_errors = []
        for source, candidate in candidate_specs:
            cleaned_candidate = self._cleanup_json_candidate(candidate)
            if not cleaned_candidate:
                parse_errors.append(f'{source}:empty_candidate')
                continue
            parsed = self._try_parse_candidate(cleaned_candidate, source=source, parse_errors=parse_errors)
            if isinstance(parsed, dict):
                return parsed, source, True
        self._log_parse_failure(
            output_text,
            reason=', '.join(parse_errors) if parse_errors else 'no_json_object_found',
        )
        self._log_fallback_activation(output_text, reason='invalid_json')
        return self._fallback_payload(reason='invalid_json'), 'fallback_payload', True

    def _candidate_json_blocks(self, output_text):
        text = self._sanitize_output_text(output_text)
        stripped_fences = self._strip_markdown_fences(text)
        candidates = []
        if stripped_fences and stripped_fences != text:
            candidates.append(('stripped_fences', stripped_fences))
        candidates.append(('cleaned_raw', text))

        fenced_blocks = self._extract_fenced_blocks(text)
        candidates.extend(('fenced', block) for block in fenced_blocks)

        regex_candidate = self._extract_first_json_by_regex(text)
        if regex_candidate:
            candidates.append(('regex_first_object', regex_candidate))

        balanced_candidate = self._extract_largest_balanced_json_block(text)
        if balanced_candidate:
            candidates.append(('largest_balanced_block', balanced_candidate))

        repaired_candidate = self._extract_repaired_partial_json_block(text)
        if repaired_candidate:
            candidates.append(('repaired_partial_block', repaired_candidate))

        unique_candidates = []
        seen = set()
        for source, candidate in candidates:
            normalized = candidate.strip()
            key = normalized
            if not normalized or key in seen:
                continue
            seen.add(key)
            unique_candidates.append((source, normalized))
        return unique_candidates

    def _strip_markdown_fences(self, text):
        stripped = re.sub(r'^\s*```json\s*', '', text, flags=re.IGNORECASE)
        stripped = re.sub(r'^\s*```\s*', '', stripped)
        stripped = re.sub(r'\s*```\s*$', '', stripped)
        return stripped.strip()

    def _extract_fenced_blocks(self, text):
        return [
            match.group(1).strip()
            for match in re.finditer(r'```(?:json)?\s*([\s\S]*?)```', text, flags=re.IGNORECASE)
            if match.group(1).strip()
        ]

    def _extract_first_json_by_regex(self, text):
        match = re.search(r'\{[\s\S]*?\}', text or '')
        return match.group(0).strip() if match else ''

    def _extract_largest_balanced_json_block(self, text):
        largest_block = ''
        start_index = None
        depth = 0
        in_string = False
        escaped = False

        for index, character in enumerate(text or ''):
            if escaped:
                escaped = False
                continue
            if character == '\\' and in_string:
                escaped = True
                continue
            if character == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if character == '{':
                if depth == 0:
                    start_index = index
                depth += 1
            elif character == '}' and depth > 0:
                depth -= 1
                if depth == 0 and start_index is not None:
                    block = text[start_index:index + 1].strip()
                    if len(block) > len(largest_block):
                        largest_block = block
                    start_index = None
        return largest_block

    def _extract_repaired_partial_json_block(self, text):
        block, missing_closers = self._scan_partial_json_block(text)
        if not block:
            return ''
        if missing_closers > 0:
            block = f'{block}{"}" * missing_closers}'
        return block

    def _scan_partial_json_block(self, text):
        start_index = None
        depth = 0
        in_string = False
        escaped = False

        for index, character in enumerate(text or ''):
            if escaped:
                escaped = False
                continue
            if character == '\\' and in_string:
                escaped = True
                continue
            if character == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if character == '{':
                if depth == 0:
                    start_index = index
                depth += 1
            elif character == '}' and depth > 0:
                depth -= 1

        if start_index is None:
            return '', 0
        return text[start_index:].strip(), depth

    def _cleanup_json_candidate(self, candidate):
        text = self._sanitize_output_text(candidate)
        text = re.sub(r'^\s*```(?:json)?\s*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\s*```$', '', text)
        text = re.sub(r'^\s*json\s*[:\-]?\s*', '', text, flags=re.IGNORECASE)
        text = text.replace('\u201c', '"').replace('\u201d', '"').replace('\u2019', "'").replace('\u2018', "'")
        start_index = text.find('{')
        end_index = text.rfind('}')
        if start_index != -1 and end_index != -1 and end_index >= start_index:
            text = text[start_index:end_index + 1]
        return text.strip()

    def _try_parse_candidate(self, candidate, *, source, parse_errors):
        normalized_candidates = [candidate]

        trailing_comma_cleaned = re.sub(r',\s*([}\]])', r'\1', candidate)
        if trailing_comma_cleaned != candidate:
            normalized_candidates.append(trailing_comma_cleaned)

        repaired_unbalanced = self._close_unbalanced_braces(candidate)
        if repaired_unbalanced and repaired_unbalanced not in normalized_candidates:
            normalized_candidates.append(repaired_unbalanced)

        for attempt_number, item in enumerate(normalized_candidates, start=1):
            parsed = self._load_json_object(item, source=f'{source}:{attempt_number}', parse_errors=parse_errors)
            if isinstance(parsed, dict):
                return parsed
        return None

    def _load_json_object(self, candidate, *, source, parse_errors=None):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            if parse_errors is not None:
                parse_errors.append(f'{source}:json_decode_error@{exc.pos}')
            return None
        if isinstance(parsed, dict):
            return parsed
        if parse_errors is not None:
            parse_errors.append(f'{source}:non_object_json')
        return None

    def _close_unbalanced_braces(self, candidate):
        text = candidate.strip()
        if not text.startswith('{'):
            return ''
        depth = 0
        in_string = False
        escaped = False
        for character in text:
            if escaped:
                escaped = False
                continue
            if character == '\\' and in_string:
                escaped = True
                continue
            if character == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if character == '{':
                depth += 1
            elif character == '}':
                depth -= 1
        if depth > 0:
            return f'{text}{"}" * depth}'
        return text

    def _validate_json_object(self, parsed, *, strategy, fallback_activated):
        missing_keys = [key for key in REQUIRED_AI_KEYS if key not in parsed]
        if missing_keys:
            logger.warning(
                "Gemini JSON validation populated missing schema keys.",
                extra={
                    'provider': self.provider_name,
                    'missing_schema_keys': missing_keys,
                    'parse_strategy': strategy,
                    'fallback_activated': fallback_activated,
                },
            )
        validated = self._normalize_schema(parsed)
        self._log_parse_success(
            strategy=strategy,
            fallback_activated=fallback_activated,
            validation_failures=missing_keys,
            parsed=validated,
        )
        return validated

    def _normalize_schema(self, parsed):
        summary = self._coerce_string(parsed.get('summary'))
        likely_root_cause = self._coerce_string(
            parsed.get('likely_root_cause')
            or parsed.get('likely_root_causes')
            or parsed.get('likely_causes')
        )
        impact = self._coerce_string(
            parsed.get('impact')
            or parsed.get('outage_narrative')
            or parsed.get('availability_interpretation')
            or parsed.get('latency_interpretation')
        )
        recommendations = self._coerce_string_list(
            parsed.get('recommendations')
            or parsed.get('suggested_fixes')
        )
        confidence = self._normalize_confidence(parsed.get('confidence'))
        trends = self._coerce_string_list(parsed.get('trends'))
        frequent_issues = self._coerce_string_list(parsed.get('frequent_issues'))
        likely_causes = self._coerce_string_list(parsed.get('likely_causes'))
        if not likely_causes and likely_root_cause:
            likely_causes = [likely_root_cause]
        root_cause_hints = list(likely_causes)

        return {
            'summary': summary,
            'likely_root_cause': likely_root_cause,
            'impact': impact,
            'recommendations': recommendations,
            'confidence': confidence,
            'suggested_fixes': list(recommendations),
            'trends': trends,
            'frequent_issues': frequent_issues,
            'likely_causes': likely_causes,
            'recurring_patterns': list(frequent_issues),
            'root_cause_hints': root_cause_hints,
            'risk_indicators': list(likely_causes),
            'outage_narrative': impact,
            'availability_interpretation': self._coerce_string(parsed.get('availability_interpretation') or impact),
            'latency_interpretation': self._coerce_string(parsed.get('latency_interpretation')),
        }

    def _coerce_string(self, value):
        if isinstance(value, str):
            return self._normalize_text(value)
        if value is None or value == '' or value == [] or value == {}:
            return ''
        if isinstance(value, (list, tuple)):
            flattened = [self._normalize_text(item) for item in value if self._normalize_text(item)]
            return ' '.join(flattened).strip()
        return self._normalize_text(value)

    def _coerce_string_list(self, value):
        if value is None or value == '' or value == [] or value == {}:
            return []
        items = value if isinstance(value, (list, tuple)) else [value]
        normalized_items = []
        for item in items:
            if isinstance(item, dict):
                item = json.dumps(item, sort_keys=True, default=str)
            normalized = self._normalize_text(item)
            if normalized:
                normalized_items.append(normalized)
        return normalized_items

    def _normalize_confidence(self, value):
        normalized = self._normalize_text(value, default='low').lower()
        if normalized in CONFIDENCE_LEVELS:
            return normalized
        return 'low'

    def _fallback_payload(self, *, reason):
        return self._normalize_schema({
            'summary': 'AI analysis could not be structured reliably. Core SiteGuard data remains available.',
            'likely_root_cause': '',
            'impact': 'No structured AI impact summary was generated from the provider response.',
            'recommendations': [],
            'confidence': 'low',
            'frequent_issues': [reason] if reason else [],
        })

    def _log_parse_failure(self, output_text, *, reason):
        logger.warning(
            "Gemini JSON parse failed.",
            extra={
                'provider': self.provider_name,
                'raw_response_length': len(output_text or ''),
                'parse_failure_reason': reason,
                'raw_output_preview': self._safe_preview(output_text),
            },
        )

    def _log_parse_success(self, *, strategy, fallback_activated, validation_failures, parsed):
        logger.info(
            "Gemini JSON parse succeeded.",
            extra={
                'provider': self.provider_name,
                'parse_strategy': strategy,
                'fallback_activated': fallback_activated,
                'validation_failures': list(validation_failures or []),
                'summary_present': bool(parsed.get('summary')),
                'recommendation_count': len(parsed.get('recommendations') or []),
                'confidence': parsed.get('confidence', 'low'),
            },
        )

    def _log_fallback_activation(self, output_text, *, reason):
        logger.warning(
            "Gemini JSON fallback activated.",
            extra={
                'provider': self.provider_name,
                'fallback_reason': reason,
                'raw_response_length': len(output_text or ''),
                'raw_output_preview': self._safe_preview(output_text),
            },
        )

    def _safe_preview(self, output_text):
        text = self._normalize_text(output_text)
        text = re.sub(r'\s+', ' ', text).strip()
        if len(text) > RAW_OUTPUT_PREVIEW_LIMIT:
            return f'{text[:RAW_OUTPUT_PREVIEW_LIMIT].rstrip()}...'
        return text

    def _debug_preview(self, output_text):
        text = self._normalize_text(output_text)
        text = re.sub(r'\s+', ' ', text).strip()
        if len(text) > RAW_DEBUG_PREVIEW_LIMIT:
            return f'{text[:RAW_DEBUG_PREVIEW_LIMIT].rstrip()}...'
        return text
