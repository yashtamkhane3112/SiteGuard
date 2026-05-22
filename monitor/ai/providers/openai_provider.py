import json

import requests
from django.conf import settings

from .base import AIProviderError, AIProviderUnavailable, BaseAIProvider


class OpenAIResponsesProvider(BaseAIProvider):
    provider_name = 'openai'
    api_url = 'https://api.openai.com/v1/responses'

    def __init__(self):
        self.api_key = (getattr(settings, 'OPENAI_API_KEY', '') or '').strip()
        self.model = (getattr(settings, 'OPENAI_MODEL', '') or 'gpt-5-mini').strip()
        self.timeout = max(int(getattr(settings, 'AI_REQUEST_TIMEOUT', 20) or 20), 1)
        self.max_tokens = max(int(getattr(settings, 'AI_MAX_TOKENS', 900) or 900), 100)

    @property
    def configured(self):
        return bool(self.api_key and self.model)

    def generate_json(self, *, instructions, input_text):
        if not self.configured:
            raise AIProviderUnavailable('OpenAI is not configured.')

        payload = {
            'model': self.model,
            'instructions': instructions,
            'input': input_text,
            'max_output_tokens': self.max_tokens,
            'store': False,
            'text': {
                'format': {
                    'type': 'json_object',
                },
            },
        }
        try:
            response = requests.post(
                self.api_url,
                headers={
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json',
                },
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise AIProviderError(str(exc)) from exc

        data = response.json()
        output_text = data.get('output_text', '')
        if not output_text:
            output_text = self._extract_output_text(data)
        if not output_text:
            raise AIProviderError('OpenAI response did not include output text.')

        try:
            return json.loads(output_text)
        except json.JSONDecodeError as exc:
            raise AIProviderError('OpenAI response was not valid JSON.') from exc

    def _extract_output_text(self, data):
        chunks = []
        for item in data.get('output', []) or []:
            if item.get('type') != 'message':
                continue
            for content in item.get('content', []) or []:
                if content.get('type') in {'output_text', 'text'}:
                    chunks.append(content.get('text', ''))
        return ''.join(chunks).strip()
