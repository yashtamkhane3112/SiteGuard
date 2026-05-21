from django.conf import settings

from .gemini_provider import GeminiProvider
from .openai_provider import OpenAIResponsesProvider


def get_default_provider():
    provider_name = (getattr(settings, 'AI_PROVIDER', 'gemini') or 'gemini').strip().lower()
    if provider_name == 'openai':
        return OpenAIResponsesProvider()
    return GeminiProvider()
