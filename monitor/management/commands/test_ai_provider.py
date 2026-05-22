from django.conf import settings
from django.core.management.base import BaseCommand

from monitor.ai.providers.base import AIProviderError, AIProviderUnavailable
from monitor.ai.providers.gemini_provider import GeminiProvider
from monitor.ai.providers.registry import get_default_provider


class Command(BaseCommand):
    help = 'Validate SiteGuard AI provider configuration and run a minimal self-test.'

    def handle(self, *args, **options):
        provider = get_default_provider()

        self.stdout.write('Testing AI provider configuration...')
        self.stdout.write(f'AI features enabled: {bool(getattr(settings, "AI_FEATURES_ENABLED", False))}')
        self.stdout.write(f'Configured provider: {getattr(settings, "AI_PROVIDER", "gemini")}')

        if isinstance(provider, GeminiProvider):
            diagnostics = provider.get_startup_diagnostics()
            self.stdout.write(f'Resolved Gemini model: {diagnostics["resolved_model"] or "(invalid)"}')
            self.stdout.write(f'Configured Gemini model: {diagnostics["configured_model"] or "(not set)"}')
            self.stdout.write(f'Gemini API key configured: {diagnostics["api_key_present"]}')
        else:
            self.stdout.write(f'Resolved provider: {provider.provider_name}')

        if not provider.configured:
            self.stdout.write(self.style.ERROR('AI provider is not configured.'))
            return

        try:
            result = provider.generate_json(
                instructions=(
                    'Return ONLY raw JSON with the keys '
                    'summary, likely_root_cause, impact, recommendations, confidence. '
                    'No markdown. No code fences. No commentary. Use short strings, confidence low/medium/high, and empty lists where appropriate.'
                ),
                input_text='Self-test request. Confirm the provider is reachable.',
            )
        except AIProviderUnavailable as exc:
            self.stdout.write(self.style.ERROR(f'Provider unavailable: {exc}'))
            self._print_gemini_model_diagnostics(provider)
            return
        except AIProviderError as exc:
            self.stdout.write(self.style.ERROR(f'Provider request failed: {exc}'))
            self._print_gemini_model_diagnostics(provider)
            return

        self.stdout.write(self.style.SUCCESS('AI provider self-test passed.'))
        self.stdout.write(f'Summary: {result.get("summary", "")}')

    def _print_gemini_model_diagnostics(self, provider):
        if not isinstance(provider, GeminiProvider):
            return

        diagnostics = provider.get_last_diagnostics()
        available_models = diagnostics.get('available_models') or []
        suggested_model = diagnostics.get('suggested_model')
        list_models_error = diagnostics.get('list_models_error')

        self.stdout.write(
            f'Configured model: {diagnostics.get("configured_model") or provider.model or "(not set)"}'
        )
        self.stdout.write(
            f'Resolved model: {diagnostics.get("resolved_model") or provider._safe_resolved_model_path() or "(invalid)"}'
        )
        if suggested_model:
            self.stdout.write(f'Suggested model: {suggested_model}')
        if available_models:
            self.stdout.write('Available Gemini models:')
            for model_name in available_models[:20]:
                self.stdout.write(f' - {model_name}')
        if list_models_error:
            self.stdout.write(f'Unable to list Gemini models: {list_models_error}')
