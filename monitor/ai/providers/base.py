class AIProviderError(Exception):
    pass


class AIProviderUnavailable(AIProviderError):
    pass


class BaseAIProvider:
    provider_name = 'base'

    def generate_json(self, *, instructions, input_text):
        raise NotImplementedError
