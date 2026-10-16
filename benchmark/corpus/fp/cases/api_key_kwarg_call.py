"""A boolean kwarg whose value is a call on a module, not an API key."""


def describe(config):
    return dict(
        name="provider",
        has_api_key=ai_provider_config_service.has_api_key(config),
    )
