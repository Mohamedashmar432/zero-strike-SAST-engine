import logging

logger = logging.getLogger(__name__)


def report(name, exc, config, token):
    logger.warning("missing secret", secret_name=name)
    logger.warning("unresolved reference %s", config.api_key_secret_name)
    logger.error("clone failed: %s", git_workspace.sanitize(str(exc), token))
