# Phase 7: a guarded sentinel, not a leaked credential.
#
# The literal exists so the start-up check below can recognise it and refuse
# to boot. Reporting it inverts the security posture: deleting the literal
# would delete the guard that makes the deployment safe.
INSECURE_JWT_SECRET = "insecure-development-only-do-not-deploy"
DEFAULT_ADMIN_PASSWORD = "changeme-before-first-boot"


class Settings:
    jwt_secret: str = ""


def production_secret_problem(settings: Settings):
    if settings.jwt_secret == INSECURE_JWT_SECRET:
        return "JWT_SECRET is still the development sentinel"
    if len(settings.jwt_secret) < 32:
        return "JWT_SECRET is too short"
    return None
