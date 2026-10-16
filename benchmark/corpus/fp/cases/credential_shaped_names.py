"""Names that look like credentials but hold scheme names, endpoints or
placeholders. Synthetic values only; nothing here is a secret."""

BEARER_SCHEME = "bearer"
token_scheme = "Bearer"
TOKEN_URL = "/api/v1/auth/token"
REFRESH_TOKEN_URL = "/api/v1/auth/refresh"
token_type = "bearer"
use_basic = False
repo_token_auth_scheme = "basic" if use_basic else "bearer"
LOCAL_MODEL_API_KEY = "not-needed"
_PLACEHOLDER_API_KEY = "synthetic-placeholder-value"
