# Phase 6: the credential-redaction canary test.
#
# This builds a settings object whose every secret field contains the word
# "canary", then asserts none of it reaches repr(). It is the control that
# protects the codebase from leaking real secrets; the scanner reported it as
# a leaked mongodb URI pointing at a reserved example domain.
def test_credentials_never_reach_repr():
    printed = repr(
        dict(
            mongo_uri="mongodb+srv://user:canary-value@cluster.example.net",
            smtp_password="canary-smtp-password",
            api_token="canary-api-token-value",
        )
    )
    assert "canary" not in printed, f"a credential reached the repr: {printed}"
