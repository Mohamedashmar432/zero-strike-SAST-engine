"""Safe HTML marking. Nothing here should be reported.

markupsafe.Markup(base, encoding, errors) renders only ``base`` as unescaped
HTML; ``encoding`` and ``errors`` are ``bytes.decode`` knobs. A request-derived
charset changes how constant bytes are decoded, not what markup the template
emits, so it is not XSS. Before ZS-PY-054 was pinned to index 0 this was
reported as an XSS sink.
"""

from markupsafe import Markup, escape

BANNER = b"<b>Welcome back</b>"


def render_banner(request):
    charset = request.GET.get("charset", "utf-8")
    return Markup(BANNER, charset)


def render_comment(request):
    """The fix ZS-PY-054 recommends: escape, then let the template render it."""
    return escape(request.GET.get("comment"))
