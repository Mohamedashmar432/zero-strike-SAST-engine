# ZS-PY-072: Django mark_safe() on a tainted value (XSS)
from django.utils.safestring import mark_safe
comment = request.GET.get('comment')
mark_safe(comment)
