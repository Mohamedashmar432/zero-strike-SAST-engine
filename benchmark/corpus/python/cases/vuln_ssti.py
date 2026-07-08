# ZS-PY-027: SSTI — the template itself (not just a render variable) is tainted
template = request.args.get('template')
render_template_string(template)
