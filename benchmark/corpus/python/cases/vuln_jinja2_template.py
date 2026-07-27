# ZS-PY-077: Jinja2 Template compiled from a tainted string (SSTI)
from jinja2 import Template
tpl = request.args.get('tpl')
Template(tpl).render()
