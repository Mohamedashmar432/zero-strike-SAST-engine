# ZS-PY-053: lxml etree.fromstring on request-supplied XML (XXE)
from lxml import etree
from flask import request

xml_data = request.form['xml']
etree.fromstring(xml_data)
