# ZS-PY-061: XPath injection — expression compiled from tainted input
from lxml import etree
name = request.args.get('name')
expr = "//user[name/text()='" + name + "']"
xpath = etree.XPath(expr)
