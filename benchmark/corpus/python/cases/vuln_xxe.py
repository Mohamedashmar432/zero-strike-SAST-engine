import xml.etree.ElementTree as ET
from flask import request

xml_data = request.form['xml']
ET.fromstring(xml_data)
