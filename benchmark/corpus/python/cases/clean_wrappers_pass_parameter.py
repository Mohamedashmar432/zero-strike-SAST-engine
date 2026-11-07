# True negatives: wrappers that hand their own parameter straight to the sink
# build nothing here, so there is no injected string to report (their callers
# decide). The twin cases in vuln_execute_param_format.py build the string.
import xml.etree.ElementTree as ET


def run(sql):
    cursor.execute(sql)


def parse(document):
    return ET.fromstring(document)
