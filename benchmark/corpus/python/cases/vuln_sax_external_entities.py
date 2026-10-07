# ZS-PY-092: a SAX parser told to resolve external general entities (XXE).
from xml.dom.pulldom import parseString
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges


def parse(body):
    parser = make_parser()
    parser.setFeature(feature_external_ges, True)
    return parseString(body, parser=parser)
