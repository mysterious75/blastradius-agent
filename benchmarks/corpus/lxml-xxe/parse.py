import lxml.etree


def parse_xml(data):
    return lxml.etree.fromstring(data)
