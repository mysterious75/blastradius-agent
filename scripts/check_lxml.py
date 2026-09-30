"""Check lxml default entity behavior."""
import os
import tempfile

from lxml import etree

sent = os.path.join(tempfile.gettempdir(), "xxe_test.txt")
open(sent, "w").write("SECRET123")
uri = "file:///" + sent.replace("\\", "/").replace(":", "|", 1) if False else None
# proper file URI on windows: file:///C:/...
uri = "file:///" + sent.replace("\\", "/")
xml = ('<?xml version="1.0"?>'
       '<!DOCTYPE r [<!ENTITY xxe SYSTEM "' + uri + '">]>'
       '<r>&xxe;</r>')
print("uri:", uri)
for name, p in [("default", etree.XMLParser()),
                ("resolve", etree.XMLParser(resolve_entities=True, no_network=False))]:
    try:
        out = etree.fromstring(xml.encode(), parser=p)
        print(name, "->", repr(out.text))
    except Exception as e:
        print(name, "ERR", str(e)[:100])
