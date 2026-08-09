"""Self-contained scanners tests — no prometheus, no network."""

from blastradius.scanners import get_scanner, get_scanners, scan_file


def test_registry_discovers_all_scanners():
    scanners = get_scanners()
    assert set(scanners) == {"sqli", "xss", "ssrf", "ssti", "xxe"}


def test_sqli_detects_concat_and_ignores_parameterized():
    scanner = get_scanner("sqli")
    vuln = (
        "name = request.args.get('name')\n"
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
    )
    safe = "cur.execute('SELECT * FROM users WHERE name = %s', (name,))"
    assert len(scanner.detect(vuln)) == 1
    assert scanner.detect(safe) == []


def test_sqli_confidence():
    scanner = get_scanner("sqli")
    findings = scanner.detect(
        "name = request.args.get('name')\n"
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
    )
    assert findings[0].confidence >= 0.9


def test_xss_detects_sinks():
    scanner = get_scanner("xss")
    assert scanner.detect("document.getElementById('x').innerHTML = data;")
    assert scanner.detect("el.innerHTML = userInput;")
    assert scanner.detect("document.write(name);")
    # literal is not flagged
    assert scanner.detect("document.write('static');") == []


def test_xss_escape_not_flagged():
    scanner = get_scanner("xss")
    assert scanner.detect("el.innerHTML = html.escape(userInput);") == []


def test_ssrf_detects_fetches():
    scanner = get_scanner("ssrf")
    assert scanner.detect("return requests.get(url).text")
    assert scanner.detect("await fetch(userInput);")
    assert scanner.detect("axios.get(targetUrl);")
    assert scanner.detect("requests.get('https://static.example.com/x')") == []


def test_ssti_detects_render_template_string():
    scanner = get_scanner("ssti")
    assert scanner.detect("return render_template_string(tmpl)")
    assert scanner.detect("return render_template_string('static')") == []


def test_xxe_detects_unsafe_parse():
    scanner = get_scanner("xxe")
    code = "import xml.etree.ElementTree as ET\nreturn ET.parse(xml_data)\n"
    assert scanner.detect(code)
    safe = "from defusedxml import ElementTree as ET\nreturn ET.parse(xml_data)\n"
    assert scanner.detect(safe) == []


def test_scan_file_runs_all_scanners(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "name = request.args.get('name')\n"
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n",
        encoding="utf-8",
    )
    findings = scan_file(str(path))
    types = {f.vuln_type for f in findings}
    assert "sqli" in types
    assert all(f.line > 0 for f in findings)
