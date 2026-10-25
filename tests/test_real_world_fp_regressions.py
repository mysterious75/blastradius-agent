"""Regression cases from the 20-repository real-world precision study.

Each pattern below produced a HIGH/CRITICAL candidate on a mature OSS repo
while being a framework definition, a literal DOM write, a defense, or a
config-driven value. These tests pin the tightened scoring so the noise does
not return.
"""

import pytest

from blastradius.hunter.scanner import CVEHunter

pytestmark = [pytest.mark.unit, pytest.mark.integration]


def _types(tmp_path, files):
    for name, code in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
    return {f.vuln_type for f in CVEHunter().scan_repo(str(tmp_path))}


def test_header_assignment_with_config_value_is_not_crlf(tmp_path):
    types = _types(
        tmp_path,
        {
            "client.py": (
                "def build(request):\n"
                "    request.headers['Authorization'] = self._build_auth_header()\n"
                "    return request.args.get('next')\n"
            )
        },
    )
    assert "crlf" not in types


def test_header_assignment_from_request_arg_is_crlf(tmp_path):
    types = _types(
        tmp_path,
        {
            "redirect.py": (
                "def go(request):\n"
                "    response = make_response()\n"
                "    response.headers['Location'] = request.args['next']\n"
                "    return response\n"
            )
        },
    )
    assert "crlf" in types


def test_literal_and_readonly_dom_writes_are_not_xss(tmp_path):
    types = _types(
        tmp_path,
        {
            "ui.ts": (
                "element.innerHTML = '&#8210;';\n"
                "element.innerHTML = '';\n"
                "const html = element.innerHTML;\n"
                "if (element.innerHTML !== '') {}\n"
            )
        },
    )
    assert "xss" not in types


def test_data_bearing_dom_write_is_still_xss(tmp_path):
    types = _types(tmp_path, {"ui.ts": "target.innerHTML = results;\n"})
    assert "xss" in types


def test_python_eval_is_not_xss(tmp_path):
    types = _types(tmp_path, {"a.py": "return eval('%s.%s' % (module, target))\n"})
    assert "xss" not in types


def test_string_template_substitution_is_not_ssti(tmp_path):
    types = _types(
        tmp_path,
        {
            "routes.py": (
                "from string import Template\n"
                "def f(value, ctx):\n"
                "    out = Template(value).substitute(ctx)\n"
                "    return out\n"
            )
        },
    )
    assert "ssti" not in types


def test_literal_template_is_not_ssti(tmp_path):
    types = _types(
        tmp_path,
        {"a.py": "def f(ctx):\n    ctx.template = Template('')\n    return ctx\n"},
    )
    assert "ssti" not in types


def test_render_template_string_with_data_is_ssti(tmp_path):
    types = _types(
        tmp_path,
        {"a.py": "def f(source):\n    return render_template_string(source)\n"},
    )
    assert "ssti" in types


def test_hasownproperty_guard_is_not_proto_pollution(tmp_path):
    types = _types(
        tmp_path,
        {
            "a.ts": (
                "if (Object.prototype.hasOwnProperty.call(obj, key)) {}\n"
                "const proto = Object.prototype;\n"
            )
        },
    )
    assert "proto_pollution" not in types


def test_proto_assignment_is_proto_pollution(tmp_path):
    types = _types(tmp_path, {"a.ts": "obj['__proto__'] = payload;\n"})
    assert "proto_pollution" in types


def test_window_open_and_config_path_are_not_traversal(tmp_path):
    types = _types(
        tmp_path,
        {
            "ui.ts": "window.open(url);\n",
            "setup.py": (
                "for path in (MEDIA_ROOT, REPORTS_ROOT):\n"
                "    Path(path).mkdir(parents=True, exist_ok=True)\n"
            ),
        },
    )
    assert "traversal" not in types


def test_debugger_eval_method_is_not_cmd_injection(tmp_path):
    types = _types(
        tmp_path,
        {
            "debug.py": (
                "class Console:\n"
                "    def eval(self, code):\n"
                "        return self.console.eval(code)\n"
            )
        },
    )
    assert "cmd_injection" not in types


def test_os_system_with_user_parameter_is_cmd_injection(tmp_path):
    types = _types(tmp_path, {"run.py": "def run(user_input):\n    os.system(user_input)\n"})
    assert "cmd_injection" in types


def test_view_args_without_object_access_is_not_idor(tmp_path):
    types = _types(
        tmp_path,
        {
            "ctx.py": (
                "def match_request(request):\n"
                "    return request.url_rule.endpoint, request.view_args\n"
            )
        },
    )
    assert "idor" not in types


def test_id_parameter_with_object_access_is_idor(tmp_path):
    types = _types(
        tmp_path,
        {
            "views.py": (
                "def get_user(request):\n"
                "    user_id = request.args['user_id']\n"
                "    return User.objects.get(id=user_id)\n"
            )
        },
    )
    assert "idor" in types


def test_browser_same_origin_fetch_is_not_ssrf(tmp_path):
    types = _types(
        tmp_path,
        {"util.ts": "const res = await fetch(url, {credentials: 'same-origin'});\n"},
    )
    assert "ssrf" not in types


def test_server_side_proxy_fetch_is_still_ssrf(tmp_path):
    types = _types(
        tmp_path,
        {"proxy.ts": "const url = req.query.url;\nreturn fetch(url);\n"},
    )
    assert "ssrf" in types
