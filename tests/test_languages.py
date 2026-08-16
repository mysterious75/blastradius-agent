"""Language-expansion tests (Task 4) — no network/Docker/CAI."""

import pytest

from blastradius.hunter.scanner import CVEHunter


@pytest.fixture
def hunter():
    return CVEHunter()


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _xss(hunter, tmp_path):
    return [f for f in hunter.scan_repo(str(tmp_path)) if f.vuln_type == "xss"]


# --- Ruby --------------------------------------------------------------------


def test_ruby_render_inline_params_is_xss(tmp_path, hunter):
    _write(
        tmp_path,
        "views/user.rb",
        "def show\n  render inline: params[:name]\nend\n",
    )
    assert any("user.rb" in f.file for f in _xss(hunter, tmp_path))


def test_ruby_html_safe_with_user_data_is_xss(tmp_path, hunter):
    _write(
        tmp_path,
        "views/post.rb",
        "def show\n  @content = params[:body]\n  @content.html_safe\nend\n",
    )
    # .html_safe line carries no params keyword; the params line is the source —
    # the html_safe call is what should be flagged via file-level has_source
    assert _xss(hunter, tmp_path)  # at least one xss finding


def test_ruby_escaped_output_not_flagged(tmp_path, hunter):
    _write(
        tmp_path,
        "views/safe.rb",
        "def show\n  render inline: escape_html(params[:name])\nend\n",
    )
    assert not any("safe.rb" in f.file for f in _xss(hunter, tmp_path))


# --- Java --------------------------------------------------------------------


def test_java_getparameter_to_write_is_xss(tmp_path, hunter):
    _write(
        tmp_path,
        "HelloServlet.java",
        "public class HelloServlet extends HttpServlet {\n"
        "  protected void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
        "    PrintWriter out = response.getWriter();\n"
        '    out.write(request.getParameter("name"));\n'
        "  }\n"
        "}\n",
    )
    assert any("HelloServlet.java" in f.file for f in _xss(hunter, tmp_path))


def test_java_encoded_output_not_flagged(tmp_path, hunter):
    _write(
        tmp_path,
        "SafeServlet.java",
        "public class SafeServlet extends HttpServlet {\n"
        "  protected void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
        "    PrintWriter out = response.getWriter();\n"
        '    out.write(escapeHtml(request.getParameter("name")));\n'
        "  }\n"
        "}\n",
    )
    assert not any("SafeServlet.java" in f.file for f in _xss(hunter, tmp_path))


# --- Go ----------------------------------------------------------------------


def test_go_formvalue_into_fprintf_is_xss(tmp_path, hunter):
    _write(
        tmp_path,
        "main.go",
        "package main\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        '    fmt.Fprintf(w, "<b>%s</b>", r.FormValue("name"))\n'
        "}\n",
    )
    assert any("main.go" in f.file for f in _xss(hunter, tmp_path))


def test_go_escaped_output_not_flagged(tmp_path, hunter):
    _write(
        tmp_path,
        "main.go",
        "package main\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        '    fmt.Fprintf(w, "<b>%s</b>", template.HTMLEscapeString(r.FormValue("name")))\n'
        "}\n",
    )
    assert not _xss(hunter, tmp_path)


# --- Rust --------------------------------------------------------------------


def test_rust_format_with_query_is_xss(tmp_path, hunter):
    _write(
        tmp_path,
        "src/main.rs",
        "fn handler(request: &Request) {\n"
        '    let html = format!("<div>{}</div>", query);\n'
        "    respond(html)\n"
        "}\n",
    )
    assert any("main.rs" in f.file for f in _xss(hunter, tmp_path))


# --- ERB ---------------------------------------------------------------------


def test_erb_params_interpolation_is_xss(tmp_path, hunter):
    _write(
        tmp_path,
        "app/views/show.html.erb",
        "<div><%= params[:name] %></div>\n",
    )
    assert any("show.html.erb" in f.file for f in _xss(hunter, tmp_path))


# --- extension coverage ------------------------------------------------------


def test_new_extensions_are_scanned(tmp_path, hunter):
    _write(
        tmp_path,
        "app.jsx",
        "export function App() {\n"
        "  return <div dangerouslySetInnerHTML={{ __html: props.userInput }} />;\n"
        "}\n",
    )
    _write(
        tmp_path,
        "app.rb",
        "def show\n  render inline: params[:name]\nend\n",
    )
    findings = hunter.scan_repo(str(tmp_path))
    assert {Path(f.file).suffix for f in findings} == {".jsx", ".rb"}


from pathlib import Path  # noqa: E402
