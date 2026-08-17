"""Minimal intraprocedural taint tracing (semgrep OSS model). Pure stdlib.

For a matched sink line, walk the containing function's earlier lines to find
the variable's origin — an assignment from a user-input source (request.,
req., input, params, getParameter, FormValue, ...) or a chain of plain
variable propagations (up to 3 hops) — and record the taint path.

Trace format (a list of step dicts, origin -> sink):

    [
      {"line": 2, "kind": "source",     "var": "x", "expr": "request.args.get(\"q\")"},
      {"line": 3, "kind": "propagator", "var": "y", "expr": "x"},
      {"line": 5, "kind": "sink",       "var": "y", "expr": "os.system(y)", "sanitized": False},
    ]

``sink_line_idx`` is the 0-based index of the sink line inside ``lines``;
``line`` values in the trace are 1-based human line numbers. When no origin
is found (constant sink, unassigned variable, no enclosing function) [] is
returned. The sink step carries ``sanitized: True`` when a sanitizer
(html.escape/escape reassignment, ``var.replace(``, a ``parameterized`` query,
or an ``execute(..., (var,))`` tuple) is present in the function.
"""

import re

# Real user-input APIs (assignment RHS matching means the value originates from
# user input). Taint is assignment-chain based, not name based: a bare
# identifier name (req, data, url, ...) is NOT a source — the RHS must call a
# genuine input accessor. The `request.` / `req.` patterns require an input
# accessor so module paths like ``urllib.request.Request(`` or a bare
# ``self.request`` never match; `(?<![.\w])` guards keep `params[`/`ctx.query`/
# `context.request` from substring-matching inside other identifiers.
_SOURCE_RE = re.compile(
    r"request\.(?:args|form|values|get_json|query_params|cookies|headers|json|body)\b"
    r"|req\.(?:query|body|params|headers)\b"
    r"|\$_GET|\$_POST|\$_REQUEST"
    r"|getParameter\s*\("
    r"|r\.FormValue\s*\("
    r"|\binput\s*\("
    r"|(?<![.\w])params\["
    r"|searchParams\.get\s*\("
    r"|(?<![.\w])ctx\.query\b"
    r"|(?<![.\w])context\.(?:request|args)\b"
    r"|window\.location",
    re.I,
)

# A language-agnostic function-start superset (def / function / func /
# Java-ish methods / arrow functions / async def).
_FUNC_START_RE = re.compile(
    r"^\s*(?:"
    r"def\s+\w+\s*\(|"
    r"function\s*\w*\s*\(|"
    r"func\s+\w+\s*\(|"
    r"(?:public|private|protected|static|final|async)\b.*\([^)]*\)\s*\{?|"
    r"(?:\([^)]*\)\s*=>|[\w$.]+\s*\([^)]*\)\s*=>)"
    r")"
)

# Language keywords / pseudo-values that are never tainted variables.
_KEYWORDS = frozenset(
    {
        "and",
        "as",
        "assert",
        "async",
        "await",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "try",
        "while",
        "with",
        "yield",
        "True",
        "False",
        "None",
        "true",
        "false",
        "null",
        "undefined",
        "var",
        "let",
        "const",
        "this",
        "self",
        "new",
        "extends",
        "super",
        "typeof",
        "instanceof",
        "void",
        "delete",
        "switch",
        "case",
        "default",
        "do",
        "of",
        "public",
        "private",
        "protected",
        "static",
        "final",
        "int",
        "long",
        "short",
        "byte",
        "char",
        "float",
        "double",
        "boolean",
        "string",
        "object",
        "export",
        "package",
        "interface",
        "implements",
        "enum",
        "struct",
        "select",
        "defer",
        "go",
        "func",
        "range",
        "map",
        "chan",
    }
)

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")

_ASSIGN_RE_CACHE: dict = {}


def _assign_re(var: str) -> re.Pattern:
    """Assignment regex for ``var = <expr>`` (excludes ==, >=, <=, !=, +=, ...)."""
    rx = _ASSIGN_RE_CACHE.get(var)
    if rx is None:
        rx = re.compile(
            rf"(?<![\w$]){re.escape(var)}(?![\w$])\s*(?<![+\-*/%&|^<>=!:])=(?!=)\s*(?P<expr>.+)"
        )
        _ASSIGN_RE_CACHE[var] = rx
    return rx


def sink_arg_var(line: str) -> str:
    """First data identifier inside the sink's first paren group.

    String literals are stripped and call-names (identifiers immediately
    followed by ``(``) are skipped, so ``pickle.loads(bytes.fromhex(data))``
    resolves to ``data``, not ``bytes``.
    """
    start = line.find("(")
    if start == -1:
        return ""
    depth = 0
    end = -1
    for i in range(start, len(line)):
        ch = line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end == -1:
        return ""
    arg_text = line[start + 1 : end]
    stripped = re.sub(r"(['\"])(?:\\.|(?!\1)[^\\])*?\1", " ", arg_text)
    for m in _IDENT_RE.finditer(stripped):
        ident = m.group(0)
        if ident in _KEYWORDS:
            continue
        if stripped[m.end() : m.end() + 1] == "(":  # call name, not a variable
            continue
        return ident
    return ""


def _find_func_start(lines: list, sink_line_idx: int):
    """Nearest function-start line index above the sink (or None)."""
    for i in range(sink_line_idx - 1, -1, -1):
        if _FUNC_START_RE.search(lines[i]):
            return i
    return None


def _find_assignment(lines: list, var: str, start_idx: int, end_idx: int):
    """Nearest ``var = <expr>`` line scanning upward in lines[end_idx:start_idx+1].

    Returns (line_idx, expr) or (None, None).
    """
    rx = _assign_re(var)
    for i in range(end_idx, start_idx - 1, -1):
        m = rx.search(lines[i])
        if m:
            return i, m.group("expr")
    return None, None


def _chain_var(expr: str, seen: set) -> str:
    """First identifier in an RHS that can be followed as a tainted variable.

    String literals are stripped first so words inside them (``'ping -c 1 '``)
    are never treated as chain variables — only real identifiers survive.
    """
    stripped = re.sub(r"(['\"])(?:\\.|(?!\1)[^\\])*?\1", " ", expr)
    for m in _IDENT_RE.finditer(stripped):
        ident = m.group(0)
        if ident in _KEYWORDS or _SOURCE_RE.match(ident) or ident in seen:
            continue
        if stripped[m.end() : m.end() + 1] == "(":  # a call, not a variable
            continue
        return ident
    return None


def _is_sanitized(var: str, lines: list, func_start: int, sink_line_idx: int) -> bool:
    """Whether ``var`` is escaped/replaced/parameterized somewhere in the function."""
    block = lines[func_start : sink_line_idx + 1]
    for line in block:
        if re.search(rf"\b{re.escape(var)}\s*=\s*(?:\w+\.)*escape\s*\(", line):
            return True
        if re.search(rf"\b{re.escape(var)}\s*\.\s*replace\s*\(", line):
            return True
        if re.search(rf"\b{re.escape(var)}\s*=\s*(?:\w+\.)*sanitize\w*\s*\(", line):
            return True
        if re.search(r"\bparameterized\b", line, re.I):
            return True
        if re.search(rf"\bexecute\s*\([^)]*\(\s*{re.escape(var)}\s*[,)]", line):
            return True
    return False


def trace_sink(lines: list, sink_line_idx: int, sink_var: str = "") -> list:
    """Trace a sink's argument back to a user-input origin inside its function.

    Returns a list of step dicts (origin -> sink); [] when no origin is found.
    """
    if not lines or not (0 <= sink_line_idx < len(lines)):
        return []
    if not sink_var:
        sink_var = sink_arg_var(lines[sink_line_idx])
    if not sink_var:
        return []

    func_start = _find_func_start(lines, sink_line_idx)
    if func_start is None:
        return []

    steps = []  # discovered source/propagator steps (reverse discovery order)
    var = sink_var
    scan_from = sink_line_idx - 1
    seen = {sink_var}
    for _hop in range(4):  # source + up to 3 propagator hops
        match_line, expr = _find_assignment(lines, var, func_start, scan_from)
        if match_line is None:
            return []  # no assignment of this var in the function
        if _SOURCE_RE.search(expr):
            steps.append(
                {"line": match_line + 1, "kind": "source", "var": var, "expr": expr.strip()}
            )
            break
        chain_var = _chain_var(expr, seen)
        if chain_var is None:
            if re.search(rf"\b{re.escape(var)}\b", expr):
                # self-reassignment (x = x.replace(...) / x = x.strip()):
                # a mutation/sanitization of the same variable — keep looking
                # further up for the true origin
                scan_from = match_line - 1
                continue
            return []  # RHS references neither a source nor a followable variable
        steps.append(
            {"line": match_line + 1, "kind": "propagator", "var": var, "expr": expr.strip()}
        )
        var = chain_var
        seen.add(var)
        scan_from = match_line - 1
    else:
        return []  # more than 3 propagation hops

    steps.reverse()
    steps.append(
        {
            "line": sink_line_idx + 1,
            "kind": "sink",
            "var": sink_var,
            "expr": lines[sink_line_idx].strip(),
            "sanitized": _is_sanitized(sink_var, lines, func_start, sink_line_idx),
        }
    )
    return steps


def is_var_tainted(lines: list, sink_line_idx: int, sink_var: str = "") -> bool:
    """Whether ``sink_var`` on the 0-based ``sink_line_idx`` is user-controlled.

    True iff ``trace_sink`` returns a non-empty trace whose FIRST step has
    ``kind == 'source'`` — i.e. the variable's origin was found at a real
    user-input API. Constants, config values, attribute access (``self.``),
    constructor/module origins and unassigned variables are not tainted.
    """
    trace = trace_sink(lines, sink_line_idx, sink_var)
    return bool(trace and trace[0].get("kind") == "source")


def has_enclosing_function(lines: list, sink_line_idx: int) -> bool:
    """Whether any enclosing function scope exists above ``sink_line_idx``.

    Intraprocedural taint tracing is scoped to the containing function; when
    no function encloses the line (top-level script code) callers should fall
    back to a coarser heuristic.
    """
    return _find_func_start(lines, sink_line_idx) is not None


def is_function_parameter(lines: list, sink_line_idx: int, var: str) -> bool:
    """Whether ``var`` is a parameter of the function enclosing ``sink_line_idx``.

    Cross-function taint cannot be resolved intra-procedurally — a parameter's
    origin lives in the caller. Callers should treat a parameter argument as
    potentially tainted when the FILE contains user-input sources elsewhere
    (the parameter may receive request data from a call site).
    """
    func_start = _find_func_start(lines, sink_line_idx)
    if func_start is None or not var:
        return False
    m = re.search(r"\(([^)]*)\)", lines[func_start])
    if not m:
        return False
    return re.search(rf"(?<![\w$]){re.escape(var)}(?![\w$])", m.group(1)) is not None
