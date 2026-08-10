"""Shared tool-registration helper.

The built-in agent loop (blastradius.agent) generates tool schemas from plain
functions via inspect — CAI's ``FunctionTool`` wrapper would break direct
callability of the tools, so tools are always kept as plain callables
regardless of whether cai-framework happens to be installed.
"""


def cai_tool(fn):
    """Keep ``fn`` a plain callable (no CAI wrapping)."""
    return fn
