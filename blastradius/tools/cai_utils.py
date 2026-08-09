"""Shared CAI registration helper.

Registers a function as a CAI ``function_tool`` (``cai.sdk.agents``) when
cai-framework is installed; otherwise leaves it a plain callable so tool
wiring stays testable without CAI.
"""


def cai_tool(fn):
    """Register ``fn`` as a CAI function_tool; keep it plain when CAI is absent."""
    try:
        from cai.sdk.agents import function_tool

        return function_tool(fn)
    except ImportError:
        return fn
