"""BasePlugin — plugin interface (zero dependencies)."""


class BasePlugin:
    """Base class for BlastRadius plugins.

    Hooks (all optional):
        on_finding(finding)        — after a finding is produced
        on_patch(patch_result)     — after a patch is generated
        on_scan_complete(results)  — after a full pipeline run
        register_scanner() -> dict — extra vulnerability rules
        register_tool() -> func    — extra CAI-style tool
    """

    name: str = "base"
    version: str = "0.1.0"

    def on_finding(self, finding) -> None:
        pass

    def on_patch(self, patch) -> None:
        pass

    def on_scan_complete(self, results) -> None:
        pass

    def register_scanner(self) -> dict:
        return {}

    def register_tool(self):
        def _noop(*args, **kwargs):
            return None

        return _noop
