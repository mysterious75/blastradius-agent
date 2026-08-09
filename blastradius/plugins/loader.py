"""PluginLoader — discovers and loads plugins (zero dependencies).

Loads plugin modules from:
  - blastradius/plugins/builtin/   (bundled plugins)
  - ~/.blastradius/plugins/*.py    (user plugins)
"""

import importlib.util
import inspect
import sys
from pathlib import Path
from typing import List, Optional

from blastradius.plugins.base import BasePlugin


def _user_plugin_dir() -> Path:
    return Path.home() / ".blastradius" / "plugins"


def _load_module(path: Path):
    name = f"blastradius_plugin_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        return None
    return module


def _plugin_classes(module):
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if obj is BasePlugin or not issubclass(obj, BasePlugin):
            continue
        if getattr(obj, "__module__", "") == module.__name__:
            yield obj


class PluginLoader:
    """Discover and instantiate all plugins."""

    def __init__(self, extra_dirs: Optional[List[Path]] = None):
        self.plugins: List[BasePlugin] = []
        dirs = [Path(__file__).resolve().parent / "builtin", _user_plugin_dir()]
        dirs += list(extra_dirs or [])
        for directory in dirs:
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.py")):
                if path.name == "__init__.py":
                    continue
                module = _load_module(path)
                if module is None:
                    continue
                for cls in _plugin_classes(module):
                    try:
                        self.plugins.append(cls())
                    except Exception:
                        continue

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def fire(self, event: str, *args) -> None:
        for plugin in self.plugins:
            try:
                getattr(plugin, event)(*args)
            except Exception:
                continue

    def on_finding(self, finding) -> None:
        self.fire("on_finding", finding)

    def on_patch(self, patch) -> None:
        self.fire("on_patch", patch)

    def on_scan_complete(self, results) -> None:
        self.fire("on_scan_complete", results)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def registered_scanners(self) -> dict:
        merged = {}
        for plugin in self.plugins:
            try:
                merged.update(plugin.register_scanner() or {})
            except Exception:
                continue
        return merged

    def registered_tools(self) -> list:
        tools = []
        for plugin in self.plugins:
            try:
                tools.append(plugin.register_tool())
            except Exception:
                continue
        return tools
