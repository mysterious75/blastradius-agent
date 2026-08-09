"""Plugin CLI.

Usage:
    python -m blastradius.plugins list
    python -m blastradius.plugins install <path-to-plugin.py>
"""

import argparse
import shutil
from pathlib import Path

from blastradius.cli.display import RichDisplay
from blastradius.plugins.loader import PluginLoader, _user_plugin_dir


def cmd_list(_args) -> int:
    loader = PluginLoader()
    display = RichDisplay()
    rows = [[p.name, p.version] for p in loader.plugins]
    display.print_table(["Plugin", "Version"], rows, title="Installed Plugins")
    return 0


def cmd_install(args) -> int:
    src = Path(args.path)
    if not src.is_file():
        print(f"❌ no such file: {src}")
        return 1
    dest_dir = _user_plugin_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    shutil.copyfile(src, dest)
    print(f"[+] installed {src.name} → {dest}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius-plugins")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list installed plugins")
    install_p = sub.add_parser("install", help="copy a plugin into the plugins dir")
    install_p.add_argument("path", help="path to the plugin .py file")
    args = parser.parse_args(argv)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "install":
        return cmd_install(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
