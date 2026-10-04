"""Fixed counterpart of vulnerable_app.py for the CI gate demo (local only).

The query is parameterized, so the deterministic analyzer must stay silent
and the gate must PASS on this fixture.
"""

from flask import request


def search():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = %s"
    return db.execute(query, (name,))
