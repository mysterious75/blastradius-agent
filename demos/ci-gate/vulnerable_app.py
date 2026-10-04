"""Intentionally vulnerable demo fixture for the CI gate (local only).

Introduces SQL injection by concatenating a request parameter into a query.
The deterministic analyzer must flag the ADDED lines; the policy engine
must FAIL the gate on this fixture.
"""

from flask import request


def search():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
