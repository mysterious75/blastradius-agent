"""Fake GraphQL endpoint for the live-graphql benchmark target.

Deliberately misconfigured in the three ways the live checker probes:

* introspection enabled        -> graphql-introspection
* field suggestions enabled    -> graphql-suggestions
* alias batching unthrottled   -> graphql-batching

Discovery works through the universal `{__typename}` probe. Everything else
returns a GraphQL-shaped errors array.
"""

import json
from http.server import BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path != "/graphql":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            query = json.loads(self.rfile.read(length) or b"{}").get("query", "")
        except ValueError:
            query = ""
        if "__schema" in query:
            body = {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                    }
                }
            }
        elif "blast_radius_nonexistent_field_xyz" in query:
            body = {
                "errors": [
                    {
                        "message": 'Cannot query field "blast_radius_nonexistent_field_xyz" '
                        'on type "Query". Did you mean "user"?'
                    }
                ]
            }
        elif "blast_alias_" in query:
            count = query.count("blast_alias_")
            body = {"data": {f"blast_alias_{i}": "Query" for i in range(count)}}
        elif "__typename" in query:
            body = {"data": {"__typename": "Query"}}
        else:
            body = {"errors": [{"message": "syntax error, unexpected IDENT"}]}
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
