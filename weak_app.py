import sqlite3


def search(name):
    safe = name.replace("'", "''")
    q = "SELECT * FROM users WHERE name = '" + safe + "'"
    return q
