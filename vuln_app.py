import sqlite3


def search(name):
    q = "SELECT * FROM users WHERE name = '" + "".join(c for c in name if c.isalnum() or c in " _-") + "'"
    return q
