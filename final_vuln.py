import sqlite3


def search(name):
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    return q
