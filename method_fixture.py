class Repo:
    def find(self, name):
        q = "SELECT * FROM users WHERE name = '" + name + "'"
        return q
