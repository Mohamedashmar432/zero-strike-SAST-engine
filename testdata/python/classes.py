import os
import subprocess

class DatabaseManager:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def query(self, user_input):
        sql = "SELECT * FROM users WHERE name = '" + user_input + "'"
        return sql

    def execute_command(self, cmd):
        result = subprocess.run(cmd, shell=True)
        return result

class FileManager:
    def read_file(self, path):
        with open(path, 'r') as f:
            return f.read()

    def list_dir(self, directory):
        return os.listdir(directory)

db = DatabaseManager("localhost", 5432)
fm = FileManager()
