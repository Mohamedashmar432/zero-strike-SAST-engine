from hashlib import md5, sha1
import pickle
import yaml
import base64

def hash_password(password):
    return md5(password.encode()).hexdigest()

def load_data(data_bytes):
    return pickle.loads(data_bytes)

def parse_config(config_str):
    return yaml.load(config_str)

SECRET_KEY = "hardcoded_secret_12345"
API_TOKEN = "Bearer eyJhbGciOiJIUzI1NiJ9.example"
