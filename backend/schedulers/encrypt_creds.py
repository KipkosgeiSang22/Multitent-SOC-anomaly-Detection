import os, json
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Always resolve path relative to this file
env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(env_path)

fernet_key = os.getenv("FERNET_KEY")
if not fernet_key:
    raise ValueError("FERNET_KEY not found in .env")

f = Fernet(fernet_key.encode())
creds = {"username": "Report", "password": "MPdusTrPj1mEaTQEyaKpw9PP6GMrN4"}
encrypted = f.encrypt(json.dumps(creds).encode()).decode()
print(encrypted)
