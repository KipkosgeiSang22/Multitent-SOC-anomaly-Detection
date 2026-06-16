from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path("C:/Users/ADMIN/Desktop/Model/soc_platform/backend/.env"))

f = Fernet(os.environ["FERNET_KEY"])
encrypted = b"gAAAAABqDDIQx8pDPSooCuTzapu-K-XgW0iRfhVLzRb5v5mXk83rtJxSiAiPGfpFXtXfwwEY2aKQRLNplBp9o5OCurqcJ2y5JQ=="
print(f.decrypt(encrypted))