import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')
    FIREBASE_CONFIG = 'firebase_config.json'
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', '32-byte-key-for-aes-256-encryption!!')  # Must be 32 bytes for AES-256
