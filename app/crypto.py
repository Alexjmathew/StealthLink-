from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from . import Config

def encrypt_message(message, key):
    # Ensure key is 32 bytes for AES-256
    key = key.encode('utf-8')[:32].ljust(32, b'\0')
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

def decrypt_message(encrypted_message, key):
    try:
        key = key.encode('utf-8')[:32].ljust(32, b'\0')
        data = base64.b64decode(encrypted_message)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except:
        return None
