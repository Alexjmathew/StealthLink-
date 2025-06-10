from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import HMAC, SHA256
import base64
import os

class StealthCipher:
    def __init__(self, key=None, hmac_key=None):
        if key is None:
            key = get_random_bytes(32)  # AES-256 key
        if hmac_key is None:
            hmac_key = get_random_bytes(32)  # HMAC key
            
        self.key = key
        self.hmac_key = hmac_key
    
    def encrypt(self, plaintext):
        # Generate random IV
        iv = get_random_bytes(AES.block_size)
        
        # Create cipher and encrypt
        cipher = AES.new(self.key, AES.MODE_GCM, iv, mac_len=16)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        
        # Create HMAC for additional integrity check
        hmac = HMAC.new(self.hmac_key, digestmod=SHA256)
        hmac.update(iv + ciphertext + tag)
        
        # Combine all components
        payload = iv + ciphertext + tag + hmac.digest()
        
        return base64.b64encode(payload).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        try:
            # Decode from base64
            decoded = base64.b64decode(encrypted_data)
            
            if len(decoded) < (AES.block_size + 16 + 32):  # IV + tag + HMAC
                raise ValueError("Invalid encrypted data length")
                
            # Split components
            iv = decoded[:AES.block_size]
            ciphertext = decoded[AES.block_size:-48]
            tag = decoded[-48:-32]
            received_hmac = decoded[-32:]
            
            # Verify HMAC
            hmac = HMAC.new(self.hmac_key, digestmod=SHA256)
            hmac.update(iv + ciphertext + tag)
            
            try:
                hmac.verify(received_hmac)
            except ValueError:
                raise ValueError("HMAC verification failed")
            
            # Decrypt
            cipher = AES.new(self.key, AES.MODE_GCM, iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def generate_keys_from_password(password, salt=None):
        if salt is None:
            salt = get_random_bytes(32)
            
        # Generate encryption key
        enc_key = scrypt(
            password.encode(),
            salt,
            key_len=32,
            N=2**20,
            r=8,
            p=1
        )
        
        # Generate HMAC key
        hmac_key = scrypt(
            password.encode(),
            salt + b'hmac',
            key_len=32,
            N=2**18,
            r=8,
            p=1
        )
        
        return enc_key, hmac_key, salt
