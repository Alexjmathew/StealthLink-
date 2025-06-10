from . import db
from .crypto import encrypt_message, decrypt_message
from datetime import datetime, timedelta
from . import Config

def save_message(sender_id, receiver_id, message, ttl_seconds=None):
    encrypted_message = encrypt_message(message, Config.ENCRYPTION_KEY)
    timestamp = datetime.utcnow().isoformat()
    message_data = {
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'message': encrypted_message,
        'timestamp': timestamp,
        'ttl': ttl_seconds
    }
    db.child('messages').push(message_data)

def get_messages(user_id):
    messages = db.child('messages').get().val()
    result = []
    if messages:
        for msg_id, msg in messages.items():
            if msg['receiver_id'] == user_id or msg['sender_id'] == user_id:
                decrypted = decrypt_message(msg['message'], Config.ENCRYPTION_KEY)
                if decrypted:
                    result.append({
                        'id': msg_id,
                        'sender_id': msg['sender_id'],
                        'receiver_id': msg['receiver_id'],
                        'message': decrypted,
                        'timestamp': msg['timestamp'],
                        'ttl': msg.get('ttl')
                    })
                    # Delete message if TTL has expired or after reading
                    if msg.get('ttl'):
                        ttl_time = datetime.fromisoformat(msg['timestamp']) + timedelta(seconds=int(msg['ttl']))
                        if datetime.utcnow() > ttl_time:
                            db.child('messages').child(msg_id).remove()
                    else:
                        db.child('messages').child(msg_id).remove()  # Vanish after reading
    return result
