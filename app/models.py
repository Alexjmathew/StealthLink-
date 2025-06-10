from datetime import datetime

class User:
    def __init__(self, uid, email, public_key=None):
        self.uid = uid
        self.email = email
        self.public_key = public_key
        self.created_at = datetime.utcnow()
        self.last_seen = datetime.utcnow()

class Message:
    def __init__(self, sender_id, recipient_id, encrypted_content, timestamp, metadata=None):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.encrypted_content = encrypted_content
        self.timestamp = timestamp
        self.metadata = metadata or {}
        
    def to_dict(self):
        return {
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'content': self.encrypted_content,
            'timestamp': self.timestamp,
            'metadata': self.metadata
        }
        
    @classmethod
    def from_dict(cls, data):
        return cls(
            data.get('sender_id'),
            data.get('recipient_id'),
            data.get('content'),
            data.get('timestamp'),
            data.get('metadata', {})
        )
