from datetime import time
import json

class User:
    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.username = kwargs.get('username')
        self.tacs = kwargs.get('tacs')
        
    def set_username(self, username):
        self.username = username
        
    def set_tacs(self, tacs):
        self.tacs = tacs
        
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'tacs': self.tacs,
        }
    
    @staticmethod
    def fromAttributes(user_attributes):
        
        attrs = {}
        
        for attr in user_attributes:
            name = attr.get("Name", "")
            if name.startswith("custom:"):
                name = name[len("custom:"):]
            attrs[name] = attr.get("Value")
                
        return User(
            id=attrs.get("sub"),
            username=attrs.get("email"),
            tacs=json.loads(attrs["tacs"]) if attrs.get("tacs") else None,
        )