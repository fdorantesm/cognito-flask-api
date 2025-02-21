import json

HIDDEN_ATTRIBUTES = ["email", "email_verified", "phone_verified"]
JSON_FIELDS = ["tacs"]

def get_attributes(user_attributes):
    attributes = {}
    user_attributes = user_attributes or []
        
    for attr in user_attributes:
        name = attr.get("Name", "")
        if name.startswith("custom:"):
            name = name[len("custom:"):]
        attributes[name] = attr.get("Value")
    return attributes

def get_custom_attribute(user_attributes, attribute_name):
    for attr in user_attributes.get("UserAttributes", []):
        name = attr.get("Name", "")
        if name.startswith("custom:"):
            name = name[len("custom:"):]
        if name == attribute_name:
            value = attr.get("Value")
            try:
                return json.loads(value)
            except (TypeError, ValueError):
                return value
    return None

def get_public_attributes(user_attributes):
    public_attrs = {}
    for key, value in user_attributes.items():
        if key not in HIDDEN_ATTRIBUTES:
            if key in JSON_FIELDS:
                try:
                    public_attrs[key] = json.loads(value)
                except (TypeError, ValueError):
                    public_attrs[key] = value
            else:
                public_attrs[key] = value
    return public_attrs