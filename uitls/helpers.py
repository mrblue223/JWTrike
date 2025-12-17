# utils/helpers.py
import json
import base64

def is_valid_json(string):
    try:
        json.loads(string)
        return True
    except:
        return False

def base64_url_decode(input_str):
    padding = 4 - (len(input_str) % 4)
    input_str += '=' * padding
    return base64.urlsafe_b64decode(input_str)

def format_jwt_output(header, payload, signature=None):
    output = {
        "header": header,
        "payload": payload
    }
    if signature:
        output["signature"] = signature
    return json.dumps(output, indent=2)