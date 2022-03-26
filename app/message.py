import time
import hashlib
import json
import uuid

class Message:
    def __init__(self, text = ""):
        self.time_received = time.time()
        self.text = ""
        self.id = str(uuid.uuid4())
        
    def to_json(self):
        data = dict()
        data['id'] = self.id
        data['text'] = self.text
        return json.dumps(data)

    def __eq__(self, other):
        return self.id == other.id

    def __lt__(self, other):
        return self.id < other.id

    def __lq__(self, other):
        return self.id <= other.id

    def __hash__(self):
        return int(hashlib.md5(self.id.encode()).hexdigest(), 16)

def message_from_json(json_string):
    data = json.loads(json_string)

    result = Message()
    result.id = data['id']
    result.text = data['text']
    return result
    