import hashlib
import json
import logging
from PIL import Image
from pyzbar.pyzbar import decode
import qrcode

class Peer:
    def __init__(self, peer_id):
        self.peer_id = peer_id

    def id(self):
        return self.peer_id

    def to_json(self):
        data = dict()
        data['id'] = self.peer_id
        return json.dumps(data)

    def make_qr_code(self, filename = "QR.png"):
        image = qrcode.make(self.to_json())
        image.save(filename)

    def __eq__(self, other):
        return self.peer_id == other.peer_id

    def __lt__(self, other):
        return self.peer_id < other.peer_id

    def __lq__(self, other):
        return self.peer_id <= other.peer_id

    def __hash__(self):
        return int(hashlib.md5(self.peer_id.encode()).hexdigest(), 16)

def peer_from_json(json_string):
    data = json.loads(json_string)
    return Peer(data['id'])

def from_qr_code(filename = "QR.png"):
    data = decode(Image.open(filename))
    return peer_from_json(data[0].data)
