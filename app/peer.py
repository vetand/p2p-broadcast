import hashlib
import json
import logging
from PIL import Image
from pyzbar.pyzbar import decode
import qrcode
import io

class Peer:
    def __init__(self, id, pubkey, transports):
        self.id = id
        self.pubkey = pubkey
        self.transports = transports

    def to_json(self):
        data = dict()
        data['id'] = self.id
        data['pubkey'] = str(self.pubkey)
        data['transports'] = self.transports
        return json.dumps(data)

    def make_qr_code(self, filename = "QR.png"):
        image = qrcode.make(self.to_json())
        image.save(filename)

    def __eq__(self, other):
        return self.id == other.id

    def __lt__(self, other):
        return self.id < other.id

    def __lq__(self, other):
        return self.id <= other.id

    def __hash__(self):
        return int(hashlib.md5(self.id.encode()).hexdigest(), 16)

def peer_from_json(json_string):
    logging.info("json string: {}".format(json_string))
    data = json.loads(json_string)
    logging.info("data id: {}".format(data['id']))
    return peer_from_dict(data)

def peer_from_dict(data):
    return Peer(data['id'], data['pubkey'], data['transports'])

def from_qr_code(bytes):
    data = decode(Image.open(io.BytesIO(bytes)))
    return peer_from_json(data[0].data.decode())
