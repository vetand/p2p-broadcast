import hashlib
import json
import logging
from PIL import Image
from pyzbar.pyzbar import decode
from Crypto.PublicKey import RSA
import qrcode
import io

class Peer:
    def __init__(self, id, pubkey: RSA.RsaKey, transports):
        self.id = id
        self.pubkey = pubkey
        self.transports = transports

    @staticmethod
    def from_json(s):
        return Peer.from_dict(json.loads(s))

    @staticmethod
    def from_dict(d):
        return Peer(d['id'], RSA.import_key(d['pubkey']), d['transports'])

    def to_json(self):
        data = dict()
        data['id'] = self.id
        data['pubkey'] = str(self.pubkey.export_key().decode())
        data['transports'] = self.transports
        return json.dumps(data)

    def to_dict(self):
        data = dict()
        data['id'] = self.id
        data['pubkey'] = str(self.pubkey.export_key().decode())
        data['transports'] = self.transports
        return data

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

def from_qr_code(bytes):
    data = decode(Image.open(io.BytesIO(bytes)))
    return Peer.from_json(data[0].data.decode())
