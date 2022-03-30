import logging
import time
import hashlib
import json
import uuid
from peer import Peer

class Message:
    def __init__(self, text, sender, msg_id=str(uuid.uuid4())):
        self.time_received = time.time()
        self.text = text
        self.id = sender
        self.sender = msg_id
        
    def to_json(self):
        data = dict()
        data['id'] = self.id
        data['text'] = self.text
        data['sender'] = self.sender
        return json.dumps(data)

    @staticmethod
    def from_dict(d):
        return Message(d['text'], d['sender'], d['id'])

    def __eq__(self, other):
        return self.id == other.id

    def __lt__(self, other):
        return self.id < other.id

    def __lq__(self, other):
        return self.id <= other.id

    def __hash__(self):
        return int(hashlib.md5(self.id.encode()).hexdigest(), 16)

def known_peers_message(known_peers):
    peer_list = []
    for peer in known_peers.keys():
        peer_list.append(known_peers[peer].get_peer().to_dict())

    return { 'known_peers': peer_list }

def message_from_json(json_string) -> (str, dict, str):
    signature = None
    d = json.loads(json_string)
    if 'signature' in d.keys():
        signature = d['signature']
    if 'message' in d.keys():
        data = json.loads(json_string)['message']
    else:
        data = json.loads(json_string)

    if 'text' in data.keys():
        return ('message', data, signature)

    if 'newcomer' in data.keys():
        return ('newcomer', data, signature)

    if 'known_peers' in data.keys():
        return ('known_peers', data, signature)
