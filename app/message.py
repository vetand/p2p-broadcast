import time
import hashlib
import json
import uuid
from peer import Peer, peer_from_json, peer_from_dict

class Message:
    def __init__(self, node_id = "", text = ""):
        self.time_received = time.time()
        self.text = ""
        self.id = str(uuid.uuid4())
        self.sender = node_id
        
    def to_json(self):
        data = dict()
        data['id'] = self.id
        data['text'] = self.text
        data['sender'] = self.sender
        return json.dumps(data)

    def __eq__(self, other):
        return self.id == other.id

    def __lt__(self, other):
        return self.id < other.id

    def __lq__(self, other):
        return self.id <= other.id

    def __hash__(self):
        return int(hashlib.md5(self.id.encode()).hexdigest(), 16)

def newcomer_message(peer, current_node_id):
    return json.dumps({ 'newcomer': peer.to_json(), 'sender': current_node_id })

def known_peers_message(known_peers):
    peer_list = []
    for peer in known_peers.keys():
        peer_list.append(known_peers[peer].get_peer().to_json())

    return { 'known_peers': peer_list }

def message_from_json(json_string) -> (str, object):
    data = json.loads(json_string)

    if 'text' in data.keys():
        result = Message()
        result.id = data['id']
        result.text = data['text']
        result.sender = data['sender']
        return ('message', result)

    if 'newcomer' in data.keys():
        return ('newcomer', { 'peer': peer_from_dict(data['newcomer']), 'sender': data['sender'] })

    if 'known_peers' in data.keys():
        peer_list = []
        for peer in data['known_peers']:
            peer_list.append(peer_from_dict(peer))

        return ('known_peers', { 'peers': peer_list })
