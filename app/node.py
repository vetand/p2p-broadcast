import json
import logging
import time
import rsa
import uuid

from peer import Peer
from message import Message, message_from_json, known_peers_message
from transport import Transport

MAX_CACHE_MESSAGES = 10

class PeersInfo:
    def __init__(self, peer_id, pubkey):
        self.peer_id = peer_id
        self.verifications = 1
        self.pubkey = pubkey

    def verify(self):
        self.verifications += 1

    def verified(self, system_size):
        return self.verifications >= 3 or self.verifications >= system_size

    def get_peer(self):
        return Peer(self.peer_id, self.pubkey)

class Node:
    def __init__(self):
        self.id = str(uuid.uuid4())
        (self.pubkey, self.privkey) = rsa.newkeys(512)

        self.known_peers = dict()

        # message history info
        self.messages_receipt_time = dict()
        self.messages = dict()

        self.transport = Transport()

    def add_peer(self, peer, already_verified=False):
        if peer.id in self.known_peers.keys():
            self.known_peers[peer.id].verify()
            return

        self.known_peers[peer.id] = PeersInfo(peer.id, peer.pubkey)
        if already_verified:
            self.known_peers[peer.id].verifications = 3

    def send_known_peers(self, peer):
        message = known_peers_message(self.known_peers)
        message['known_peers'].append(self.get_peer_info().to_json())
        self.transport.send_message(peer, json.dumps(message))

    def add_and_broadcast_peer(self, peer):
        message = json.dumps({ 'newcomer': peer.to_json(), 'sender': self.id })
        for peer_id in self.known_peers.keys():
            self.transport.send_message(self.known_peers[peer_id].get_peer(), message)

        self.send_known_peers(peer)
        self.add_peer(peer, already_verified=True)

    def broadcast_message(self, text):
        message = json.dumps({ 'id': str(uuid.uuid4()), 'text': text, 'sender': self.id })
        for peer_id in self.known_peers.keys():
            self.transport.send_message(self.known_peers[peer_id].get_peer(), message)

    def validate_message(self, message) -> bool:
        if message.sender not in self.known_peers.keys():
            logging.info('Ignore message {} as it came from unknown peer'.format(message.id))
            return False

        if not self.known_peers[message.sender].verified(len(self.known_peers)):
            logging.info('Ignore message {} as it came from unverified peer'.format(message.id))
            return False

        if message.id in self.messages_receipt_time.keys():
            logging.info('Ignore message {} as it was previously broadcasted'.format(message.id))
            return False
        return True

    def inspect_messages_store(self):
        if len(self.messages_receipt_time) >= MAX_CACHE_MESSAGES:
            message_to_exclude = min(self.messages_receipt_time.items(), key=lambda row: row[1])
            del self.messages_receipt_time[message_to_exclude[0]]
            del self.messages[message_to_exclude[0]]

    def on_message_receive(self, message):
        logging.info('Got message {}'.format(message))

        # simple user message
        if message[0] == 'message':
            if self.validate_message(message[1]):
                message = message[1]
                self.messages_receipt_time[message.id] = time.time()
                self.messages[message.id] = message
                self.inspect_messages_store()
        # when new peer is broadcasted by 3 QR-code receivers
        elif message[0] == 'newcomer':
            message = message[1]
            if not self.known_peers[message['sender']].verified(len(self.known_peers)):
                logging.warning('Trying to add peer from unverified peer')
                return

            self.add_peer(message['peer'])
        # receive full peer_list from other node
        elif message[0] == 'known_peers':
            message = message[1]
            for peer in message['peers']:
                self.add_peer(peer, already_verified=True)

    def get_peer_info(self) -> Peer:
        return Peer(self.id, { 'n': self.pubkey['n'], 'e': self.pubkey['e'] })

    def send_qr(self, filename = "QR.png"):
        self.get_peer_info().make_qr_code(filename)

    def get_recent_messages(self, size):
        size = int(size)
        result = []
        for item in sorted(self.messages_receipt_time.items())[::-1]:
            if len(result) == size:
                break
            result.append(self.messages[item[0]].text)
        return result
