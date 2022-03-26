import logging
import time
import uuid

from peer import Peer
from message import Message, message_from_json
from transport import Transport

MAX_CACHE_MESSAGES = 10

class Node:
    def __init__(self):
        self.id = str(uuid.uuid4())
        self.known_peers = set()
        self.messages_receipt_time = dict()
        self.transport = Transport()

    def add_peer(self, peer):
        self.known_peers.add(peer)

    def broadcast(self, message):
        for peer in self.known_peers:
            self.transport.send_message(peer, message)

    def validate_message(self, message) -> bool:
        if message.id in self.messages_receipt_time.keys():
            logging.info('Ignore messgage {} as it was previously broadcasted'.format(message.id))
            return False
        return True

    def inspect_messages_store(self):
        if len(self.messages_receipt_time) >= MAX_CACHE_MESSAGES:
            message_to_exclude = min(self.messages_receipt_time.items(), key=lambda row: row[1])
            del self.messages_receipt_time[message_to_exclude[0]]

    def on_message_receive(self, message):
        logging.info('Got message {}'.format(message.id))
        if self.validate_message(message):
            self.messages_receipt_time[message.id] = time.time()
            self.inspect_messages_store()
            self.broadcast(message)

    def get_peer_info(self) -> Peer:
        return Peer(self.id)

    def send_qr(self, filename = "QR.png"):
        self.get_peer_info().make_qr_code(filename)
