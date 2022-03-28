import os.path
import json
import logging
import time
import uuid
import asyncio

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from peer import Peer
from message import Message, message_from_json, known_peers_message
from transport import Transport

MAX_CACHE_MESSAGES = 10
KEY_STORAGE = 'key.pem'

class PeersInfo:
    def __init__(self, peer_id, pubkey, transports):
        self.peer_id = peer_id
        self.verifications = 1
        self.pubkey = pubkey
        self.transports = transports

    def verify(self):
        self.verifications += 1

    def verified(self, system_size):
        return self.verifications >= 3 or self.verifications >= system_size

    def get_peer(self):
        return Peer(self.peer_id, self.pubkey, self.transports)

class Node:
    def __init__(self):
        self.id = str(uuid.uuid4())

        if not os.path.exists(KEY_STORAGE):
            key = RSA.generate(1024, get_random_bytes)
            f = open(KEY_STORAGE,'wb')
            f.write(key.export_key('PEM'))
            f.close()
        else:
            f = open(KEY_STORAGE, "rb")
            encoded_key = f.read()
            f.close()
            key = RSA.import_key(encoded_key)   

        self.pubkey = key.publickey().export_key()
        self.privkey = key.export_key()

        self.known_peers = dict()

        # message history info
        self.messages_receipt_time = dict()
        self.messages = dict()

        self.transports = []

    def add_transport(self, transport):
        self.transports.append(transport)
        self.transports[-1].set_on_message(self.on_message_receive)

    def add_peer(self, peer, already_verified=False):
        if peer.id in self.known_peers.keys():
            self.known_peers[peer.id].verify()
            return

        self.known_peers[peer.id] = PeersInfo(peer.id, peer.pubkey, peer.transports)
        if already_verified:
            self.known_peers[peer.id].verifications = 3

    async def send_known_peers(self, peer):
        message = known_peers_message(self.known_peers)
        message['known_peers'].append(self.get_peer_info().to_json())
        await self.encode_and_send_message(self.privkey, peer, message)

    async def add_and_broadcast_peer(self, peer):
        message = {
            'newcomer': peer.to_json(),
            'sender': self.id,
        }
        awaits = []
        for peer_id in self.known_peers.keys():
            awaits.append(self.encode_and_send_message(self.privkey, self.known_peers[peer_id].get_peer(), message))
        await asyncio.gather(*awaits)

        await self.send_known_peers(peer)
        self.add_peer(peer, already_verified=True)

    async def broadcast_message(self, text):
        message = {
            'id': str(uuid.uuid4()),
            'text': text,
            'sender': self.id,
        }
        awaits = []
        for peer_id in self.known_peers.keys():
            awaits.append(self.encode_and_send_message(self.privkey, self.known_peers[peer_id].get_peer(), message))
        await asyncio.gather(*awaits)

    def verify_signature(self, message, signature):
        peer = self.known_peers[message['sender']]
        digest = SHA256.new()
        digest.update(json.dumps(message).encode('utf-8'))

        if not peer.pubkey:
            return False

        pubkey = peer.pubkey
        try:
            pubkey = pubkey.encode('utf-8')
        except Exception as e:
            pass

        verifier = PKCS1_v1_5.new(RSA.import_key(pubkey))
        return verifier.verify(digest, bytes.fromhex(signature))

    def validate_message(self, message, signature) -> bool:
        if message.sender not in self.known_peers.keys():
            logging.info('Ignore message {} as it came from unknown peer'.format(message.id))
            return False

        if not self.known_peers[message.sender].verified(len(self.known_peers)):
            logging.info('Ignore message {} as it came from unverified peer'.format(message.id))
            return False

        raw_message = {
            'id': message.id,
            'text': message.text,
            'sender': message.sender,
        }
        if not self.verify_signature(raw_message , signature):
            logging.info('Ignore message {} as bad signature'.format(message.id))
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
            if self.validate_message(message[1], message[2]):
                message = message[1]
                self.messages_receipt_time[message.id] = time.time()
                self.messages[message.id] = message
                self.inspect_messages_store()
        # when new peer is broadcasted by 3 QR-code receivers
        elif message[0] == 'newcomer':
            message, signature = message[1], message[2]

            if not self.known_peers[message['sender']].verified(len(self.known_peers)):
                logging.warning('Trying to add peer from unverified peer')
                return

            if not self.verify_signature(message, signature):
                logging.info('Ignore new peer as bad signature')
                return False
 
            peer = Peer(message['newcomer']['id'], message['newcomer']['pubkey'])
            self.add_peer(peer)
        # receive full peer_list from other node
        elif message[0] == 'known_peers':
            message = message[1]
            for peer in message['peers']:
                self.add_peer(peer, already_verified=True)

    def get_peer_info(self) -> Peer:
        infos = dict()
        for t in self.transports:
            infos[t.get_name()] = t.get_peer_info()
        return Peer(self.id, self.get_pubkey(), infos)

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

    def get_pubkey(self) -> RSA.RsaKey:
        f = open(KEY_STORAGE,'r')
        result = RSA.import_key(f.read()).publickey()
        f.close()
        return result

    async def encode_and_send_message(self, privkey, peer, message):
        logging.info("Sign and send message {} to peer {}".format(message, peer.id))

        final_message = dict()
        final_message['message'] = message
        digest = SHA256.new()
        digest.update(json.dumps(message).encode('utf-8')) 
        signer = PKCS1_v1_5.new(RSA.importKey(privkey))
        final_message['signature'] = signer.sign(digest).hex()
        raw_message = json.dumps(final_message)

        for transport in self.transports:
            if await transport.send_message(peer, raw_message):
                return
