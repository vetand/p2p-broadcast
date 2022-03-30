import math
import os.path
import json
import logging
import time
import uuid
import asyncio
import random
import string
import base64
import hashlib

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from peer import Peer
from message import Message, message_from_json, known_peers_message
from transport import Transport
from Crypto.Cipher import AES
from collections import defaultdict

MAX_CACHE_MESSAGES = 50
KEY_STORAGE = 'key.pem'
AES_KEY_STORAGE = 'aes.txt'
ID_STORAGE = 'id.txt'
PEERS_STORAGE = 'peers.json'

class AESCipher(object):
    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode()

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

class PeersInfo:
    def __init__(self, peer_id, pubkey, transports):
        self.peer_id = peer_id
        self.pubkey = pubkey
        self.transports = transports

    def get_peer(self):
        return Peer(self.peer_id, self.pubkey, self.transports)

    def to_dict(self):
        return {
            'peer_id': self.peer_id,
            'pubkey': self.pubkey.export_key().decode(),
            'transports': self.transports,
        }

def peers_info_from_dict(info):
    return PeersInfo(info['peer_id'], info['pubkey'], info['transports'])

class Node:
    def __init__(self):
        self.id = str(uuid.uuid4())

        if not os.path.exists(ID_STORAGE):
            self.id = str(uuid.uuid4())
            f = open(ID_STORAGE,'wb')
            f.write(self.id.encode())
            f.close()
        else:
            f = open(ID_STORAGE, "rb")
            self.id = f.read().decode()
            f.close()

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

        self.known_peers = dict()

        if not os.path.exists(PEERS_STORAGE):
            self.known_peers = dict()
            self.save_peers()
        else:
            f = open(PEERS_STORAGE, "rb")
            peers = json.load(f)
            f.close()

            for peer in peers['peers']:
                self.known_peers['peer_id'] = peers_info_from_dict(peer)

        self.pubkey = key.publickey().export_key()
        self.privkey = key.export_key()

        self.unverified_peers = dict()
        self.peer_verifications = defaultdict(lambda: set())

        # message history info
        self.messages_receipt_time = dict()
        self.messages = dict()

        self.transports = []

    def save_peers(self):
        f = open(PEERS_STORAGE, 'wb')
        final_dict = {
            'peers': [],
        }
        for peer in self.known_peers.keys():
            final_dict['peers'].append(self.known_peers[peer].to_dict())
        f.write(json.dumps(final_dict).encode())
        f.close()

    def add_transport(self, transport):
        self.transports.append(transport)
        self.transports[-1].set_on_message(self.on_message_receive)


    def add_peer(self, peer):
        self.known_peers[peer.id] = PeersInfo(peer.id, peer.pubkey, peer.transports)
        self.save_peers()

    def check_peer_verified(self, peer):
        if self.unverified_peers.get(peer.id) is None:
            return
        if len(self.peer_verifications[peer.id]) >= min(3, len(self.known_peers) + 1):
            self.known_peers[peer.id] = self.unverified_peers[peer.id]
            del self.peer_verifications[peer.id]
            del self.unverified_peers[peer.id]

    def add_peer(self, peer, verified_by):
        if verified_by is None:
            self.known_peers[peer.id] = PeersInfo(peer.id, peer.pubkey, peer.transports)
        else:
            self.peer_verifications[peer.id].add(verified_by)
            self.unverified_peers[peer.id] = PeersInfo(peer.id, peer.pubkey, peer.transports)
            self.check_peer_verified(peer)

    async def send_known_peers(self, peer):
        message = known_peers_message(self.known_peers)
        message['known_peers'].append(self.get_peer_info().to_json())
        message['sender'] = self.id
        await self.sign_and_send_message(peer, message)

    async def add_and_broadcast_peer(self, peer):
        message = {
            'newcomer': peer.to_json(),
            'sender': self.id,
        }
        awaits = []
        for peer_id in self.known_peers.keys():
            awaits.append(self.sign_and_send_message(self.known_peers[peer_id].get_peer(), message))
        await asyncio.gather(*awaits)

        await self.send_known_peers(peer)
        self.add_peer(peer, self.id)

    async def broadcast_message(self, text: str):
        message = {
            'id': str(uuid.uuid4()),
            'text': text,
            'sender': self.id,
        }
        awaits = []
        for peer_id in self.known_peers.keys():
            awaits.append(self.sign_and_send_message(self.known_peers[peer_id].get_peer(), message))
        await asyncio.gather(*awaits)

    async def broadcast_message_struct(self, message: Message, signature):
        awaits = []
        for peer_id in self.known_peers.keys():
            awaits.append(self.resend_message_with_signature(self.known_peers[peer_id].get_peer(), message, signature))
        await asyncio.gather(*awaits)

    def verify_signature(self, message, signature):    
        peer = self.known_peers[message['sender']]
        digest = SHA256.new()
        digest.update(json.dumps(message).encode('utf-8'))

        if not peer.pubkey:
            return False

        verifier = PKCS1_v1_5.new(peer.pubkey)
        return verifier.verify(digest, bytes.fromhex(signature))

    def validate_message(self, message, signature) -> bool:
        if message.sender not in self.known_peers.keys():
            logging.info('Ignore message {} as it came from unknown peer'.format(message.id))
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

    def on_message_receive(self, q: dict):
        req = json.loads(q['message'])
        c = Cipher_PKCS1_v1_5.new(RSA.importKey(self.privkey))
        res = c.decrypt(base64.b64decode(req['key']), None).decode()
        cipfer = AESCipher(res)
        req = cipfer.decrypt(req["payload"])

        message = message_from_json(req)
        logging.info('Got message {}'.format(message))

        # simple user message
        if message[0] == 'message':
            if self.validate_message(message[1], message[2]):
                msg = message
                message = message[1]
                if message.id in self.messages_receipt_time:
                    logging.info("Message {} already in store".format(message))
                else:
                    self.messages_receipt_time[message.id] = time.time()
                    self.messages[message.id] = message
                    self.inspect_messages_store()
                    asyncio.ensure_future(self.broadcast_message_struct(msg[1], msg[2]))
        # when new peer is broadcasted by 3 QR-code receivers
        elif message[0] == 'newcomer':
            message, signature = message[1], message[2]
            message['newcomer'] = message['newcomer'].to_json()
            newcomer = json.loads(message['newcomer'])

            if message['sender'] not in self.known_peers.keys():
                logging.info('Ignore message {} as it came from unknown peer'.format(message))
                return

            if not self.verify_signature(message, signature):
                logging.info('Ignore new peer as bad signature')
                return False

            if newcomer['id'] in self.known_peers.keys() or message['sender'] in self.peer_verifications[newcomer['id']]:
                logging.info('Already added')
                return

            peer = Peer(newcomer['id'], RSA.import_key(newcomer['pubkey']), newcomer['transports'])
            self.add_peer(peer, message['sender'])
            asyncio.ensure_future(self.broadcast_message_struct(message, signature))

        # receive full peer_list from other node
        elif message[0] == 'known_peers':
            message, signature = message[1], message[2]

            if len(self.known_peers) != 0:
                if message['sender'] not in self.known_peers.keys():
                    logging.info('Ignore message {} as it came from unknown peer'.format(message))
                    return

                if not self.verify_signature(message, signature):
                    logging.info('Ignore new peer as bad signature')
                    return False

            cnt = 0

            for peer in message['known_peers']:
                if peer['id'] not in self.known_peers.keys():
                    cnt += 1
                self.add_peer(Peer.from_dict(peer), None)
            if cnt > 0:
                asyncio.ensure_future(self.broadcast_message_struct(message, signature))

    def get_peer_info(self) -> Peer:
        infos = dict()
        for t in self.transports:
            infos[t.get_name()] = t.get_peer_info()
        return Peer(self.id, self.get_pubkey(), infos)

    def send_qr(self, filename = "QR.png"):
        self.get_peer_info().make_qr_code(filename)

    def get_recent_messages(self, size, full=False):
        size = int(size)
        result = []
        for item in sorted(self.messages_receipt_time.items(), key = lambda x: x[1])[::-1]:
            if len(result) == size:
                break
            if full:
                result.append(self.messages[item[0]])
            else:
                result.append(self.messages[item[0]].text)
        return result

    def get_pubkey(self) -> RSA.RsaKey:
        f = open(KEY_STORAGE,'r')
        result = RSA.import_key(f.read()).publickey()
        f.close()
        return result

    async def sign_and_send_message(self, peer, message):
        logging.info("Sign and send message {} to peer {}".format(message, peer.id))

        final_message = dict()
        final_message['message'] = message
        digest = SHA256.new()
        digest.update(json.dumps(message).encode('utf-8')) 
        signer = PKCS1_v1_5.new(RSA.importKey(self.privkey))
        final_message['signature'] = signer.sign(digest).hex()
        await self.send_securely(peer, final_message)

    async def resend_message_with_signature(self, peer, message, signature):
        final_message = dict()
        final_message['message'] = message
        final_message['signature'] = signature
        await self.send_securely(peer, final_message)

    async def send_securely(self, peer, final_message):
        cipher = Cipher_PKCS1_v1_5.new(peer.pubkey)
        aes_key = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
        aes_cipher = AESCipher(aes_key)

        raw_message = json.dumps(final_message)
        raw_message = aes_cipher.encrypt(raw_message).decode()

        key_b64 = base64.b64encode(cipher.encrypt(aes_key.encode())).decode()

        the_final_stuff = json.dumps({"payload": raw_message, "key": key_b64})

        for transport in self.transports:
            if await transport.send_message(peer, the_final_stuff):
                return

        logging.info("Couldn't send message to peer {}, available transports: {}".format(peer.id, list(
            t.get_name() for t in self.transports)))
