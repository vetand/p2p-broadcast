import json
import logging
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

class EastablishTransportError(Exception):
    pass

class Transport:
    def __init__(self):
        logging.info("Initialize transport")
        pass

    def establish(self):
        pass

    def set_on_message(self, callback):
        self.on_message = callback

    def send_message(self, peer, message):
        logging.info("Send message {} to peer {}".format(message, peer.id))

    def get_peer_info(self) -> dict:
        pass

    def get_name(self) -> str:
        pass
