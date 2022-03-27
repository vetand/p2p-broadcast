import json
import logging
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

class Transport:
    def __init__(self):
        logging.info("Initialize transport")
        pass
        
    def send_message(self, message):
        logging.info("Signed message is {}".format(message))
        pass
