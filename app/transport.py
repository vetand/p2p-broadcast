import json
import logging
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

class Transport:
    def __init__(self):
        logging.info("Initialize transport")
        pass
        
    def send_message(self, privkey, peer, message):
        logging.info("Sign and send message {} to peer {}".format(message, peer.id))

        if 'sender' in message.keys():
            digest = SHA256.new()
            digest.update(message['sender'].encode('utf-8')) 
            signer = PKCS1_v1_5.new(RSA.importKey(privkey))
            message['signature'] = signer.sign(digest).hex()
        raw_message = json.dumps(message)

        logging.info("Signed message is {}".format(raw_message))
        pass
