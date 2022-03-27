import logging

class Transport:
    def __init__(self):
        logging.info("Initialize transport")
        pass

    def send_message(self, peer, message):
        logging.info("Send message {} to peer {}".format(message, peer.id))
        pass
