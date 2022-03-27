import logging

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
        pass
