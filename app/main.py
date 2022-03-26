import logging
import uuid

from node import Node
from message import Message, message_from_json
from peer import Peer

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    node = Node()

    peer1 = Peer('peer-1')
    peer2 = Peer('peer-47')

    node.add_peer(peer1)
    node.add_peer(peer2)

    message = message_from_json('{"id": "unique", "text": "hey"}')
    node.on_message_receive(message)
    node.on_message_receive(message) # just ignore

    for i in range(10):
        json = '{"id": "' + str(uuid.uuid4()) + '", "text": "GG"}'
        gen_message = message_from_json(json)
        node.on_message_receive(gen_message)

    node.on_message_receive(message) # not ignore
    node.on_message_receive(message) # ignore again
