from transport import Transport, EastablishTransportError
import logging
import json
import asyncio
from node import Node
from message import message_from_json
import random
import string

nodes = dict()

for i in range(5):
    node = Node()
    nodes[node.id] = node

class TestTransport(Transport):
    def __init__(self, nodes):
        super().__init__()
        self.nodes = nodes
        logging.info("Initialize TCP transport")
        self.config = {
            'phone': '88005553535'
        }

    async def send_message(self, peer, message):
        self.nodes[peer.id].on_message_receive(message)

    def get_peer_info(self):
        return {"phone": self.config["phone"]}

    def get_name(self):
        return "testing"

transport = TestTransport(nodes)
for id in nodes.keys():
    nodes[id].add_transport(transport)

def run_playbook_1():
    global nodes
    keys = list(nodes.keys())

    nodeA = nodes[keys[0]]
    nodeB = nodes[keys[1]]
    nodeC = nodes[keys[2]]

    loop = asyncio.get_event_loop()
    coroutine = nodeA.add_and_broadcast_peer(nodeB.get_peer_info())
    loop.run_until_complete(coroutine)

    coroutine = nodeA.add_and_broadcast_peer(nodeC.get_peer_info())
    loop.run_until_complete(coroutine)

    assert len(nodeA.known_peers.keys()) == 2
    assert len(nodeB.known_peers.keys()) == 2
    assert len(nodeC.known_peers.keys()) == 2

    coroutine = nodeA.broadcast_message("biba")
    loop.run_until_complete(coroutine)

    assert nodeA.get_recent_messages(10) == []
    assert nodeB.get_recent_messages(10) == ['biba']
    assert nodeC.get_recent_messages(10) == ['biba']

    coroutine = nodeC.broadcast_message("biba2")
    loop.run_until_complete(coroutine)

    assert nodeA.get_recent_messages(10) == ['biba2']
    assert nodeB.get_recent_messages(10) == ['biba2', 'biba']
    assert nodeC.get_recent_messages(10) == ['biba']

def run_playbook_2():
    global nodes
    keys = list(nodes.keys())

    loop = asyncio.get_event_loop()
    for i in range(1, len(keys)):
        loop.run_until_complete(nodes[keys[i - 1]].add_and_broadcast_peer(nodes[keys[i]].get_peer_info()))
    for node in nodes.values():
        assert len(node.known_peers.keys()) == len(nodes) - 1

    random.seed(123)
    messages = []
    for i in range(100):
        messages.append(''.join(random.choice(string.ascii_lowercase) for _ in range(4)))

    correct_messages = dict()
    for key in keys:
        correct_messages[key] = []

    for message in messages:
        current = random.choice(keys)
        for key in keys:
            if key != current:
                correct_messages[key].append(message)
        loop.run_until_complete(nodes[current].broadcast_message(message))

    for key in keys:
        assert correct_messages[key][-8:][::-1] == nodes[key].get_recent_messages(8)

run_playbook_1()
