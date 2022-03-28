from transport import Transport, EastablishTransportError
import logging
import json
import asyncio
from node import Node
from message import message_from_json
import random
import string
import uuid


open('log_file.txt', 'w')
logging.basicConfig(filename="log_file.txt", level=logging.INFO)


class TestTransport(Transport):
    def __init__(self, nodes):
        super().__init__()
        self.nodes = nodes
        logging.info("Initialize TCP transport")
        self.config = {
            'phone': '88005553535'
        }

    async def send_message(self, peer, message):
        logging.info('Sent message to {}: {}'.format(peer, message))
        message = { 'message': message }
        self.nodes[peer.id].on_message_receive(message)

    def get_peer_info(self):
        return {"phone": self.config["phone"]}

    def get_name(self):
        return "testing"


def create_nodes(node_count):
    nodes = dict()

    for i in range(node_count):
        node = Node()
        node.id = str(uuid.uuid4())
        nodes[node.id] = node

    transport = TestTransport(nodes)
    for id in nodes.keys():
        nodes[id].add_transport(transport)

    return nodes


def test_3_nodes():
    nodes = create_nodes(5)
    keys = list(nodes.keys())

    nodeA = nodes[keys[0]]
    nodeB = nodes[keys[1]]
    nodeC = nodes[keys[2]]

    loop = asyncio.get_event_loop()
    coroutine = nodeA.add_and_broadcast_peer(nodeB.get_peer_info())
    loop.run_until_complete(coroutine)

    coroutine = nodeA.add_and_broadcast_peer(nodeC.get_peer_info())
    loop.run_until_complete(coroutine)

    coroutine = nodeB.add_and_broadcast_peer(nodeC.get_peer_info())
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
    assert nodeB.get_recent_messages(10) == ['biba2','biba']
    assert nodeC.get_recent_messages(10) == ['biba']

def test_message_order():
    nodes = create_nodes(7)
    keys = list(nodes.keys())

    loop = asyncio.get_event_loop()
    for i in range(1, len(keys)):
        for j in range(min(3, i)):
            loop.run_until_complete(nodes[keys[j]].add_and_broadcast_peer(nodes[keys[i]].get_peer_info()))
    for node in nodes.values():
        assert len(node.known_peers.keys()) == len(nodes) - 1

    random.seed(123)
    messages = []
    for i in range(40):
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

def test_deny_access():
    nodes = create_nodes(3)
    keys = list(nodes.keys())

    nodeA = nodes[keys[0]]
    nodeB = nodes[keys[1]]
    nodeC = nodes[keys[2]]

    loop = asyncio.get_event_loop()
    loop.run_until_complete(nodeA.add_and_broadcast_peer(nodeB.get_peer_info()))
    loop.run_until_complete(nodeA.add_and_broadcast_peer(nodeC.get_peer_info()))

    loop.run_until_complete(nodeC.broadcast_message("hello"))

    assert nodeA.get_recent_messages(10) == []
    assert nodeB.get_recent_messages(10) == []

    assert len(nodeA.known_peers.keys()) == 1
    assert len(nodeB.known_peers.keys()) == 1

def test_qr_count():
    nodes = create_nodes(5)
    keys = list(nodes.keys())

    loop = asyncio.get_event_loop()
    for i in range(4):
        for j in range(i):
            loop.run_until_complete(nodes[keys[j]].add_and_broadcast_peer(nodes[keys[i]].get_peer_info()))

    for i in range(4):
        assert len(nodes[keys[i]].known_peers.keys()) == 3

    loop = asyncio.get_event_loop()
    loop.run_until_complete(nodes[keys[0]].add_and_broadcast_peer(nodes[keys[4]].get_peer_info()))
    loop.run_until_complete(nodes[keys[4]].broadcast_message("first_hello"))
    loop.run_until_complete(nodes[keys[0]].broadcast_message("first_internal_hello"))

    loop.run_until_complete(nodes[keys[1]].add_and_broadcast_peer(nodes[keys[4]].get_peer_info()))
    loop.run_until_complete(nodes[keys[4]].broadcast_message("second_hello"))
    loop.run_until_complete(nodes[keys[0]].broadcast_message("second_internal_hello"))

    for i in range(4):
        assert len(nodes[keys[i]].known_peers.keys()) == 3

    loop.run_until_complete(nodes[keys[2]].add_and_broadcast_peer(nodes[keys[4]].get_peer_info()))
    loop.run_until_complete(nodes[keys[4]].broadcast_message("third_hello"))
    loop.run_until_complete(nodes[keys[0]].broadcast_message("third_internal_hello"))

    for i in range(5):
        assert len(nodes[keys[i]].known_peers.keys()) == 4

    loop.run_until_complete(nodes[keys[3]].add_and_broadcast_peer(nodes[keys[4]].get_peer_info()))
    loop.run_until_complete(nodes[keys[4]].broadcast_message("fourth_hello"))
    loop.run_until_complete(nodes[keys[0]].broadcast_message("fourth_internal_hello"))

    for i in range(5):
        assert len(nodes[keys[i]].known_peers.keys()) == 4

    assert nodes[keys[0]].get_recent_messages(10) == ["fourth_hello", "third_hello"]
    for i in range(1, 4):
        assert nodes[keys[i]].get_recent_messages(10) == ["fourth_internal_hello", "fourth_hello", "third_internal_hello", "third_hello", "second_internal_hello", "first_internal_hello"]
    assert nodes[keys[4]].get_recent_messages(10) == ["fourth_internal_hello", "third_internal_hello"]


tests = [
    test_3_nodes,
    test_message_order,
    test_deny_access,
    test_qr_count,
]

for test in tests:
    print("Running test {}".format(test.__name__))
    test()
