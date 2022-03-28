from transport import Transport, EastablishTransportError
import logging
import json
import asyncio
from node import Node
from message import message_from_json

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
    print(keys)

    nodeA = nodes[keys[0]]
    nodeB = nodes[keys[1]]
    nodeC = nodes[keys[2]]

    loop = asyncio.get_event_loop()
    coroutine = nodeA.add_and_broadcast_peer(nodeB.get_peer_info())
    loop.run_until_complete(coroutine)

    coroutine = nodeA.add_and_broadcast_peer(nodeC.get_peer_info())
    loop.run_until_complete(coroutine)

    for peer in nodeA.known_peers.keys():
        print(nodeA.known_peers[peer].peer_id, end = ' ')
    print()
    for peer in nodeB.known_peers.keys():
        print(nodeB.known_peers[peer].peer_id, end = ' ')
    print()
    for peer in nodeC.known_peers.keys():
        print(nodeC.known_peers[peer].peer_id, end = ' ')
    print()

run_playbook_1()