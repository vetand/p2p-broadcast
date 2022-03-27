import json
import logging
import uuid

from node import Node
from message import Message, message_from_json
from peer import Peer, from_qr_code

def run_playbook_1(node):
    # basic interface ###############################################
    peer = Peer('me', None)
    node.add_peer(peer)

    message = message_from_json('{"id": "unique", "text": "hey", "sender": "me"}')
    node.on_message_receive(message)
    node.on_message_receive(message) # just ignore

    for i in range(10):
        json = '{"id": "' + str(uuid.uuid4()) + '", "text": "GG", "sender": "me"}'
        gen_message = message_from_json(json)
        node.on_message_receive(gen_message)

    node.on_message_receive(message) # not ignore
    node.on_message_receive(message) # ignore again

    # QR generation ###############################################

    logging.info("node ID = {}".format(node.id))
    node.send_qr()
    peer = from_qr_code()
    logging.info("generated peer ID = {}, pubkey = {}".format(peer.id, peer.pubkey))

def run_playbook_2(node):
    for peer_name in ['A', 'B', 'C', 'D', 'E']:
        peer = Peer(peer_name, None)
        node.add_and_broadcast_peer(peer)

    for peer_name in ['A', 'B', 'C']:
        add_member_message = {
            'newcomer': {
                'id': 'F',
                'pubkey': {
                    'n': '856065456185554426478737699815514',
                    'e': '65537',
                }
            },
            'sender': peer_name,
        }
        node.on_message_receive(message_from_json(json.dumps(add_member_message)))
        user_message = {
            'id': 'XXX',
            'sender': 'F',
            'text': 'hey',
        }
        node.on_message_receive(message_from_json(json.dumps(user_message)))

def run_playbook_3(node):
    add_members_message = {
        'known_peers': [
            {
                'id': 'A',
                'pubkey': {
                    'n': '856065456185554426478737699815514',
                    'e': '65537',
                }
            },
            {
                'id': 'B',
                'pubkey': {
                    'n': '856065456185554426478737699815514',
                    'e': '65537',
                }
            },
            {
                'id': 'C',
                'pubkey': {
                    'n': '856065456185554426478737699815514',
                    'e': '65537',
                }
            },
            {
                'id': 'D',
                'pubkey': {
                    'n': '856065456185554426478737699815514',
                    'e': '65537',
                }
            },
        ],
    }

    node.on_message_receive(message_from_json(json.dumps(add_members_message)))
    user_message = {
        'id': 'XXX',
        'sender': 'C',
        'text': 'hey',
    }
    node.broadcast_message('loopa & pupa')
