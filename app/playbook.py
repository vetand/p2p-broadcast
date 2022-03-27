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
                'pubkey': '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClSjxTeqLzsnDiZk6KmRFR6keT\nA3eyQbRxYAy6hgbXADv7qq5NlVFL2x83x+zAAI+FnHKEK/Kg8q5SqSF/TSaTfPj5\nyN5f/pZFAeeRbkzIWQX/w1Ho5vIkq3oDbTv4ZCuSiXj7V6S8zqdTRFL174y1MQP0\nYAIpkQwgoegVGzS+QQIDAQAB\n-----END PUBLIC KEY-----'
            },
            'sender': peer_name,
            'signature': 'e4f95a1a19561402b76bd3a684207cae32d2b18acec30c25dee748452f9c01dbe343cd2ae5c2d48f68c4aa9db82bc35ccb9d935b2d4d159e43fa430e67dc416277735115c26aa55c6842fbd5c1b4b6d1a9aa67501908fb11bae46d3e89dfa80d0b74fe42c1e75c3067378650bce9c6eb5e3d71f6561e6a6aeb9f90e3d4323c6e',
        }
        node.on_message_receive(message_from_json(json.dumps(add_member_message)))
        user_message = {
            'id': 'XXX',
            'sender': 'F',
            'text': 'hey',
            'signature': 'e4f95a1a19561402b76bd3a684207cae32d2b18acec30c25dee748452f9c01dbe343cd2ae5c2d48f68c4aa9db82bc35ccb9d935b2d4d159e43fa430e67dc416277735115c26aa55c6842fbd5c1b4b6d1a9aa67501908fb11bae46d3e89dfa80d0b74fe42c1e75c3067378650bce9c6eb5e3d71f6561e6a6aeb9f90e3d4323c6e',
        }
        node.on_message_receive(message_from_json(json.dumps(user_message)))

def run_playbook_3(node):
    add_members_message = {
        'known_peers': [
            {
                'id': 'A',
                'pubkey': '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClSjxTeqLzsnDiZk6KmRFR6keT\nA3eyQbRxYAy6hgbXADv7qq5NlVFL2x83x+zAAI+FnHKEK/Kg8q5SqSF/TSaTfPj5\nyN5f/pZFAeeRbkzIWQX/w1Ho5vIkq3oDbTv4ZCuSiXj7V6S8zqdTRFL174y1MQP0\nYAIpkQwgoegVGzS+QQIDAQAB\n-----END PUBLIC KEY-----'
            },
            {
                'id': 'B',
                'pubkey': '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClSjxTeqLzsnDiZk6KmRFR6keT\nA3eyQbRxYAy6hgbXADv7qq5NlVFL2x83x+zAAI+FnHKEK/Kg8q5SqSF/TSaTfPj5\nyN5f/pZFAeeRbkzIWQX/w1Ho5vIkq3oDbTv4ZCuSiXj7V6S8zqdTRFL174y1MQP0\nYAIpkQwgoegVGzS+QQIDAQAB\n-----END PUBLIC KEY-----'
            },
            {
                'id': 'C',
                'pubkey': '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClSjxTeqLzsnDiZk6KmRFR6keT\nA3eyQbRxYAy6hgbXADv7qq5NlVFL2x83x+zAAI+FnHKEK/Kg8q5SqSF/TSaTfPj5\nyN5f/pZFAeeRbkzIWQX/w1Ho5vIkq3oDbTv4ZCuSiXj7V6S8zqdTRFL174y1MQP0\nYAIpkQwgoegVGzS+QQIDAQAB\n-----END PUBLIC KEY-----'
            },
            {
                'id': 'D',
                'pubkey': '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClSjxTeqLzsnDiZk6KmRFR6keT\nA3eyQbRxYAy6hgbXADv7qq5NlVFL2x83x+zAAI+FnHKEK/Kg8q5SqSF/TSaTfPj5\nyN5f/pZFAeeRbkzIWQX/w1Ho5vIkq3oDbTv4ZCuSiXj7V6S8zqdTRFL174y1MQP0\nYAIpkQwgoegVGzS+QQIDAQAB\n-----END PUBLIC KEY-----'
            },
        ],
    }

    node.on_message_receive(message_from_json(json.dumps(add_members_message)))
    user_message = {
        'id': 'XXX',
        'sender': 'C',
        'text': 'hey',
    }
    node.broadcast_message('kek')
