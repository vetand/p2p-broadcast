import json
import logging
import uuid
import yaml
import asyncio

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from node import Node
from message import Message, message_from_json
from peer import Peer, from_qr_code
from telegram_transport import TelegramTransport

PRIVATE_KEY = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQD34AJOnZfW5qkM6EOZDYfi8Iac53GZ6gF5UaHzTv7UoWT2ViMU\n2QJd/nPfuO9pURedGZeGwLlX2tyweIHGcYS/Xrvxqxh6HcdQeMm/99FlzFA2rvXF\np+N3FftkJaq3LrB29WNGLiMb/j/JZMI9PvuvwI9CL4oLWQaNXiyeghDQxwIDAQAB\nAoGAM/yOX1CcFN1BnUxlSQdWdZk+kk/UOpSihIBDeBUcSxoiY6vDJc8xuObyBHzz\n8WGpkzBX4FIxTSTA3l4X0bfjQBoAcvbGFm20g4Czxw0e+DeaHlFHjii1ccBrjgyK\nNauhBrcUKvMO4LFJDrrYJiwzmsRjGbooFohzCLjyv0FppnkCQQD4bLMhp1zOK6sA\n8a+5Qg5L7JoAAiFO1TqjikCM6A077FQ2fhOeycMKeMXpU/WOad8L/P3zkZZbSfVK\nAcKj5qPzAkEA/28E43SObJbpaG+Zxd6thQB5EKkdiRjE7ugkzjpTRVFOdN0Agq/w\nhOOaRYhMfQnaihviWvdFUeRt/JkdYy+Y3QJAGl4PNUc6RnfEErmUWSl1swFN5ypS\ntrdTHgCSkWIf5XhUB+Sh2Hy5wubGutk6ev8puXAE1FFjkBTtgAlny1WzmQJASOJY\ntr4vVXTKLO6LJhaf1G+KG+LldpUGvFSpC99Am2rTxCy7VI73RjPbdTOq/5KsNPQ3\n5lTgBrnzWDwoUoDmUQJBAOazBxT6MKLofCdpTLqsYPtRlpqx110ksnyvBCV16tRl\nxK/n6oo//QYxmKDUtmQRMU4JPDcR9ppqr/KiU/NP7Vg=\n-----END RSA PRIVATE KEY-----'
PUBLIC_KEY = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD34AJOnZfW5qkM6EOZDYfi8Iac\n53GZ6gF5UaHzTv7UoWT2ViMU2QJd/nPfuO9pURedGZeGwLlX2tyweIHGcYS/Xrvx\nqxh6HcdQeMm/99FlzFA2rvXFp+N3FftkJaq3LrB29WNGLiMb/j/JZMI9PvuvwI9C\nL4oLWQaNXiyeghDQxwIDAQAB\n-----END PUBLIC KEY-----'

def sign(message):
    digest = SHA256.new()
    digest.update(json.dumps(message).encode('utf-8')) 
    signer = PKCS1_v1_5.new(RSA.importKey(PRIVATE_KEY))
    return signer.sign(digest).hex()

def run_playbook_1(node):
    logging.info("node ID = {}".format(node.id))
    node.send_qr()
    peer = from_qr_code()
    logging.info("generated peer ID = {}, pubkey = {}".format(peer.id, peer.pubkey))

def run_playbook_2(node):
    for peer_name in ['A', 'B', 'C', 'D', 'E']:
        peer = Peer(peer_name, PUBLIC_KEY)
        node.add_and_broadcast_peer(peer)

    for peer_name in ['A', 'B', 'C']:
        raw_message = {
            'newcomer': {
                'id': 'F',
                'pubkey': PUBLIC_KEY.decode('utf-8')
            },
            'sender': peer_name,
        }
        signature = sign(raw_message)

        add_member_message = {
            'message': raw_message,
            'signature': signature,
        }
        node.on_message_receive(message_from_json(json.dumps(add_member_message)))

        raw_message = {
            'id': 'XXX',
            'text': 'hey',
            'sender': 'F',
        }
        signature = sign(raw_message)
        user_message = {
            'message': raw_message,
            'signature': signature,
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
    node.broadcast_message('kek')


def test_telegram_transport():
    telegram_transport = TelegramTransport.create_from_config(yaml.safe_load(open("config.yaml", "r"))["transports"])
    asyncio.get_event_loop().run_until_complete(telegram_transport.establish())
    n1 = Node()
    n1.add_transport(telegram_transport)
    n2 = Node()
    n2.add_transport(telegram_transport)
    n1.add_peer(n2.get_peer_info())
    asyncio.get_event_loop().run_until_complete(n1.broadcast_message("hello 123321"))
