from flask import Flask, flash, request, redirect, url_for, render_template, send_file
from node import Node
import logging
from peer import from_qr_code
from playbook import run_playbook_3

logging.basicConfig(level=logging.INFO)
filename = 'QR.png'

node = Node()
app = Flask(__name__)

@app.route('/playbook')
def playbook():
    run_playbook_3(node)
    return 'OK! Watch server logs'

@app.route('/get-peer')
def get_peer():
    global node
    node.send_qr(filename)
    return send_file(filename, mimetype='image/png')

@app.route('/add-peer', methods = ['GET', 'POST'])
def add_peer():
    if request.method == 'POST':
        global node

        file = request.files[filename]
        file.save(filename)
        node.add_and_broadcast_peer(from_qr_code(filename))
        for peer in node.known_peers:
            logging.info(peer.id)
        return 'OK'

    return 'NOT OK'

@app.route('/get-messages')
def get_messages():
    global node

    size = request.args.get('size')
    messages = node.get_recent_messages(size)
    return str(messages)

@app.route('/broadcast-message', methods = ['POST'])
def broadcast_message():
    global node

    text = request.args.get('text')
    node.broadcast_message(text)
    return 'OK'
