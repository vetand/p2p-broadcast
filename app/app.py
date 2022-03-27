import asyncio

from fastapi import FastAPI, UploadFile
from node import Node
import logging
from peer import from_qr_code
from playbook import run_playbook_3
from fastapi.responses import FileResponse
from main import main

logging.basicConfig(level=logging.INFO)
filename = 'QR.png'

node = Node()
app = FastAPI()

@app.on_event("startup")
async def startup_event():
    asyncio.ensure_future(main(), loop=asyncio.get_running_loop())

@app.get('/playbook')
def playbook():
    run_playbook_3(node)
    return 'OK! Watch server logs'

@app.get('/get-peer')
def get_peer():
    global node
    node.send_qr(filename)
    return FileResponse(filename, media_type='image/png')

@app.post('/add-peer')
def add_peer(file: UploadFile):
    global node
    node.add_and_broadcast_peer(from_qr_code(file.filename))
    for peer in node.known_peers:
        logging.info(peer.id)
    return 'OK'

@app.get('/get-messages')
def get_messages(size: int):
    global node
    messages = node.get_recent_messages(size)
    return str(messages)

@app.post('/broadcast-message')
def broadcast_message(text: str):
    global node
    node.broadcast_message(text)
    return 'OK'
