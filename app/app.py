import asyncio
import json

from fastapi import FastAPI, File, UploadFile, Form
from node import Node
import logging
from peer import from_qr_code
from playbook import run_playbook_4
from fastapi.responses import FileResponse
from main import main
from peer import Peer

logging.basicConfig(level=logging.INFO)
filename = 'QR.png'

node = Node()
app = FastAPI()

@app.on_event("startup")
async def startup_event():
    asyncio.ensure_future(main(node=node), loop=asyncio.get_running_loop())

@app.get('/playbook')
async def playbook():
    run_playbook_4(node)
    return 'OK! Watch server logs'

@app.get('/get-peer')
async def get_peer():
    global node
    node.send_qr(filename)
    return FileResponse(filename, media_type='image/png')

@app.get('/get-json')
async def get_peer():
    global node
    return json.loads(node.get_peer_info().to_json())

@app.post('/add-peer')
async def add_peer(file: UploadFile = File(...)):
    global node
    contents = await file.read()
    await node.add_and_broadcast_peer(from_qr_code(contents))
    for key in node.known_peers:
        logging.info("listing peer {}".format(node.known_peers[key]))
    return 'OK'

@app.post('/add-json')
async def add_peer(req: str = Form(...)):
    global node
    await node.add_and_broadcast_peer(Peer.from_json(req))
    for key in node.known_peers:
        logging.info("listing peer {}".format(node.known_peers[key]))
    return 'OK'

@app.get('/get-messages')
async def get_messages(size: int):
    global node
    messages = node.get_recent_messages(size)
    return str(messages)

@app.get('/get-recent-messages')
async def get_recent_messages(size: int):
    global node
    messages = node.get_recent_messages(size, full=True)
    return [json.loads(x.to_json()) for x in messages]

@app.get('/healthcheck')
async def healthcheck():
    return 'OK'

@app.post('/broadcast-message')
async def broadcast_message(text: str):
    global node
    await node.broadcast_message(text)
    return 'OK'
