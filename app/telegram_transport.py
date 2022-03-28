from transport import Transport, EastablishTransportError
import logging
import json
from message import message_from_json
from telethon import TelegramClient, events
from telethon.tl.types import *
from telethon.tl.types.phone import *
from telethon.tl.functions import *
from telethon.tl.functions.phone import *
from telethon.tl.functions.messages import *
from telethon.errors.rpcerrorlist import SessionPasswordNeededError

API_ID = 10534
API_HASH = "844584f2b1fd2daecee726166dcc1ef8"

class TelegramTransport(Transport):

    def __init__(self, config):
        super().__init__()
        self.client = TelegramClient("p2p-session", API_ID, API_HASH)
        self.config = config
        self.client.add_event_handler(self.on_telegram_message, events.NewMessage)
        logging.info("Initialize Telegram transport")

    @staticmethod
    def create_from_config(config):
        d = config["telegram"]
        return TelegramTransport(d)

    async def send_message(self, peer, message):
        if peer.transports.get('telegram') is not None:
            wrapped_message = {"protocol": "p2p-1.0", "payload": message}
            await self.client.send_message(str(peer.transports['telegram']["phone"]), json.dumps(wrapped_message))
            return True
        return False
    
    async def on_telegram_message(self, event):
        logging.info("Received message: {}".format(event.raw_text))
        try:
            res = json.loads(event.raw_text)
            if not "protocol" in res or not "payload" in res:
                return
            if res["protocol"] != "p2p-1.0":
                return
            self.on_message(message_from_json(json.loads(res["payload"])))
        except json.JSONDecodeError:
            return

    def get_peer_info(self):
        return {"phone": self.config["phone"]}

    async def establish(self):
        await self.authorize()

    async def authorize(self):
        logging.info("Authorizing into Telegram...")
        await self.client.connect()
        if not await self.client.is_user_authorized():
            await self.client.send_code_request(self.config["phone"])
            logging.info("Code request sent")
            try:
                await self.client.sign_in(self.config["phone"], input("Enter the code: "))
            except SessionPasswordNeededError:
                try:
                    logging.info("Password required")
                    await self.client.sign_in(password=self.config["password"])
                except:
                    logging.info("Password incorrect")
                    raise EastablishTransportError()
        logging.info("Authorized to Telegram successfully")

    def get_name(self):
        return "telegram"
