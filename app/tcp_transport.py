from transport import Transport, EastablishTransportError
import logging
import json
import asyncio

API_ID = 10534
API_HASH = "844584f2b1fd2daecee726166dcc1ef8"

class TCPTransport(Transport):

    def __init__(self, config):
        super().__init__()
        self.config = config
        logging.info("Initialize TCP transport")

    @staticmethod
    def create_from_config(config):
        d = config["tcp"]
        return TCPTransport(d)

    async def send_message(self, peer, message):
        try:
            wrapped_message = {"protocol": "p2p-1.0", "payload": message}
            reader, writer = await asyncio.open_connection(
                peer.transports['tcp']["host"], eer.transports['tcp']["port"])
            writer.write(json.dumps(wrapped_message).encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            logging.error("Could not send with TCP", e)
            return False

    async def on_tcp_message(self, reader, writer):
        msg = (await reader.read()).decode().strip()
        logging.info("Received message {} from {}".format(msg, writer.get_extra_info("peername")))
        try:
            res = json.loads(msg)
            if not "protocol" in res or not "payload" in res:
                return
            if res["protocol"] != "p2p-1.0":
                return
            self.on_message(json.loads(res["payload"]))
        except json.JSONDecodeError:
            logging.info("JSON error")
            return
        except:
            logging.info("Strange message")
            return

    def get_peer_info(self):
        return {"host": self.config["host"], "port": self.config["port"]}

    async def establish(self):
        logging.info("Starting up a TCP server...")
        self.server = await asyncio.start_server(
            self.on_tcp_message, "0.0.0.0", self.config["port"])
        logging.info("TCP server started!")

    def get_name(self):
        return "tcp"
