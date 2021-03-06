import asyncio
import yaml
import logging
import aiofiles
import argparse
from telegram_transport import TelegramTransport
from tcp_transport import TCPTransport
from node import Node


async def main(node: Node, console_mode=False):
    in_file = None
    config = None
    if console_mode:
        parser = argparse.ArgumentParser(description="p2p-broadcast console")
        parser.add_argument('--config', default="config.yaml",
                            help='Config file path')
        args = parser.parse_args()
        config = yaml.safe_load(open(args.config, "r"))
        in_file = await aiofiles.open("/dev/stdin", "r")
        logging.basicConfig(filename=config["log_file"], level=logging.INFO)
    else:
        config = yaml.safe_load(open("config.yaml", "r"))

    transport_creators = {"telegram": TelegramTransport.create_from_config, "tcp": TCPTransport.create_from_config}
    transports = []

    def on_message(m):
        logging.warning("New message: {}".format(m))

    for creator in transport_creators:
        if creator in config["transports"]:
            transport = (transport_creators[creator])(config["transports"])
            transport.set_on_message(node.on_message_receive)
            await transport.establish()
            transports.append(transport)
            node.add_transport(transport)
    if console_mode:
        while True:
            cmd = await in_file.readline()
            l = cmd.split()
            type = l[0]
            if type == "tg":
                user = l[1]
                msg = " ".join(l[2:])
                for t in transports:
                    if isinstance(t, TelegramTransport):
                        asyncio.ensure_future(t.send_message({"phone": user}, msg))
            elif type == "tcp":
                host = l[1]
                port = int(l[2])
                msg = " ".join(l[3:])
                for t in transports:
                    if isinstance(t, TCPTransport):
                        asyncio.ensure_future(t.send_message({"host": host, "port": port}, msg))


if __name__ == "__main__":
    asyncio.ensure_future(main(node=Node(), console_mode=True))
    asyncio.get_event_loop().run_forever()
