import asyncio
import yaml
import logging
import aiofiles
import argparse
from telegram_transport import TelegramTransport
from tcp_transport import TCPTransport

async def main():
    parser = argparse.ArgumentParser(description="p2p-broadcast console")
    parser.add_argument('--config', default="config.yaml",
                        help='Config file path')
    args = parser.parse_args()

    config = yaml.safe_load(open(args.config, "r"))
    logging.basicConfig(filename=config["log_file"], level=logging.INFO)
    in_file = await aiofiles.open("/dev/stdin", "r")
    out_file = await aiofiles.open("/dev/stdout", "w")

    transport_creators = {"telegram": TelegramTransport.create_from_config, "tcp": TCPTransport.create_from_config}
    transports = []

    def on_message(m):
        logging.warning("New message: {}".format(m))

    for creator in transport_creators:
        if creator in config["transports"]:
            transport = (transport_creators[creator])(config["transports"])
            transport.set_on_message(on_message)
            await transport.establish()
            transports.append(transport)

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
    asyncio.ensure_future(main())
    asyncio.get_event_loop().run_forever()
