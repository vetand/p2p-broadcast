import asyncio
import yaml
import logging
import aiofiles
from telegram_transport import TelegramTransport
from tcp_transport import TCPTransport

logging.basicConfig(filename="log.txt", level=logging.INFO)

async def main():
    config = yaml.safe_load(open("config.yaml", "r"))
    in_file = await aiofiles.open("/dev/stdin", "r")
    out_file = await aiofiles.open("/dev/stdout", "w")

    transport_creators = [TelegramTransport.create_from_config, TCPTransport.create_from_config]
    transports = []


    def on_message(m):
        logging.warning("New message: {}".format(m))

    for creator in transport_creators:
        transport = creator(config["transports"])
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
