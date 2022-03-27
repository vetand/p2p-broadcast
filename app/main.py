import asyncio
import yaml
import logging
import aiofiles
from telegram_transport import TelegramTransport

logging.basicConfig(filename="log.txt", level=logging.INFO)

async def main():
    config = yaml.safe_load(open("config.yaml", "r"))
    in_file = await aiofiles.open("/dev/stdin", "r")
    out_file = await aiofiles.open("/dev/stdout", "w")

    transport_creators = [TelegramTransport.create_from_config]
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
        phone = l[0]
        msg = " ".join(l[1:])
        for t in transports:
            asyncio.ensure_future(t.send_message({"phone": phone}, msg))

if __name__ == "__main__":
    asyncio.ensure_future(main())
    asyncio.get_event_loop().run_forever()
