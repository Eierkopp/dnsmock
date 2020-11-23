#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import logging
import dnsmocklib

logging.basicConfig(level=logging.DEBUG)


async def setup():
    loop.set_debug(config.getboolean("global", "debug"))

    mocks.start()
    await client.start()
    await server.start(mocks, client)
    await http_server.start(server, mocks)


async def shutdown():
    await http_server.stop()
    await server.stop()
    await client.stop()
    mocks.stop()


loop = asyncio.get_event_loop()
config = dnsmocklib.config
mocks = dnsmocklib.Mocks(config)
client = dnsmocklib.DNS_Client(config)
server = dnsmocklib.DNS_Server(config)
http_server = dnsmocklib.HttpServer(config)

loop.run_until_complete(setup())

try:
    print("======== Running ========\n"
          "(Press CTRL+C to quit)")
    loop.run_forever()
except KeyboardInterrupt:
    pass

loop.run_until_complete(shutdown())

loop.close()
