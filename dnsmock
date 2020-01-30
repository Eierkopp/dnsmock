#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import logging
import dnsmocklib

logging.basicConfig(level=logging.DEBUG)

config = dnsmocklib.config

loop = asyncio.get_event_loop()
loop.set_debug(config.getboolean("global", "debug"))

mocks = dnsmocklib.mocks(config, loop)
mocks.start()

network = dnsmocklib.network(config, loop)
network.start(mocks)

http_server = dnsmocklib.http_server(config, loop)
http_server.start(network, mocks)

try:
    print("======== Running ========\n"
          "(Press CTRL+C to quit)")
    loop.run_forever()
except KeyboardInterrupt:
    pass

http_server.shutdown()
network.stop()
mocks.stop()
loop.close()
