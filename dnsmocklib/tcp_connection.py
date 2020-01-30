import asyncio
import logging

logging.basicConfig(level=logging.DEBUG)


class TCPConnection(asyncio.Protocol):

    def __init__(self, loop, host, port, idle_timeout, buffer_handler):

        self.loop = loop
        self.host = host
        self.port = port
        self.idle_timeout = idle_timeout
        self.buffer_handler = buffer_handler
        self.is_open = False
        self.idle_timer = None
        self.transport = None

    def remote_addr(self):
        return (self.host, self.port)

    def handler(self):
        return self.buffer_handler

    def eof_received(self):
        self.close()

    def connection_lost(self, exc):
        self.close()

    def connection_made(self, transport):
        self.is_open = True
        self.transport = transport
        self.refresh()

    def data_received(self, data):
        self.buffer_handler.add(data)
        self.refresh()

    def open(self):
        return self.loop.create_connection(lambda: self, self.host, self.port)

    def close(self):
        if self.transport:
            if self.idle_timer:
                self.idle_timer.cancel()
            self.transport.close()
            self.transport = None
        self.is_open = False
        self.buffer_handler.flush()

    def refresh(self):
        if self.idle_timer:
            self.idle_timer.cancel()
        self.idle_timer = self.loop.call_later(self.idle_timeout, self.close)

    async def send(self, data):
        if self.is_open:
            self.refresh()
        else:
            await self.open()
        return self.transport.write(data)


if __name__ == "__main__":

    class BufferHandler:

        def __init__(self):
            self.buffer = bytearray()

        def flush(self):
            self.buffer.clear()

        def add(self, data):
            self.buffer += data
            if self.is_complete(self.buffer):
                self.buffer = self.handle(self.buffer)

        def is_complete(self, buffer):
            return buffer.find(b"\n") != -1

        def handle(self, buffer):
            packet, remains = buffer.split(b"\n", 1)
            print("handling", packet)
            return remains

    loop = asyncio.get_event_loop()

    c = TCPConnection(loop, "127.0.0.1", 8100, 5, BufferHandler())

    loop.run_until_complete(c.send(b"Howdy\n"))

    loop.run_until_complete(asyncio.sleep(30))
