"""BLE transport test: connect over GATT and run CTAP2 getInfo."""

import asyncio
import sys

from bleak import BleakClient, BleakScanner
from fido2 import cbor

SERVICE = "0000fffd-0000-1000-8000-00805f9b34fb"
CP = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
STATUS = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
CP_LEN = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"


class BleLink:
    def __init__(self):
        self.buf = b""
        self.total = 0
        self.expect = None
        self.done = asyncio.Event()
        self.stat = None
        self.data = b""

    def on_notify(self, _sender, payload: bytearray):
        p = bytes(payload)
        if not p:
            return
        if p[0] & 0x80 or (self.total == 0 and self.stat is None):
            # initialization fragment (status byte high bit may be clear; the
            # first notification after a request always starts a frame)
            if len(p) < 3:
                return
            self.stat = p[0]
            self.total = (p[1] << 8) | p[2]
            body = p[3:]
            self.buf = body[: self.total]
            if len(self.buf) >= self.total:
                self.done.set()
        else:
            if not self.buf and self.total == 0:
                return
            body = p[1:]
            self.buf += body[: max(0, self.total - len(self.buf))]
            if len(self.buf) >= self.total:
                self.done.set()


async def find_device(timeout=10):
    devices = await BleakScanner.discover(timeout=timeout)
    for d in devices:
        if d.name and "TechXPassKey" in d.name:
            return d
    raise SystemExit("TechXPassKey not found")


async def main():
    dev = await find_device()
    print("device:", dev.address, dev.name)
    async with BleakClient(dev.address, timeout=20) as client:
        print("connected:", client.is_connected)
        services = client.services
        for s in services:
            if s.uuid.lower() == SERVICE:
                print("service found:", s.uuid)
        cp_len = await client.read_gatt_char(CP_LEN)
        max_write = int.from_bytes(cp_len, "little")
        print("control point length:", max_write)

        link = BleLink()
        await client.start_notify(STATUS, link.on_notify)

        async def call(cmd: int, data: bytes = b""):
            link.buf = b""
            link.total = 0
            link.stat = None
            link.done.clear()
            frame = bytes([cmd]) + len(data).to_bytes(2, "big") + data
            first = frame[:max_write]
            await client.write_gatt_char(CP, first, response=True)
            seq = 0
            sent = len(first)
            while sent < len(frame):
                chunk = frame[sent:sent + max_write - 1]
                await client.write_gatt_char(CP, bytes([seq]) + chunk, response=True)
                seq = (seq + 1) & 0x7F
                sent += len(chunk)
            await asyncio.wait_for(link.done.wait(), timeout=30)
            return link.stat, link.buf

        stat, payload = await call(0x90, bytes([0x04]))
        print("status:", hex(stat) if stat is not None else None, "len", len(payload))
        print("ctap status:", hex(payload[0]))
        info = cbor.decode(payload[1:])
        print("versions:", info[1])
        print("aaguid:", info[3].hex())
        print("options:", info[4])
        print("protocols:", info[6])
        print("BLE GETINFO OK")


if __name__ == "__main__":
    asyncio.run(main())
