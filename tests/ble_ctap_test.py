"""Full CTAP2-over-BLE test (makeCredential + getAssertion) via bleak.

The firmware exposes the FIDO GATT layout on 0xFFFD; Windows reserves that UUID
for its own FIDO stack, so a test build can map the identical layout to 0xFFF0
(compile with -DPK_BLE_ALIAS=1). This script accepts either.
"""

import asyncio
import os
import sys
import threading

from bleak import BleakClient, BleakScanner
from fido2 import cbor
from fido2.cose import ES256
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.utils import sha256

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import pkdev  # noqa: E402

PIN = "123456"
SERVICES = [
    "0000fffd-0000-1000-8000-00805f9b34fb",
    "0000fff0-0000-1000-8000-00805f9b34fb",
]
CP = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
STATUS = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
CP_LEN = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"


class FrameAssembler:
    def __init__(self):
        self.buf = bytearray()
        self.total = 0
        self.stat = None
        self.seq = 0
        self.done = asyncio.Event()

    def reset(self):
        self.buf = bytearray()
        self.total = 0
        self.stat = None
        self.seq = 0
        self.done.clear()

    def on_notify(self, _sender, data: bytearray):
        p = bytes(data)
        if not p:
            return
        if self.total == 0:
            if len(p) < 3:
                return
            self.stat = p[0]
            self.total = (p[1] << 8) | p[2]
            self.buf = bytearray(p[3:3 + self.total])
            if len(self.buf) >= self.total:
                self.done.set()
        else:
            if p[0] != self.seq:
                return
            self.seq = (self.seq + 1) & 0x7F
            self.buf += p[1:1 + max(0, self.total - len(self.buf))]
            if len(self.buf) >= self.total:
                self.done.set()


class BleCtapDevice:
    capabilities = 0x04

    def __init__(self, address):
        self.address = address
        self.loop = asyncio.new_event_loop()
        self.client = None
        self.asm = FrameAssembler()
        self.max_write = 20
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ready.wait(25)

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._connect())
        self.loop.run_forever()

    async def _find(self):
        for _ in range(3):
            devices = await BleakScanner.discover(timeout=6)
            for d in devices:
                if d.name and "TechXPassKey" in d.name:
                    return d
        raise RuntimeError("TechXPassKey not found")

    async def _connect(self):
        d = await self._find()
        self.client = BleakClient(d.address, timeout=20,
                                  winrt={"use_cached_services": False})
        await self.client.connect()
        for s in self.client.services:
            if s.uuid.lower() in SERVICES:
                print("BLE service:", s.uuid)
        self.max_write = int.from_bytes(await self.client.read_gatt_char(CP_LEN), "little")
        await self.client.start_notify(STATUS, self.asm.on_notify)
        self.ready.set()

    def _submit(self, coro, timeout=60):
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut.result(timeout)

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        cmd = int(cmd)
        # python-fido2 uses CTAPHID command values without the 0x80 bit; the
        # BLE wire format carries the full command byte.
        wire = {0x10: 0x90, 0x03: 0x83, 0x01: 0x81}.get(cmd, cmd | 0x80)
        return self._submit(self._call(wire, bytes(data)))

    async def _call(self, cmd, data):
        self.asm.reset()
        frame = bytes([cmd]) + len(data).to_bytes(2, "big") + data
        first = frame[: self.max_write]
        await self.client.write_gatt_char(CP, first, response=True)
        seq = 0
        sent = len(first)
        while sent < len(frame):
            chunk = frame[sent:sent + self.max_write - 1]
            await self.client.write_gatt_char(CP, bytes([seq]) + chunk, response=True)
            seq = (seq + 1) & 0x7F
            sent += len(chunk)
        await asyncio.wait_for(self.asm.done.wait(), timeout=60)
        stat, payload = self.asm.stat, bytes(self.asm.buf)
        if stat == 0xBF:
            raise RuntimeError(f"BLE transport error: {payload.hex()}")
        # payload starts with the CTAP status byte for CBOR, or is the raw U2F
        # response (with SW) for MSG.
        return payload

    def close(self):
        try:
            self._submit(self.client.disconnect(), timeout=5)
        except Exception:
            pass


def parse_auth_data(auth_data):
    flags = auth_data[32]
    counter = int.from_bytes(auth_data[33:37], "big")
    rest = auth_data[37:]
    cred_id = None
    cose = None
    if flags & 0x40:
        cred_len = int.from_bytes(rest[16:18], "big")
        cred_id = rest[18:18 + cred_len]
        cose = cbor.decode(rest[18 + cred_len:])
    return flags, counter, cred_id, cose


def main():
    usb = pkdev.find_device()
    usb.set_up_mode(True)
    usb.close()

    dev = BleCtapDevice("")
    print("BLE connected, max write", dev.max_write)
    ctap = Ctap2(dev)
    print("versions:", ctap.info.versions)
    print("options:", ctap.info.options)

    pin = ClientPin(ctap, PinProtocolV2())
    rp_id = "ble.example"
    cdh = sha256(os.urandom(32))
    token = pin.get_pin_token(
        PIN,
        permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION,
        permissions_rpid=rp_id,
    )
    print("makeCredential over BLE ...")
    att = ctap.make_credential(
        cdh,
        {"id": rp_id, "name": "BLE Test"},
        {"id": b"ble-user", "name": "carol", "displayName": "Carol"},
        [{"type": "public-key", "alg": -7}],
        options={"rk": True},
        pin_uv_param=pin.protocol.authenticate(token, cdh),
        pin_uv_protocol=pin.protocol.VERSION,
    )
    flags, counter, cred_id, cose = parse_auth_data(att.auth_data)
    print("  flags", hex(flags), "cred", cred_id.hex())
    ES256(cose).verify(att.auth_data + cdh, att.att_stmt["sig"])
    print("  attestation signature OK")

    print("getAssertion over BLE ...")
    cdh2 = sha256(os.urandom(32))
    token2 = pin.get_pin_token(PIN, permissions=ClientPin.PERMISSION.GET_ASSERTION,
                               permissions_rpid=rp_id)
    res = ctap.get_assertion(
        rp_id, cdh2,
        allow_list=[{"type": "public-key", "id": cred_id}],
        pin_uv_param=pin.protocol.authenticate(token2, cdh2),
        pin_uv_protocol=pin.protocol.VERSION,
    )
    ES256(cose).verify(res.auth_data + cdh2, res.signature)
    print("  assertion signature OK, counter", res.auth_data[33:37].hex())
    print("BLE CTAP OK")
    dev.close()

    usb = pkdev.find_device()
    usb.set_up_mode(False)
    usb.close()


if __name__ == "__main__":
    main()
