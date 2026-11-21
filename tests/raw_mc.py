"""Reproduce a Windows-style makeCredential and dissect the authData."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import pkdev
from ctap_test import CdcCtapDevice
from fido2 import cbor
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.utils import sha256

PIN = "123456"


def main():
    dev = pkdev.find_device()
    dev.set_up_mode(True)
    ctap = Ctap2(CdcCtapDevice(dev))
    pin = ClientPin(ctap, PinProtocolV2())
    rp_id = "ext.example"
    cdh = sha256(os.urandom(32))
    token = pin.get_pin_token(
        PIN,
        permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
        permissions_rpid=rp_id,
    )
    req = {
        1: cdh,
        2: {"id": rp_id, "name": "Ext Test"},
        3: {"id": b"ext-user", "name": "eve", "displayName": "Eve"},
        4: [{"type": "public-key", "alg": -7}],
        6: {"credProtect": 2},
        7: {"rk": True, "uv": True},
        8: pin.protocol.authenticate(token, cdh),
        9: pin.protocol.VERSION,
    }
    raw = bytes([0x01]) + cbor.encode(req)
    status, payload = dev.ctap(raw, timeout=30)
    print("status", status, "len", len(payload))
    obj = cbor.decode(payload)
    print("fmt", obj[1], "keys", list(obj))
    auth = obj[2]
    print("authData len", len(auth), "flags", hex(auth[32]))
    print("counter", int.from_bytes(auth[33:37], "big"))
    cred_len = int.from_bytes(auth[53:55], "big")
    print("credIdLen", cred_len, "credId", auth[55:55 + cred_len].hex())
    cose_start = 55 + cred_len
    key = cbor.decode(auth[cose_start:])
    print("cose", key)
    enc = cbor.encode(key)
    print("cose encoded len", len(enc), "leftover after cose:", len(auth) - cose_start - len(enc))
    if len(auth) > cose_start + len(enc):
        print("leftover bytes:", auth[cose_start + len(enc):].hex())
        print("decoded leftover:", cbor.decode(auth[cose_start + len(enc):]))
    whole = cbor.encode(obj)
    print("payload len", len(payload), "reencoded len", len(whole))
    if len(payload) > len(whole):
        print("TRAILING:", payload[len(whole):].hex())
    print("raw response:", payload.hex())
    dev.set_up_mode(False)
    dev.close()


if __name__ == "__main__":
    main()
