"""End-to-end CTAP2 test against the ESP32 Passkey over the CDC bridge.

Windows' fidohid.sys reserves the FIDO HID interface for the platform FIDO
service, so raw HID access from a normal process is denied.  The firmware
exposes the same CTAP dispatcher over the CDC management channel; this test
drives that path, which exercises exactly the same command handlers.

Run:  python tests/ctap_test.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from fido2 import cbor
from fido2.cose import ES256
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.utils import sha256

import pkdev


class CdcCtapDevice:
    """Minimal CtapDevice shim backed by the CDC CTAP bridge."""

    capabilities = 0x04  # CBOR

    def __init__(self, dev):
        self.dev = dev

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        cmd = int(cmd)
        if cmd == 0x10:  # CTAPHID.CBOR
            status, payload = self.dev.ctap(bytes(data), timeout=120)
            return bytes([status]) + payload
        if cmd == 0x03:  # CTAPHID.MSG (U2F APDU)
            return self.dev.u2f(bytes(data), timeout=60)
        raise ValueError(f"unsupported CTAPHID command {cmd:#x}")


def parse_auth_data(auth_data: bytes):
    rp_hash = auth_data[:32]
    flags = auth_data[32]
    counter = int.from_bytes(auth_data[33:37], "big")
    rest = auth_data[37:]
    cred_id = None
    cose_key = None
    if flags & 0x40:
        cred_len = int.from_bytes(rest[16:18], "big")
        cred_id = rest[18:18 + cred_len]
        cose_key = cbor.decode(rest[18 + cred_len:])
    return rp_hash, flags, counter, cred_id, cose_key


def main():
    dev = pkdev.find_device()
    print("device:", dev.port)
    ctap = Ctap2(CdcCtapDevice(dev))
    info = ctap.info
    print("versions      :", info.versions)
    print("extensions    :", info.extensions)
    print("options       :", info.options)
    print("max_msg_size  :", info.max_msg_size)
    print("pin protocols :", info.pin_uv_protocols)
    print("remaining     :", info.remaining_disc_creds)

    pin = ClientPin(ctap, PinProtocolV2())
    if not info.options.get("clientPin"):
        print("setting PIN to 1234 ...")
        pin.set_pin("1234")

    rp_id = "test.example"
    user = {"id": b"user-1", "name": "alice", "displayName": "Alice"}
    cdh = sha256(os.urandom(32))
    token = pin.get_pin_token(
        "1234",
        permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION,
        permissions_rpid=rp_id,
    )

    print("makeCredential ...")
    att = ctap.make_credential(
        cdh,
        {"id": rp_id, "name": "Test RP"},
        user,
        [{"type": "public-key", "alg": -7}],
        options={"rk": True},
        pin_uv_param=pin.protocol.authenticate(token, cdh),
        pin_uv_protocol=pin.protocol.VERSION,
    )
    print("  fmt:", att.fmt, "attStmt:", list(att.att_stmt))
    rp_hash, flags, counter, cred_id, cose_key = parse_auth_data(att.auth_data)
    assert flags & 0x01, "UP flag missing"
    assert flags & 0x04, "UV flag missing"
    assert cred_id, "no credential id"
    print("  cred id:", cred_id.hex(), "counter:", counter)

    key = ES256(cose_key)
    key.verify(att.auth_data + cdh, att.att_stmt["sig"])
    print("  attestation signature OK")

    print("getAssertion ...")
    cdh2 = sha256(os.urandom(32))
    token2 = pin.get_pin_token(
        "1234",
        permissions=ClientPin.PERMISSION.GET_ASSERTION,
        permissions_rpid=rp_id,
    )
    res = ctap.get_assertion(
        rp_id,
        cdh2,
        allow_list=[{"type": "public-key", "id": cred_id}],
        pin_uv_param=pin.protocol.authenticate(token2, cdh2),
        pin_uv_protocol=pin.protocol.VERSION,
    )
    print("  assertions:", res.number_of_credentials)
    ar = res
    _, flags2, counter2, _, _ = parse_auth_data(ar.auth_data)
    ar.verify(cdh2, key)
    assert flags2 & 0x01, "UP flag missing on assertion"
    print("  assertion signature OK, counter:", counter2)
    print("  user:", ar.user)
    print("remaining after registration:", ctap.info.remaining_disc_creds)
    print("ALL OK")


if __name__ == "__main__":
    main()
