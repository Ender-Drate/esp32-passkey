"""Exercise CTAP1/U2F, credential management and large blobs over CDC."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import pkdev
from ctap_test import CdcCtapDevice
from fido2 import cbor
from fido2.ctap1 import Ctap1
from fido2.ctap2 import Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.utils import sha256

PIN = "123456"


class Shim(CdcCtapDevice):
    capabilities = 0x04 | 0x08  # CBOR + NMSG


def main():
    dev = pkdev.find_device()
    dev.set_up_mode(True)
    ctap = Ctap2(Shim(dev))
    pin = ClientPin(ctap, PinProtocolV2())
    token = pin.get_pin_token(
        PIN,
        permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT | ClientPin.PERMISSION.LARGE_BLOB_WRITE,
    )

    print("== U2F ==")
    u2f = Ctap1(Shim(dev))
    client_param = sha256(b"u2f-challenge")
    app_param = sha256(b"https://u2f.example")
    reg = u2f.register(client_param, app_param)
    reg.verify(app_param, client_param)
    print("  register signature OK, key handle", len(reg.key_handle), "bytes")
    sig = u2f.authenticate(client_param, app_param, reg.key_handle)
    sig.verify(app_param, client_param, reg.public_key)
    print("  authenticate signature OK, counter", sig.counter)

    print("== credential management ==")
    cm = CredentialManagement(ctap, pin.protocol, token)
    meta = cm.get_metadata()
    print("  metadata:", meta)
    rps = cm.enumerate_rps()
    print("  RPs:", len(rps))
    total_creds = 0
    for rp in rps:
        creds = cm.enumerate_creds(rp[4])
        total_creds += len(creds)
        print(f"    {rp[3]['id']}: {len(creds)} credential(s)")
    print("  total credentials:", total_creds)
    if total_creds > 0:
        first = cm.enumerate_creds(rps[0][4])[0]
        cid = first[7]["id"]
        cm.delete_cred({"type": "public-key", "id": cid})
        print("  deleted one credential")
        meta2 = cm.get_metadata()
        print("  metadata after delete:", meta2)
        assert meta2[1] == meta[1] - 1

    print("== large blobs ==")
    blob = LargeBlobs(ctap, pin.protocol, token)
    arr = blob.read_blob_array()
    print("  initial array:", arr)
    payload = [{1: b"\x11" * 32, 2: b"hello large blob", 3: 0}]
    blob.write_blob_array(payload)
    back = blob.read_blob_array()
    assert back == payload, (back, payload)
    print("  wrote and read back:", back)
    dev.set_up_mode(False)
    dev.close()
    print("PROTOCOLS OK")


if __name__ == "__main__":
    main()
