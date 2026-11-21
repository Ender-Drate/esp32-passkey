"""Set a PIN on the device and check that credentials + PIN survive a reboot."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import pkdev
from ctap_test import CdcCtapDevice, parse_auth_data
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.utils import sha256

PIN = "123456"


def open_ctap():
    dev = pkdev.find_device()
    return dev, Ctap2(CdcCtapDevice(dev))


def main():
    dev, ctap = open_ctap()
    dev.set_up_mode(True)  # auto user presence for unattended tests
    pin = ClientPin(ctap, PinProtocolV2())
    if not ctap.info.options.get("clientPin"):
        print("setting PIN ...")
        pin.set_pin(PIN)
    print("clientPin:", ctap.info.options.get("clientPin"))

    rp_id = "persist.example"
    cdh = sha256(os.urandom(32))
    token = pin.get_pin_token(
        PIN,
        permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION,
        permissions_rpid=rp_id,
    )
    att = ctap.make_credential(
        cdh,
        {"id": rp_id, "name": "Persist Test"},
        {"id": b"persist-user", "name": "bob", "displayName": "Bob"},
        [{"type": "public-key", "alg": -7}],
        options={"rk": True},
        pin_uv_param=pin.protocol.authenticate(token, cdh),
        pin_uv_protocol=pin.protocol.VERSION,
    )
    cred_id = parse_auth_data(att.auth_data)[3]
    print("created credential:", cred_id.hex())
    print("creds on device:", len(dev.list_credentials()))

    print("rebooting device ...")
    dev.reboot()
    dev.close()
    time.sleep(6)

    dev2, ctap2_ = open_ctap()
    print("after reboot: clientPin =", ctap2_.info.options.get("clientPin"))
    creds = dev2.list_credentials()
    print("after reboot: creds =", len(creds))
    assert ctap2_.info.options.get("clientPin"), "PIN did not persist"
    assert len(creds) >= 1, "credential did not persist"
    dev2.set_up_mode(False)
    dev2.close()
    print("PERSISTENCE OK")


if __name__ == "__main__":
    main()
