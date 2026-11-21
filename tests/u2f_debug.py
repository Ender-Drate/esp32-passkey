"""Debug U2F registration signature against the embedded attestation cert."""

import hashlib
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import pkdev
from fido2.ctap1 import Ctap1, APDU
from fido2.ctap1 import RegistrationData
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def main():
    dev = pkdev.find_device()
    dev.set_up_mode(True)
    client_param = hashlib.sha256(b"u2f-challenge").digest()
    app_param = hashlib.sha256(b"https://u2f.example").digest()
    apdu = bytes([0x00, 0x01, 0x00, 0x00, 0x40]) + client_param + app_param
    raw = dev.u2f(apdu)
    print("raw len", len(raw), "sw", raw[-2:].hex())
    reg = RegistrationData(raw[:-2])
    print("pub", len(reg.public_key), "kh", len(reg.key_handle), "cert", len(reg.certificate), "sig", len(reg.signature))
    cert = x509.load_der_x509_certificate(reg.certificate)
    m = b"\0" + app_param + client_param + reg.key_handle + reg.public_key
    print("m len", len(m), "sha", hashlib.sha256(m).hexdigest())

    # header key
    src = open(os.path.join(os.path.dirname(__file__), "..", "projects", "passkey", "src", "pk_u2f_cert.h"),
               encoding="utf-8").read()
    m2 = re.search(r"U2F_ATTEST_PRIV\[[^\]]*\]\s*=\s*\{(.*?)\}", src, re.S)
    priv = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m2.group(1)))
    hdr_key = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256R1())
    print("cert == header key:", hdr_key.public_key().public_numbers() == cert.public_key().public_numbers())
    m3 = re.search(r"U2F_ATTEST_CERT\[[^\]]*\]\s*=\s*\{(.*?)\}", src, re.S)
    hdr_cert = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m3.group(1)))
    print("response cert == header cert:", hdr_cert == reg.certificate)
    print("signature vs credential key:",
          end=" ")
    cred_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), reg.public_key)
    try:
        cred_key.verify(reg.signature, m, ec.ECDSA(hashes.SHA256()))
        print("VERIFIES (wrong key used!)")
    except Exception:
        print("no")

    for label, msg in {
        "app,client": b"\0" + app_param + client_param + reg.key_handle + reg.public_key,
        "client,app": b"\0" + client_param + app_param + reg.key_handle + reg.public_key,
        "no-reserved": app_param + client_param + reg.key_handle + reg.public_key,
    }.items():
        try:
            cert.public_key().verify(reg.signature, msg, ec.ECDSA(hashes.SHA256()))
            print(label, "VERIFY OK")
        except Exception as e:
            print(label, "fail", type(e).__name__)
    print("sig der", reg.signature.hex())
    dev.set_up_mode(False)
    dev.close()


if __name__ == "__main__":
    main()
