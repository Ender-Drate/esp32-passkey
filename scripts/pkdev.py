"""pkdev - ESP32 Passkey management-protocol client.

Used by the desktop app, the flash helper and the test suite.

Frame: A5 5A | ver(1) | cmd(1) | seq(1) | len(2 LE) | payload | crc16(2 LE)
"""

from __future__ import annotations

import json
import os
import struct
import sys
import time
import zlib

try:
    import serial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover
    serial = None
    list_ports = None

SOF = b"\xa5\x5a"
VER = 1

CMD_PING = 0x01
CMD_INFO = 0x02
CMD_LOG = 0x03
CMD_SET_TIME = 0x10
CMD_SET_UP_MODE = 0x11
CMD_GET_TIME = 0x12
CMD_DEVICE_ID = 0x13
CMD_OTA_BEGIN = 0x20
CMD_OTA_DATA = 0x21
CMD_OTA_END = 0x22
CMD_REBOOT = 0x30
CMD_BOOTLOADER = 0x31
CMD_FACTORY_RESET = 0x32
CMD_REPLACE_KEY = 0x33
CMD_REPLACE_CANCEL = 0x34
CMD_CLEAR_KEYBOARD = 0x35
CMD_LIST_CREDS = 0x40
CMD_DELETE_CRED = 0x41
CMD_DELETE_ALL = 0x42

CMD_CTAP = 0x50
CMD_U2F = 0x51

ST_OK = 0
ST_ERROR = 1
ST_BAD_FRAME = 2
ST_AUTH = 3
ST_LOCKED = 6
ST_BUSY = 4
ST_NOTSUP = 5

ESP_VIDS = {0x303A, 0x1A86, 0x10C4}


def crc16(data: bytes, crc: int = 0xFFFF) -> int:
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


class PasskeyError(Exception):
    pass


class CtapCdc:
    """python-fido2 CtapDevice shim backed by the CDC CTAP bridge."""

    capabilities = 0x04 | 0x08  # CBOR + NMSG

    def __init__(self, dev: "Device"):
        self.dev = dev

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        cmd = int(cmd)
        if cmd == 0x10:  # CTAPHID.CBOR
            status, payload = self.dev.ctap(bytes(data), timeout=120)
            return bytes([status]) + payload
        if cmd == 0x03:  # CTAPHID.MSG (U2F)
            return self.dev.u2f(bytes(data), timeout=60)
        raise ValueError(f"unsupported CTAPHID command {cmd:#x}")


class Device:
    def __init__(self, port: str, baud: int = 115200, timeout: float = 0.2):
        if serial is None:
            raise PasskeyError("pyserial is not installed")
        self.port = port
        self.ser = serial.Serial(port, baud, timeout=timeout, write_timeout=2)
        self.ser.reset_input_buffer()
        self._buf = b""

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _read_frame(self, deadline: float):
        while time.time() < deadline:
            chunk = self.ser.read(256)
            if not chunk:
                continue
            self._buf += chunk
            while True:
                i = self._buf.find(SOF)
                if i < 0:
                    self._buf = b""
                    break
                self._buf = self._buf[i:]
                if len(self._buf) < 2 + 5:
                    break
                ver, cmd, _seq, ln = struct.unpack("<BBBH", self._buf[2:7])
                total = 2 + 5 + ln + 2
                if len(self._buf) < total:
                    break
                payload = self._buf[7:7 + ln]
                crc = struct.unpack("<H", self._buf[7 + ln:total])[0]
                frame = self._buf[2:7 + ln]
                self._buf = self._buf[total:]
                if ver == VER and crc16(frame) == crc:
                    return cmd, payload
        return None

    def xfer(self, cmd: int, payload: bytes = b"", timeout: float = 5.0):
        hdr = struct.pack("<BBBH", VER, cmd, 0, len(payload))
        crc = crc16(hdr + payload)
        self.ser.write(SOF + hdr + payload + struct.pack("<H", crc))
        self.ser.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            got = self._read_frame(deadline)
            if got is None:
                break
            rcmd, rpayload = got
            if rcmd == (cmd | 0x80):
                if not rpayload:
                    raise PasskeyError("empty response")
                return rpayload[0], rpayload[1:]
        raise PasskeyError(f"timeout waiting for response to 0x{cmd:02x}")

    # -- commands ------------------------------------------------------------
    def ping(self, data: bytes = b"ping", timeout: float = 1.0) -> bytes:
        st, payload = self.xfer(CMD_PING, data, timeout)
        if st != ST_OK:
            raise PasskeyError(f"ping status {st}")
        return payload

    def info(self, timeout: float = 2.0) -> dict:
        st, payload = self.xfer(CMD_INFO, timeout=timeout)
        if st != ST_OK:
            raise PasskeyError(f"info status {st}")
        return json.loads(payload.decode("utf-8"))

    def logs(self) -> str:
        st, payload = self.xfer(CMD_LOG)
        return payload.decode("utf-8", "replace")

    def set_time(self, epoch: int | None = None):
        if epoch is None:
            epoch = int(time.time())
        st, _ = self.xfer(CMD_SET_TIME, struct.pack("<Q", epoch))
        if st != ST_OK:
            raise PasskeyError("set_time failed")

    def set_up_mode(self, auto: bool):
        st, _ = self.xfer(CMD_SET_UP_MODE, bytes([1 if auto else 0]))
        if st != ST_OK:
            raise PasskeyError("set_up_mode failed")

    def list_credentials(self) -> list[dict]:
        st, payload = self.xfer(CMD_LIST_CREDS, timeout=10)
        if st == ST_LOCKED:
            raise PasskeyError("副板未连接，无法读取 Passkeys")
        if st != ST_OK:
            raise PasskeyError(f"list status {st}")
        return json.loads(payload.decode("utf-8"))

    def delete_credential(self, cred_id: bytes, pin: str = ""):
        p = pin.encode("utf-8")
        st, _ = self.xfer(CMD_DELETE_CRED, bytes([len(p)]) + p + cred_id)
        if st == ST_LOCKED:
            raise PasskeyError("副板未连接，无法删除 Passkeys")
        if st == ST_AUTH:
            raise PasskeyError("wrong PIN")
        if st != ST_OK:
            raise PasskeyError("delete failed")

    def delete_all(self, pin: str = ""):
        p = pin.encode("utf-8")
        st, _ = self.xfer(CMD_DELETE_ALL, bytes([len(p)]) + p)
        if st == ST_LOCKED:
            raise PasskeyError("副板未连接，无法删除 Passkeys")
        if st == ST_AUTH:
            raise PasskeyError("wrong PIN")
        if st != ST_OK:
            raise PasskeyError("delete all failed")

    def factory_reset(self, pin: str = ""):
        p = pin.encode("utf-8")
        st, _ = self.xfer(CMD_FACTORY_RESET, bytes([len(p)]) + p)
        if st == ST_AUTH:
            raise PasskeyError("wrong PIN")
        if st != ST_OK:
            raise PasskeyError("factory reset failed")

    def replace_keyboard(self, cancel: bool = False):
        cmd = CMD_REPLACE_CANCEL if cancel else CMD_REPLACE_KEY
        st, _ = self.xfer(cmd)
        if st == ST_AUTH:
            raise PasskeyError("请先接好并验证旧副板")
        if st != ST_OK:
            raise PasskeyError("replace key board failed")

    def clear_keyboard(self, pin: str = "", wipe: bool = False):
        p = pin.encode("utf-8")
        st, _ = self.xfer(CMD_CLEAR_KEYBOARD, bytes([1 if wipe else 0, len(p)]) + p, timeout=10)
        if st == ST_LOCKED:
            raise PasskeyError("副板未连接，无法清除")
        if st == ST_AUTH:
            raise PasskeyError("PIN 错误，或设备未设置 PIN")
        if st != ST_OK:
            raise PasskeyError("clear keyboard failed")

    def reboot(self):
        try:
            self.xfer(CMD_REBOOT, timeout=1)
        except PasskeyError:
            pass

    def bootloader(self):
        try:
            self.xfer(CMD_BOOTLOADER, timeout=1)
        except PasskeyError:
            pass

    def ctap(self, request: bytes, timeout: float = 60.0):
        """Raw CTAP2 request (command byte + CBOR) over the CDC bridge."""
        return self.xfer(CMD_CTAP, request, timeout=timeout)

    def u2f(self, apdu: bytes, timeout: float = 30.0) -> bytes:
        st, payload = self.xfer(CMD_U2F, apdu, timeout=timeout)
        return payload

    def ota(self, path: str, chunk: int = 1024, progress=None):
        data = open(path, "rb").read()
        size = len(data)
        crc = zlib.crc32(data) & 0xFFFFFFFF
        st, _ = self.xfer(CMD_OTA_BEGIN, struct.pack("<II", size, crc), timeout=5)
        if st != ST_OK:
            raise PasskeyError("OTA begin rejected")
        for off in range(0, size, chunk):
            piece = data[off:off + chunk]
            st, _ = self.xfer(CMD_OTA_DATA, struct.pack("<I", off) + piece, timeout=5)
            if st != ST_OK:
                raise PasskeyError(f"OTA data failed at {off}")
            if progress:
                progress(off + len(piece), size)
        st, _ = self.xfer(CMD_OTA_END, timeout=10)
        if st != ST_OK:
            raise PasskeyError("OTA finalize failed")


def esp_ports():
    out = []
    if list_ports is None:
        return out
    for p in list_ports.comports():
        vid = p.vid or 0
        if vid in ESP_VIDS or "303A" in (p.hwid or "").upper() or "1A86" in (p.hwid or "").upper():
            out.append(p.device)
    return out


def find_device(ports=None, timeout: float = 3.0) -> Device:
    if ports is None:
        ports = esp_ports() or [p.device for p in list_ports.comports()]
    last = None
    for port in ports:
        dev = None
        try:
            dev = Device(port, timeout=0.05)
            info = dev.info(timeout=timeout)
            if info.get("name"):
                found = dev
                dev = None  # hand ownership to the caller
                return found
        except Exception as e:  # noqa: BLE001
            last = e
        finally:
            # Never leak a handle on a port that did not answer: a leaked
            # serial handle keeps CH343 (COM8) busy and blocks flashing.
            if dev is not None:
                dev.close()
    raise PasskeyError(f"no passkey device found ({last})")


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: pkdev.py info|creds|logs|up-mode <auto|button>|"
              "set-time|ota <firmware.bin>|delete <b64id> [pin]|reset [pin]|bootloader|"
              "replace-key|cancel-replace")
        return 0
    cmd = argv[0]
    if cmd == "ports":
        for p in esp_ports():
            print(p)
        return 0
    dev = find_device()
    print(f"device: {dev.port}")
    try:
        if cmd == "info":
            print(json.dumps(dev.info(), indent=2))
        elif cmd == "creds":
            creds = dev.list_credentials()
            for c in creds:
                print(f"{c['rpId']:<32} {c.get('userName') or c.get('displayName') or '-'}")
            print(f"{len(creds)} credential(s)")
        elif cmd == "logs":
            print(dev.logs())
        elif cmd == "set-time":
            dev.set_time()
            print("time synced")
        elif cmd == "up-mode":
            auto = len(argv) > 1 and argv[1] == "auto"
            dev.set_up_mode(auto)
            print("user-presence mode:", "auto" if auto else "button")
        elif cmd == "ota":
            if len(argv) < 2:
                raise SystemExit("ota needs a firmware path")

            def prog(done, total):
                print(f"\r{done * 100 // total:3d}%", end="", flush=True)

            dev.ota(argv[1], progress=prog)
            print("\nOTA done, device rebooting")
        elif cmd == "delete":
            from base64 import urlsafe_b64decode
            cid = urlsafe_b64decode(argv[1] + "=" * (-len(argv[1]) % 4))
            pin = argv[2] if len(argv) > 2 else ""
            dev.delete_credential(cid, pin)
            print("deleted")
        elif cmd == "reset":
            dev.factory_reset(argv[1] if len(argv) > 1 else "")
            print("factory reset done")
        elif cmd == "replace-key":
            dev.replace_keyboard()
            print("replace mode started")
        elif cmd == "cancel-replace":
            dev.replace_keyboard(cancel=True)
            print("replace cancelled")
        elif cmd == "bootloader":
            dev.bootloader()
            print("rebooting to ROM bootloader")
        else:
            print("unknown command")
            return 2
    finally:
        dev.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
