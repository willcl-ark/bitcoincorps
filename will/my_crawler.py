import hashlib
import chainparams
import time
import struct

from requests import get


LOCAL_WAN_IP = get('https://api.ipify.org').text
PEER_IP = "77.98.116.8"
PEER_PORT = 8333

# Almost all integers are encoded in little endian. Only IP or port number are encoded big endian.


class Serializable:

    @staticmethod
    def _to_bytes(msg, length=None, byteorder='little'):
        if isinstance(msg, int):    # or isinstance(msg, bool):
            if length == None:
                length = msg.bit_length()
            return msg.to_bytes(length, byteorder)
        elif isinstance(msg, str):
            return msg.encode(encoding='UTF-8', errors='strict')
        elif isinstance(msg, bytes):
            return msg
        else:
            return print("message of type %s not supported by to_bytes()" % type(msg))

    @staticmethod
    def pad_msg_end(msg, length):
        len_diff = length - len(msg)
        msg += b"\x00" * len_diff
        return msg


class Message(Serializable):

    def __init__(self, command, payload):
        self.magic = chainparams.mainParams.StartString.to_bytes(4, byteorder='little')
        self.command = command
        self.command_bytes = None
        self.length = len(payload).to_bytes(length=4, byteorder='little')
        self.payload = payload
        self.checksum = None
        self.header = None

    def serialize_payload(self):
        if not isinstance(self.payload, bytes):
            self.payload = Serializable._to_bytes(self.payload)
            self.length = len(self.payload).to_bytes(length=4, byteorder='little')
            self.checksum = hashlib.sha256(hashlib.sha256(self.payload).digest()).digest()[:4]

    def generate_header(self):
        self.serialize_payload()
        self.command_bytes = Serializable.pad_msg_end(Serializable._to_bytes(self.command), 12)
        self.length = Serializable.pad_msg_end(Serializable._to_bytes(self.length), 4)
        self.checksum = hashlib.sha256(hashlib.sha256(self.payload).digest()).digest()[:4]

        self.header = b''.join([self.magic, self.command_bytes, self.length, self.checksum])
        return self.header

    def to_bytes(self):
        self.generate_header()
        msg = b''.join([self.header, self.payload])
        return msg

    @staticmethod
    def to_var_int(x):
        if x < 0xfd:
            return Serializable._to_bytes(x, length=1)
        elif x <= 0x10000:
            return b"\xfd" + Serializable._to_bytes(x, length=3)
        elif x <= 0x100000000:
            return b"\xfe" + Serializable._to_bytes(x, length=5)
        elif x <= 0x10000000000000000:
            return b"\xff" + Serializable._to_bytes(x, length=9)
        else:
            raise RuntimeError("integer too large for type<var_int>")

    @staticmethod
    def to_var_str(x):
        s = Serializable._to_bytes(x)
        l = len(s)
        return Message.to_var_int(l) + s

    @staticmethod
    def generate_network_address(ip, port):
        t = struct.pack(b"<q", int(time.time()))
        print(t)
        s = Serializable._to_bytes('services')
        print(s)
        p = Serializable._to_bytes(port, byteorder='big')
        print(p)

        if ':' in ip:
            addr = bytes(map(int, ip.split(':')))
        else:
            addr = (b"\x00" * 10) + (b"\xFF" * 2)
            addr_bytes = bytes(map(int, ip.split('.')))
            addr += addr_bytes

        print(addr)

        return b"".join([t, s, addr, p])









"""
class VersionMessage(Message):
    command = b"version"

    def __init__(
            self,
            version,
            services,
            time,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
    ):
        self.version = version
        self.services = services
        self.time = time
        self.addr_recv = addr_recv
        self.addr_from = addr_from
        self.nonce = nonce
        self.user_agent = user_agent
        self.start_height = start_height
        self.relay = relay
"""