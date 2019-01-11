import hashlib
import struct
import time
import random

from requests import get

import chainparams

LOCAL_WAN_IP = get('https://api.ipify.org').text
LOCAL_PORT = 8333
PEER_IP = "77.98.116.8"
PEER_PORT = 8333


# Almost all integers are encoded in little endian. Only IP or port number are encoded big endian.
# And magic bytes looks like!


class Serializable:

    # Base class for Serializing objects. To be expanded to streams + ... in future

    @staticmethod
    def _serialize(msg, length=0, byteorder='little'):
        if isinstance(msg, bytes):
            return msg
        elif isinstance(msg, int):  # or isinstance(msg, bool):
            if length == 0:
                length = msg.bit_length()
            return msg.to_bytes(length, byteorder)
        elif isinstance(msg, str):
            return msg.encode(encoding='UTF-8', errors='strict')
        # TODO: add float support?
        else:
            return print("message of type %s not supported by _serialize()" % type(msg))


class Message(Serializable):

    # Base Message class which can serialize payloads and generate headers

    def __init__(self, command, payload):
        self.magic = struct.pack('>I', chainparams.mainParams.StartString)
        self.command = command
        self.command_bytes = None
        self.length = struct.pack('<I', len(payload))
        self.payload = payload
        self.checksum = None
        self.header = None
        self.generate_header()

    def serialize_payload(self):
        if not isinstance(self.payload, bytes):
            self.payload = super()._serialize(self.payload)
        self.length = struct.pack('<I', len(self.payload))

        double_hash = hashlib.sha256(hashlib.sha256(self.payload).digest()).digest()
        self.checksum = struct.pack('<4s', double_hash[:4])

    def generate_header(self):
        self.serialize_payload()

        # serialize and pack command message
        b = super()._serialize(self.command)
        self.command_bytes = struct.pack('<12s', b)

        # Create the whole header
        self.header = b"".join([self.magic, self.command_bytes, self.length, self.checksum])

    def to_bytes(self):
        self.generate_header()
        msg = b"".join([self.header, self.payload])
        return msg

    @staticmethod
    def to_var_int(x):
        if x < 0xFD:
            # pack as uint8_t
            return struct.pack('<B', x)
        elif x <= 0xFFFF:
            # pack as uint16_t
            return b"\xFD" + struct.pack('<H', x)
        elif x <= 0xFFFFFFFF:
            # pack as uint32_t
            return b"\xFE" + struct.pack('<I', x)
        elif x <= 0xFFFFFFFFFFFFFFFF:
            # pack as uint64_t
            return b"\xFF" + struct.pack('<Q', x)
        else:
            raise RuntimeError("integer too large for type<var_int>")

    @staticmethod
    def to_var_str(x):
        s = Serializable._serialize(x)
        l = len(s)
        ss = struct.pack('<%ss' % l, s)
        return Message.to_var_int(l) + ss


class NetworkAddress(Serializable):

    def __init__(self, ip, services=1, port=8333):
        self.time = struct.pack(b"<I", int(time.time()))
        self.services = struct.pack('<Q', services)

        if ':' in ip:
            self.ip = bytes(map(int, ip.split(':')))
        else:
            a = (b"\x00" * 10) + (b"\xFF" * 2)
            a_bytes = bytes(map(int, ip.split('.')))
            a += a_bytes
            self.ip = struct.pack('>16s', a)

        self.port = struct.pack('>H', port)
        self.address = b"".join([self.time, self.services, self.ip, self.port])
        self.addr_NT = b"".join([self.services, self.ip, self.port])

    def regenerate(self, _services, _ip, _port):
        self.__init__(services=_services, ip=_ip, port=_port)


class VersionMessage(Message):

    def __init__(self,
                 version,
                 services,
                 addr_recv,
                 addr_from,
                 user_agent,
                 start_height,
                 relay):
        self.version = version
        self.services = services
        self.timestamp = int(time.time())
        self.addr_recv = addr_recv
        self.addr_from = addr_from
        self.nonce = random.getrandbits(64)
        self.user_agent = user_agent
        self.start_height = start_height
        self.relay = relay
        self.payload = b""
        self.command = b"version"
        Message.__init__(self, command=self.command, payload=self.payload)

    def generate_nonce(self):
        self.nonce = random.getrandbits(64)
        return self.nonce

    def get_current_start_height(self):
        # TODO: implement this
        pass

    def to_bytes(self):
        msg = b""
        msg += struct.pack('<I', self.version)
        msg += struct.pack('<Q', self.services)
        msg += struct.pack("<I", int(time.time()))
        msg += self.addr_recv.addr_NT
        msg += self.addr_from.addr_NT
        msg += struct.pack('<Q', self.generate_nonce())
        msg += super().to_var_str(self.user_agent)
        msg += struct.pack('<I', self.start_height)
        msg += struct.pack('?', self.relay)
        self.payload = msg
        return Message.to_bytes(self)

    assigned_services = {hex(1): 'NODE_NETWORK',
                         hex(2): 'NODE_GETUTXO',
                         hex(4): 'NODE_BLOOM',
                         hex(8): 'NODE_WITNESS',
                         hex(1024): 'NODE_NETWORK_LIMITED'
                         }


class Verack(Message):

    def __init__(self):
        self.command = b"verack"
        self.payload = b""
        Message.__init__(self, command=self.command, payload=self.payload)


class Addr(Message):

    def __init__(self):
        self.command = b"addr"
        self.payload = b""
        Message.__init__(self, command=self.command, payload=self.payload)
