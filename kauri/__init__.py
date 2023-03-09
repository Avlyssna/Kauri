#!/usr/bin/env python3

from binascii import unhexlify
from threading import Thread
from socketserver import BaseRequestHandler, ThreadingMixIn, TCPServer
from base64 import standard_b64encode
from datetime import datetime as DateTime
from json import dumps as to_json

from bitstring import ConstBitStream


FINGERPRINTS = {
    '22.04': {
        'protocol': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1',
        'supportedCiphers': unhexlify('00000434071480f9c9f38b24f91bfbc8b5d60113c20b00000109637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c736e747275703736317832353531392d736861353132406f70656e7373682e636f6d2c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d736861323536000000397273612d736861322d3531322c7273612d736861322d3235362c65636473612d736861322d6e697374703235362c7373682d656432353531390000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d0000000000000000000000000000000000000000'),
        'keyExchange': unhexlify('000000bc081f000000330000000b7373682d65643235353139000000200df9f8738d4a772c0a3ffd8885aa70a78ac7be4d5625354332ff199a8b122ef50000002050eecc69fda68a37dd7d9df1683ae1bf48413bcf7ab8a03fbce7a36491674077000000530000000b7373682d656432353531390000004062c1f61bc612c18d1f0420279dd6c3960ec191c228d96a6322c41b658ea03c3e451756eafc6f0a840ea67670fd0c926db148a243db37210d41bb458cc51c450b00000000000000000000000c0a1500000000000000000000')
    }
}


class HoneypotRequestHandler(BaseRequestHandler):
    def read_until(self, sequence, max_buffer=10240):
        buffer = b''
        has_sequence = False

        while len(buffer) < max_buffer and not has_sequence:
            buffer += self.request.recv(1024)
            has_sequence = buffer.endswith(sequence)

        return buffer, has_sequence

    def handle(self):
        session_state = {}
        session_state['anomalies'] = []
        session_state['client'] = {}

        client_protocol_packet, has_newline = self.read_until(b'\r\n')

        session_state['client']['protocol'] = standard_b64encode(client_protocol_packet)

        if not has_newline:
            session_state['anomalies'].append({
                'field': 'client.protocol',
                'problem': 'Client supplied an abnormal amount of data (>10240 bytes)',
                'timestamp': DateTime.utcnow().isoformat()
            })

        # We send back the server protocol for Ubuntu 22.04.
        self.request.sendall(b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n')

        # Time to parse the client ciphers.
        client_ciphers_packet = self.request.recv(10240)

        stream = ConstBitStream(client_ciphers_packet)
        packet_size = stream.read('uintbe:32')
        padding_size = stream.read('uintbe:8')
        ssh_message_code = stream.read('uintbe:8')
        cookie = stream.read('bytes:16').hex()

        key_exchange_size = stream.read('uintbe:32')
        supported_key_exchanges = stream.read(f'bytes:{key_exchange_size}')

        server_host_key_alg_size = stream.read('uintbe:32')
        server_host_key_algs = stream.read(f'bytes:{server_host_key_alg_size}')

        encryption_algorithms_client_to_server_size = stream.read('uintbe:32')
        encryption_algorithms_client_to_server = stream.read(f'bytes:{encryption_algorithms_client_to_server_size}')

        encryption_algorithms_server_to_client_size = stream.read('uintbe:32')
        encryption_algorithms_server_to_client = stream.read(f'bytes:{encryption_algorithms_server_to_client_size}')

        mac_c2s_size = stream.read('uintbe:32')
        mac_c2s = stream.read(f'bytes:{mac_c2s_size}')

        mac_s2c_size = stream.read('uintbe:32')
        mac_s2c = stream.read(f'bytes:{mac_s2c_size}')

        compression_c2s_size = stream.read('uintbe:32')
        compression_c2s = stream.read(f'bytes:{compression_c2s_size}')

        compression_s2c_size = stream.read('uintbe:32')
        compression_s2c = stream.read(f'bytes:{compression_s2c_size}')

        languages_c2s_size = stream.read('uintbe:32')
        languages_c2s = stream.read(f'bytes:{languages_c2s_size}')

        languages_s2c_size = stream.read('uintbe:32')
        languages_s2c = stream.read(f'bytes:{languages_s2c_size}')
        print(languages_s2c)

        first_kex_follows = stream.read('uintbe:8')
        print(first_kex_follows)

        reserved = stream.read('uintbe:32')
        print(reserved)

        padding = stream.read(f'bytes:{padding_size}')
        print(padding)

        print('Got cookie:', cookie)
        print('Supported kexs:', supported_key_exchanges.decode().split(','))

        print(packet_size)

        # session_state['client']['ciphers'] = standard_b64encode(client_ciphers)

        # self.request.sendall(FINGERPRINTS['22.04']['supportedCiphers'])

        # key_exchange = self.request.recv(1024)

        # self.request.sendall(FINGERPRINTS['22.04']['keyExchange'])


class HoneypotServer(ThreadingMixIn, TCPServer):
    pass


def main():
    server = HoneypotServer(('127.0.0.1', 13037), HoneypotRequestHandler)
    server.serve_forever()
    # server_thread = Thread(target=server.serve_forever)
    # server_thread.start()
