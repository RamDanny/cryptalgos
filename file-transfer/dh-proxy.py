#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Random.random import randint
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import sys
import socket
import select

BUFFER_SIZE = 1024
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16
LENGTH_FIELD_SIZE = 2
SESSION_KEY_SIZE = 32
G = 2
P = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

# recv data of size recv_len over conn
def recvall(conn, recv_len):
    data = b''
    while len(data) < recv_len:
        packet = conn.recv(recv_len - len(data))
        if not packet:
            break
        data += packet
    return data

def proxy(client_port, server_ip, server_port):
    # setup connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ser_conn:
        # accept client connection
        c.bind(('localhost', client_port))
        c.listen(5)
        (cli_conn, cli_addr) = c.accept()
        # request server connection
        ser_conn.connect((server_ip, server_port))
        cli_conn.setblocking(False)
        ser_conn.setblocking(False)
        # proxy private key
        x = randint(0, P-2)
        X = pow(G, x, P)
        pub_x = str(X).zfill(384).encode('utf-8')
        # proxy variables
        cli_state, ser_state = 0, 0
        pub_cli, pub_ser, cli_key, ser_key, enc_key, dec_key = None, None, None, None, None, None
        nonce, ciphertext, tag, length_field, plaintext = None, None, None, None, b''
        nonce_new, ciphertext_new, tag_new, length_new = None, None, None, None
        is_data_transfer = False
        # proxy interception
        read_socks, write_socks, err_socks = [cli_conn, ser_conn], [cli_conn, ser_conn], []
        while not is_data_transfer:
            readable, writable, errored = select.select(read_socks, write_socks, err_socks, 30)
            if cli_conn in readable:
                if cli_state == 0:
                    pub_cli = int(recvall(cli_conn, 384).decode('utf-8'))
                    cli_state = 1
                elif cli_state == 2:
                    h = SHA256.new(data=('%x' % cli_key).encode('utf-8'))
                    dec_key = h.digest()[:SESSION_KEY_SIZE]
                    while True:
                        # receive lth field
                        length_field = recvall(cli_conn, LENGTH_FIELD_SIZE)
                        if not length_field:
                            break
                        # receive rest of packet
                        packet_length = int.from_bytes(length_field, 'big')
                        packet = recvall(cli_conn, packet_length)
                        if len(packet) < packet_length:
                            sys.stderr.write('Error: Incomplete packet received.\n')
                            break
                        nonce = packet[:NONCE_SIZE]
                        tag = packet[NONCE_SIZE:NONCE_SIZE+TAG_SIZE]
                        ciphertext = packet[NONCE_SIZE+TAG_SIZE:]
                        # decrypt and verify ciphertext
                        try:
                            cipher = AES.new(dec_key, AES.MODE_GCM, nonce=nonce)
                            padded_plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                            plaintext_chunk = unpad(padded_plaintext, AES.block_size, style='pkcs7')
                            plaintext += plaintext_chunk
                        except ValueError:
                            sys.stderr.write('Error: integrity check failed.\n')
                    cli_state = 3
            if cli_conn in writable:
                if cli_state == 1:
                    cli_conn.sendall(pub_x)
                    cli_key = pow(pub_cli, x, P)
                    cli_state = 2
            if ser_conn in readable:
                if ser_state == 1:
                    pub_ser = int(recvall(ser_conn, 384).decode('utf-8'))
                    ser_state = 2
            if ser_conn in writable:
                if ser_state == 0:
                    ser_conn.sendall(pub_x)
                    ser_state = 1
                elif ser_state == 2 and cli_state == 3:
                    ser_key = pow(pub_ser, x, P)
                    h = SHA256.new(data=('%x' % ser_key).encode('utf-8'))
                    enc_key = h.digest()[:SESSION_KEY_SIZE]
                    file_length = len(plaintext)
                    read_from = 0
                    while read_from < file_length:
                        remaining_data = plaintext[read_from:]
                        data_length = min(len(remaining_data), BUFFER_SIZE)
                        # encrypt file data
                        data_to_send = remaining_data[:data_length]
                        cipher = AES.new(enc_key, AES.MODE_GCM)
                        padded_data = pad(data_to_send, AES.block_size, style='pkcs7')
                        ciphertext, tag = cipher.encrypt_and_digest(padded_data)
                        # send packet
                        packet_length = len(cipher.nonce) + len(tag) + len(ciphertext)
                        length_field = packet_length.to_bytes(LENGTH_FIELD_SIZE, 'big')
                        packet = length_field + cipher.nonce + tag + ciphertext
                        ser_conn.sendall(packet)
                        read_from += data_length
                    ser_state = 3
                    is_data_transfer = True

def main():
    # check cmd args
    if len(sys.argv) > 4 and sys.argv[1] == '-l':
        ip = sys.argv[3].split('.')
        for num in ip:
            try:
                n = int(num)
            except ValueError:
                print('Usage: filename -l client_port_number server_ip_address server_port_number')
                return
        proxy(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    else:
        print('Usage: filename -l client_port_number server_ip_address server_port_number')

if __name__ == '__main__':
    main()
