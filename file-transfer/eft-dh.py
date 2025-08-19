#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Random.random import randint
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import sys
import socket

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

def client(serv_ip, port):
    # request connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
        c.connect((serv_ip, port))
        # key exchange
        a = randint(0, P-2)
        A = pow(G, a, P)
        pub_a = (str(A).zfill(384)).encode('utf-8')
        c.sendall(pub_a)
        pub_b = int(recvall(c, 384).decode('utf-8'))
        key = pow(pub_b, a, P)
        h = SHA256.new(data=('%x' % key).encode('utf-8'))
        enc_key = h.digest()[:SESSION_KEY_SIZE]
        # send encrypted file
        filedata = sys.stdin.buffer.read()
        file_length = len(filedata)
        read_from = 0
        while read_from < file_length:
            remaining_data = filedata[read_from:]
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
            c.sendall(packet)
            read_from += data_length

def server(port):
    # accept connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', port))
        s.listen(5)
        c, cli_addr = s.accept()
        with c:
            # key exchange
            b = randint(0, P-2)
            B = pow(G, b, P)
            pub_b = (str(B).zfill(384)).encode('utf-8')
            pub_a = int(recvall(c, 384).decode('utf-8'))
            c.sendall(pub_b)
            key = pow(pub_a, b, P)
            h = SHA256.new(data=('%x' % key).encode('utf-8'))
            dec_key = h.digest()[:SESSION_KEY_SIZE]
            # receive file packets
            while True:
                # receive lth field
                length_field = recvall(c, LENGTH_FIELD_SIZE)
                if not length_field:
                    break
                # receive rest of packet
                packet_length = int.from_bytes(length_field, 'big')
                packet = recvall(c, packet_length)
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
                    plaintext = unpad(padded_plaintext, AES.block_size, style='pkcs7')
                    sys.stdout.buffer.write(plaintext)
                except ValueError:
                    sys.stderr.write('Error: integrity check failed.\n')

def main():
    # check cmd args
    if len(sys.argv) > 2:
        # server args
        if sys.argv[1] == '-l':
            server(int(sys.argv[2]))
        # client args
        else:
            ip = sys.argv[1].split('.')
            for num in ip:
                try:
                    n = int(num)
                except ValueError:
                    print('Usage: filename [-l port_number] [server_ip_address port_number]')
                    return
            client(sys.argv[1], int(sys.argv[2]))
    else:
        print('Usage: filename [-l port_number] [server_ip_address port_number]')

if __name__ == '__main__':
    main()
