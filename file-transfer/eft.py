#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
import socket

BUFFER_SIZE = 1024
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16
LENGTH_FIELD_SIZE = 2

# recv data of size recv_len over conn
def recvall(conn, recv_len):
    data = b''
    while len(data) < recv_len:
        packet = conn.recv(recv_len - len(data))
        if not packet:
            break
        data += packet
    return data

def client(key, serv_ip, port):
    # request connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
        c.connect((serv_ip, port))
        #send salt
        salt = get_random_bytes(SALT_SIZE)
        c.sendall(salt)
        # derive enc key
        enc_key = PBKDF2(key, salt, 32)
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

def server(key, port):
    # accept connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', port))
        s.listen(5)
        c, cli_addr = s.accept()
        with c:
            # receive salt
            salt = recvall(c, SALT_SIZE)
            if len(salt) < SALT_SIZE:
                sys.stderr.write('Error: Failed to receive complete salt.\n')
                return
            # derive dec key
            dec_key = PBKDF2(key, salt, 32)
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
                    sys.stdout.buffer.flush()
                except ValueError:
                    sys.stderr.write('Error: integrity check failed.\n')
                    sys.stderr.flush()

def main():
    # check cmd args
    if len(sys.argv) > 3:
        key = sys.argv[2]
        # server args
        if sys.argv[3] == '-l':
            try:
                port = int(sys.argv[4])
            except ValueError:
                print('Usage: filename -k key [-l port_number] [server_ip_address port_number]')
                return
            server(key, port)
        # client args
        else:
            ip_parts = sys.argv[3].split('.')
            if len(ip_parts) != 4 or any(not part.isdigit() for part in ip_parts):
                print('Usage: filename -k key [-l port_number] [server_ip_address port_number]')
                return
            try:
                port = int(sys.argv[4])
            except ValueError:
                print('Usage: filename -k key [-l port_number] [server_ip_address port_number]')
                return
            client(key, sys.argv[3], port)
    else:
        print('Usage: filename -k key [-l port_number] [server_ip_address port_number]')

if __name__ == '__main__':
    main()