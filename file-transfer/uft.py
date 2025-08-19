#!/usr/bin/env python3
from Crypto.Cipher import AES
import sys
import socket

def client(serv_ip, port):
    # request connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
        c.connect((serv_ip, port))
        # send data
        packet = None
        filedata = sys.stdin.buffer.read()
        length = len(filedata)
        read_from = 0
        while read_from < length:
            remaining_data = filedata[read_from:]
            # packet size header
            packet_length = min(len(remaining_data), 1024)
            length_lower = packet_length & 0xff
            length_higher = (packet_length >> 8) & 0xff
            # packet data
            packet_data = bytes([length_higher, length_lower])
            packet = packet_data + remaining_data[:packet_length]
            c.send(packet)
            read_from += packet_length

def server(port):
    # accept connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', port))
        s.listen(5)
        (c, cli_addr) = s.accept()
        filedata = b''
        # receive data
        with c:
            while True:
                packet = c.recv(2)
                if not packet:
                    break
                length_higher, length_lower = packet[0], packet[1]
                packet_length = (length_higher << 8) | length_lower
                packet_data = c.recv(packet_length)
                filedata += packet_data
        sys.stdout.buffer.write(filedata)

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
