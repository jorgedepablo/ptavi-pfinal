#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Class (and main program) for echo register server in UDP simple."""

import socketserver
import sys
import os

try:
    CONFIG = sys.argv[1]
except (IndexError, ValueError):
    sys.exit('Usage: python uaserver.py config')

TRYNING = b'SIP/2.0 100 Trying\r\n\r\n'
RING = b'SIP/2.0 180 Ring\r\n\r\n'
OK = b'SIP/2.0 200 OK\r\n\r\n'
BAD_REQUEST = b'SIP/2.0 400 Bad Request\r\n\r\n'
UNAUTHORIZED = b'SIP/2.0 401 Unauthorized\r\n\r\n'
NOT_FOUND = b'SIP/2.0 404 User Not Found\r\n\r\n'
NOT_ALLOWED = b'SIP/2.0 405 Method Not Allowed\r\n\r\n'



class SIPRegisterHandler(socketserver.DatagramRequestHandler):
 """Echo register server class."""

    dict_Users = {}

    def add_user(self, sip_address, expires_time):
        """Add users to the dictionary."""
        self.dict_Users[sip_address] = self.client_address[0] + ' Expires: '\
                                                              + expires_time
        self.wfile.write(OK)

    def del_user(self, sip_address):
        """Delete users of the dictionary."""
        try:
            del self.dict_Users[sip_address]
            self.wfile.write(OK)
        except KeyError:
            self.wfile.write(BAD_REQUEST)

    def check_expires(self):
        """Check if the users have expired, delete them of the dictionary."""
        users_list = list(self.dict_Users)
        for user in users_list:
            expires_time = self.dict_Users[user].split(': ')[1]
            current_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                         time.gmtime(time.time()))
            if expires_time < current_time:
                del self.dict_Users[user]

    def handle(self):
        """Handle method of the server class."""
        self.check_expires()
        received_mess = []
        for index, line in enumerate(self.rfile):
            received_mess = line.decode('utf-8')
            received_mess = ''.join(received_mess).split()
            if index == 0:
                if received_mess[0] == 'REGISTER':
                    sip_address = received_mess[1].split(':')[1]
                else:
                    self.wfile.write(BAD_REQUEST)
            elif index == 1:
                if received_mess[0] == 'Expires:':
                    expires_time = float(received_mess[1])
                    if expires_time > 0:
                        expires_time = expires_time + time.time()
                        expires_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                                     time.gmtime(expires_time))
                        self.add_user(sip_address, expires_time)
                    elif expires_time == 0:
                        self.del_user(sip_address)
                else:
                    self.wfile.write(BAD_REQUEST)
            elif index == 2:
                if received_mess[0] == 'Authorization:':



class EchoHandler(socketserver.DatagramRequestHandler):
    """Echo server class."""
    def __init__(self):
        self.correct = True

    def check_request(self, mess):
        """Check if the SIP request is correctly formed."""
        valid_characters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                            'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
                            'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                            'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                            'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', '_', '-', '.']
        try:
            body = mess.split()[1]
            version = mess.split()[2]
            user = body.split('@')[0]
            ip = body.split('@')[1]
        except IndexError:
            self.correct = False

        if len(mess.split()) != 3:
            self.correct = False
        if version != 'SIP/2.0':
            self.correct = False
        if user.split(':')[0] != 'sip':
            self.correct = False
        for character in user.split(':')[1]:
            if character not in valid_characters:
                self.correct = False

        return self.correct

    def handle(self):
        """Handle method of the server class."""
        received_mess = []
        for index, line in enumerate(self.rfile):
            received_mess = line.decode('utf-8')
            if index == 0:
                # Reading the first string that client send
                client = received_mess.split(':')[1].split('@')[0]
                print(client + ' send: ' + received_mess)
                if self.check_request(received_mess):
                    method = received_mess.split()[0]
                    if method == 'INVITE':
                        self.wfile.write(TRYNING)
                        self.wfile.write(RING)
                        self.wfile.write(OK)
                        print('Sending 100 Trying')
                        print('Sending 180 Ring')
                        print('Sending 200 OK')
                    elif method == 'BYE':
                        self.wfile.write(OK)
                        print('Sending 200 OK')
                    elif method == 'ACK':
                        ToRun = 'mp32rtp -i 127.0.0.1 -p 23032 < ' + FICH
                        print('Running: ', ToRun)
                        os.system(ToRun)
                    else:
                        self.wfile.write(NOT_ALLOWED)
                        print('Sending 405 Method Not Allowed')
                else:
                    self.wfile.write(BAD_REQUEST)
                    print('Sending 400 Bad Request')
            else:
                # If no more lines, exit of the loop.
                break


if __name__ == "__main__":
    """Create echo server and listening."""
    serv = socketserver.UDPServer((SERVER, PORT), EchoHandler)
    print('Listening...')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('  Server interrupt')
