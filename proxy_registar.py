#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Class (and main program) for echo register server in UDP simple."""

import socketserver
import sys
import time
import json


class SIPRegisterHandler(socketserver.DatagramRequestHandler):
    """Echo register server class."""

    dict_Users = {}

    def add_user(self, sip_address, expires_time):
        """Add users to the dictionary."""
        self.dict_Users[sip_address] = self.client_address[0] + ' Expires: '\
                                                              + expires_time
        self.register2json()
        self.wfile.write(b'SIP/2.0 200 OK\r\n\r\n')

    def del_user(self, sip_address):
        """Delete users of the dictionary."""
        try:
            del self.dict_Users[sip_address]
            self.register2json()
            self.wfile.write(b'SIP/2.0 200 OK\r\n\r\n')
        except KeyError:
            self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')

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
        self.json2register()
        self.check_expires()
        received_mess = []
        for index, line in enumerate(self.rfile):
            received_mess = line.decode('utf-8')
            received_mess = ''.join(received_mess).split()
            if index == 0:
                if received_mess[0] == 'REGISTER':
                    sip_address = received_mess[1].split(':')[1]
                else:
                    self.wfile.write(b'SIP/2.0 400 Bad Request\r\n\r\n')
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
                    self.wfile.write(b'SIP/2.0 400 Bad Request\r\n\r\n')

    def register2json(self):
        """Dump the data of users in a json file."""
        self.check_expires()
        with open('registered.json', 'w') as json_file:
            json.dump(self.dict_Users, json_file, indent=4)

    def json2register(self):
        """if exist a json file copy the data of users in the dictionary."""
        try:
            with open('registered.json', 'r') as json_file:
                self.dict_Users = json.load(json_file)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    # Listens at localhost ('') in a port defined by the user
    # and calls the SIPRegisterHandler class to manage the request
    try:
        PORT = int(sys.argv[1])
        serv = socketserver.UDPServer(('', PORT), SIPRegisterHandler)
    except IndexError or ValueError:
        sys.exit('Usage: python3 server.py "port"')

    print('Runnig echo server UDP...')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('  Server interrupt')
