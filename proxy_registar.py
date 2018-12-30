#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Class (and main program) for echo register server in UDP simple."""

import socketserver
import sys
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

TRYNING = b'SIP/2.0 100 Trying\r\n\r\n'
RING = b'SIP/2.0 180 Ring\r\n\r\n'
OK = b'SIP/2.0 200 OK\r\n\r\n'
BAD_REQUEST = b'SIP/2.0 400 Bad Request\r\n\r\n'
UNAUTHORIZED = b'SIP/2.0 401 Unauthorized\r\n\r\n'
NOT_FOUND = b'SIP/2.0 404 User Not Found\r\n\r\n'
NOT_ALLOWED = b'SIP/2.0 405 Method Not Allowed\r\n\r\n'

class XMLHandler(ContentHandler):

    def __init__(self):
        self.attrsDict = {'account': ['username', 'passwd'],
                          'uaserver': ['ip', 'port'],
                          'rtpaudio': ['port'],
                          'regproxy': ['ip', 'port'],
                          'log': ['path'],
                          'aduio': ['path'],
                          'server': ['name', 'ip', 'port'],
                          'database': ['path', 'passwdpath']}
        self.config = {}

    def startElement(self, name, attrs):
        if name in self.attrsDict:
            for tag in self.attrsDict[name]:
                self.config[name + '_' + tag] = attrs.get(tag, '')

    def get_config(self):
        return self.config


class SIPRegisterHandler(socketserver.DatagramRequestHandler):
    """Echo register server class."""

    dict_Users = {}

    def add_user(self, sip_address, expires_time, nonce):
        """Add users to the dictionary."""
        #HACER LO DEL NONCE
        self.dict_Users[sip_address] = self.client_address[0] + ' Expires: '\
                                                              + expires_time
        self.wfile.write(OK)

    def del_user(self, sip_address):
        """Delete users of the dictionary."""
        del self.dict_Users[sip_address]
        self.wfile.write(OK)

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
                    sip_address = received_mess[1].split(':')[1].split(':')[0]
                    port = received_mess[1].split(':')[1].split(':')[1]
                else:
                    self.wfile.write(BAD_REQUEST)
            elif index == 1:
                if received_mess[0] == 'Expires:':
                    expires_time = float(received_mess[1])
                    if expires_time > 0:
                        expires_time = expires_time + time.time()
                        expires_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                                     time.gmtime(expires_time))
                    elif expires_time == 0:
                        self.del_user(sip_address)
                else:
                    self.wfile.write(BAD_REQUEST)
            elif index == 2:
                if received_mess[0] == 'Authorization:':
                    if received_mess[1] == 'Digest':
                        if received_mess[2].split('=')[0] == 'response':
                            nonce = received_mess[2].split('=')[1]
                            self.add_user(sip_address, expires_time, nonce)
                        else:
                            self.wfile.write(BAD_REQUEST)
                    else:
                        self.wfile.write(BAD_REQUEST)
                else:
                    self.wfile.write(BAD_REQUEST)


if __name__ == "__main__":
    # Listens at localhost ('') in a port defined by the user
    # and calls the SIPRegisterHandler class to manage the request
    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    try:
        CONFIG = sys.argv[1]
        parser.parse(open(CONFIG))
        #serv = socketserver.UDPServer(('', PORT), SIPRegisterHandler)
    except (IndexError, ValueError, FileNotFoundError):
        sys.exit('Usage: python3 proxy_registar.py config.')

    print('Server AvengersServer listening at port 5555...')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('  Server interrupt')
