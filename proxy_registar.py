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
                          'audio': ['path'],
                          'server': ['name', 'ip', 'port'],
                          'database': ['path', 'passwdpath']}
        self.config = {}

    def startElement(self, name, attrs):
        if name in self.attrsDict:
            for tag in self.attrsDict[name]:
                self.config[name + '_' + tag] = attrs.get(tag, '')

    def get_config(self):
        return self.config


class SIPRegisterProxyHandler(socketserver.DatagramRequestHandler):
    """Echo register server class."""

    def __init__(self):
        self.dict_Users = {}
        self.dict_Passwd = {}

    def add_user(self, sip_address, expires_time):
        """Add users to the dictionary."""
        #HACER LO DEL NONCE
        self.dict_Users[sip_address] = self.client_address[0] + ' Expires: '\
                                                              + expires_time
        self.wfile.write(OK)

    def del_user(self, sip_address):
        """Delete users of the dictionary."""
        del self.dict_Users[sip_address]
        self.wfile.write(OK)
        #Aqui si hay un key error mandaria un not found???

    def check_expires(self):
        """Check if the users have expired, delete them of the dictionary."""
        users_list = list(self.dict_Users)
        for user in users_list:
            expires_time = self.dict_Users[user].split(': ')[1]
            current_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                         time.gmtime(time.time()))
            if expires_time < current_time:
                del self.dict_Users[user]

    def register2json(self):
        """Dump the data of users in a json file."""
        self.check_expires()
        with open(DATA_USERS, 'w') as json_file:
            json.dump(self.dict_Users, json_file, indent=4)

    def json2register(self):
        """if exist a json file copy the data of users in the dictionary."""
        try:
            with open(DATA_USERS, 'r') as json_file:
                self.dict_Users = json.load(json_file)
        except FileNotFoundError:
            pass

    def json2passwd(self):
        with open(DATA_PASSWD, 'r') as json_file:
            for line in json_file:
                user = line.split()[0]
                passwd = line.split()[1]
                self.dict_Passwd[user] = passwd

    def re_send(self, user):
        #Si usuario esta en la lista sacar ip y puerto else not found
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.connect(ip, port)
            for line in self.rfile:
                print('Sending: ' + line)
                my_socket.send(bytes(line, 'utf-8'))

            data = my_socket.recv(1024)
            response = data.decode('utf8')
            print(response)
            #EL 100, EL 180 Y EL 200 VAN JUNTOS???
            if response.split()[1] == ('100', '180', '200'):
                self.wfile.write(data)

    def handle(self):
        """Handle method of the server class."""
        self.json2register()
        self.check_expires()
        received_mess = []
        self.authorization = False
        for line in self.rfile:
            received_mess = line.decode('utf-8')
        received_mess = ''.join(received_mess).split()
        print(received_mess)
            #Aqui pondria lo del check_request
        if received_mess[0] == 'REGISTER':
            clt_sip = received_mess[1].split(':')[1].split(':')[0]
            clt_port = int(received_mess[1].split(':')[1].split(':')[1])
            print(clt_sip)
            print(clt_port)
            print(received_mess)
            if len(received_mess) == 5:
                if received_mess[3] == 'Expires:':
                    expires_time = float(received_mess[4])
                    if expires_time > 0:
                        expires_time = expires_time + time.time()
                        expires_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                                 time.gmtime(expires_time))
                        if clt_sip in self.dict_Users:
                            self.add_user(clt_sip, expires_time)
                        else:
                            self.wfile.write(UNAUTHORIZED)
                    elif expires_time == 0:
                        self.del_user(clt_sip)
                else:
                    self.wfile.write(BAD_REQUEST)
            elif len(received_mess) == 8:
                if received_mess[6] == 'Authorization:':
                    if received_mess[7] == 'Digest':
                        if received_mess[8].split('=')[0] == 'response':
                            nonce = received_mess[8].split('=')[1]
                            #Hacer que si pasa el nonce le añada
                            self.add_user(clt_sip, expires_time)
                        else:
                            self.wfile.write(BAD_REQUEST)
                    else:
                        self.wfile.write(BAD_REQUEST)
            else:
                self.wfile.write(BAD_REQUEST)

        elif received_mess[0] == 'INVITE' or 'BYE' or 'ACK':
            user_address = received_mess[1].split(':')[1]
            re_send(user_address)
            #Se podra hacer un disconect? o se apaga solo el client?
            #Chequear si conozco al que envia los mensajes para reenviarlos ?? si es asi como???
        else:
            self.wfile.write(NOT_ALLOWED)


if __name__ == "__main__":
    # Listens at localhost ('') in a port defined by the user
    # and calls the SIPRegisterHandler class to manage the request
    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    try:
        CONFIG = sys.argv[1]
        parser.parse(open(CONFIG))
        SERVER_NAME = cHandler.config['server_name']
        SERVER_IP = cHandler.config['server_ip']
        SERVER_PORT = int(cHandler.config['server_port'])
        DATA_USERS = cHandler.config['database_path']
        DATA_PASSWD = cHandler.config['database_passwdpath']
        FICH_LOG = cHandler.config['log_path']
        serv = socketserver.UDPServer((SERVER_IP, SERVER_PORT), SIPRegisterProxyHandler)
    except (IndexError, ValueError, FileNotFoundError):
        sys.exit('Usage: python3 proxy_registar.py config.')

    try:
        print('Server ' + SERVER_NAME + ' listening at port ' +  str(SERVER_PORT) + '...')
        serv.serve_forever()
    except KeyboardInterrupt:
        print('  Server interrupt')
