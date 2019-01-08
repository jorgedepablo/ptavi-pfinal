#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Class (and main program) for echo register server in UDP simple."""

import socketserver
import socket
import sys
import time
import json
import random
import hashlib
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

TRYNING = b'SIP/2.0 100 Trying\r\n\r\n'
RING = b'SIP/2.0 180 Ring\r\n\r\n'
OK = b'SIP/2.0 200 OK\r\n\r\n'
BAD_REQUEST = b'SIP/2.0 400 Bad Request\r\n\r\n'
UNAUTHORIZED = b'SIP/2.0 401 Unauthorized\r\n\r\n'
NOT_FOUND = b'SIP/2.0 404 User Not Found\r\n\r\n'
NOT_ALLOWED = b'SIP/2.0 405 Method Not Allowed\r\n\r\n'


class WriteLog():
    def __init__(self):
        from __main__ import FICH_LOG as log
        self.log = log

    def start_log(self):
         current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))
         action = (current_time + 'Starting...')


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

    dict_Users = {}
    dict_Passwd = {}
    dict_Nonce = {}

    def add_user(self, sip_address, expires_time, port):
        """Add users to the dictionary."""
        #HACER LO DEL NONCE
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))
        self.dict_Users[sip_address] = (self.client_address[0], str(port), current_time, expires_time)
        self.register2json()
        self.wfile.write(OK)

    def del_user(self, sip_address):
        """Delete users of the dictionary."""
        del self.dict_Users[sip_address]
        self.register2json()
        self.wfile.write(OK)
        #Aqui si hay un key error mandaria un not found???

    def check_expires(self):
        """Check if the users have expired, delete them of the dictionary."""
        users_list = list(self.dict_Users)
        for user in users_list:
            expires_time = self.dict_Users[user][3]
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
            self.dict_Passwd = json.load(json_file)

    def get_digest(self, user):
        digest = 0
        nonce = str(self.dict_Nonce[user])
        if user in self.dict_Passwd:
            passwd = self.dict_Passwd[user]
            h = hashlib.sha1(bytes(passwd + '\n', 'utf-8'))
            h.update(bytes(nonce,'utf-8'))
            digest = h.hexdigest()
        return digest

    def re_send(self, user, mess):
        #Si usuario esta en la lista sacar ip y puerto else not found
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ip = self.dict_Users[user][0]
            port =  self.dict_Users[user][1]
            my_socket.connect((ip, int(port)))
            print('Sending: ')
            print(mess)
            my_socket.send(bytes(mess, 'utf-8'))

            data = my_socket.recv(1024)
            response = data.decode('utf8')
            print(response)
            #EL 100, EL 180 Y EL 200 VAN JUNTOS???
            if response.split()[1] == ('100', '180', '200'):
                self.wfile.write(data)

    def handle(self):
        """Handle method of the server class."""
        self.json2register()
        self.json2passwd()
        self.check_expires()
        received_mess = []
        for line in self.rfile:
            received_mess.append(line.decode('utf-8'))

        received_mess = ''.join(received_mess)
        print(received_mess)
            #Aqui pondria lo del check_request
        if received_mess.split()[0] == 'REGISTER':
            clt_sip = received_mess.split()[1].split(':')[1]
            clt_port = int(received_mess.split()[1].split(':')[2])
            if len(received_mess.split()) == 5:
                if received_mess.split()[3] == 'Expires:':
                    expires_time = float(received_mess.split()[4])
                    if expires_time > 0:
                        expires_time = expires_time + time.time()
                        expires_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                                 time.gmtime(expires_time))
                        if clt_sip in self.dict_Users:
                            self.add_user(clt_sip, expires_time, clt_port)
                        else:
                            if clt_sip in self.dict_Nonce:
                                nonce = self.dict_Nonce[clt_sip]
                            else:
                                nonce = random.randint(10**19, 10**20)
                                self.dict_Nonce[clt_sip] = nonce
                            self.wfile.write(UNAUTHORIZED[:-2] + b'WWW Authenticate: Digest nonce="' +
                                             bytes(str(nonce), 'utf-8') + b'"\r\n\r\n')
                    elif expires_time == 0:
                        self.del_user(clt_sip)
                else:
                    self.wfile.write(BAD_REQUEST)
            elif len(received_mess.split()) == 8:
                if received_mess.split()[5] == 'Authorization:':
                    if received_mess.split()[6] == 'Digest':
                        if received_mess.split()[7].split('=')[0] == 'response':
                            expires_time = float(received_mess[4])
                            expires_time = expires_time + time.time()
                            expires_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                                     time.gmtime(expires_time))
                            clt_digest = received_mess[7].split('"')[1]
                            digest = self.get_digest(clt_sip)
                            if clt_digest == digest:
                                self.add_user(clt_sip, expires_time, clt_port)
                            else:
                                self.wfile.write(UNAUTHORIZED)
                        else:
                            self.wfile.write(BAD_REQUEST)
                    else:
                        self.wfile.write(BAD_REQUEST)
                else:
                    self.wfile.write(BAD_REQUEST)
            else:
                self.wfile.write(BAD_REQUEST)

        elif received_mess.split()[0] == 'INVITE' or 'BYE' or 'ACK':
            user_address = received_mess.split()[1].split(':')[1]
            self.re_send(user_address, received_mess)
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
