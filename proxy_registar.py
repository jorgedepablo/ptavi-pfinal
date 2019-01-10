#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Nick Fury Server
"""Class (and main program) for proxy register server in UDP simple."""

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


class CheckIP():
    """Class to check if ip addess is correct."""
    
    def __init__(self):
        """Init the boolean."""
        self.correct = True

    def check_ip(self, ip):
        """Check if ip is valid."""
        valid_ip = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.']
        rang = list(range(256))
        self.correct = True
        try:
            first = int(ip.split('.')[0])
            second = int(ip.split('.')[1])
            third = int(ip.split('.')[2])
            fourth = int(ip.split('.')[3])
            dot = 0
            for character in ip:
                if character not in valid_ip:
                    self.correct = False
                if character == '.':
                    dot = dot + 1
            if dot != 3:
                self.correct = False
            if first < 127 or first > 223:
                self.correct = False
            else:
                if second not in rang:
                    self.correct = False
                if third not in rang:
                    self.correct = False
                if fourth not in rang:
                    self.correct = False
        except (IndexError, ValueError):
            self.correct = False

        return self.correct


class WriterLog():
    """Class to write in log file."""

    def __init__(self):
        """Import the paht of the main."""
        from __main__ import FICH_LOG as log
        self.log = log

    def wrt_log(self, status):
        """Write the status in file."""
        with open(self.log, 'a') as log_file:
            log_file.write(status)

    def starting(self):
        """FOR Starting."""
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                     time.gmtime(time.time()))
        status = (current_time + ' Starting...\r\n')
        self.wrt_log(status)

    def finishing(self):
        """For finishing."""
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                     time.gmtime(time.time()))
        status = (current_time + ' Finishing.\r\n')
        self.wrt_log(status)

    def senting(self, ip, port, content):
        """For send messages."""
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                     time.gmtime(time.time()))
        content = content.replace('\r\n', ' ')
        status = (current_time + ' Sent to ' + ip + ':' + str(port) +
                  ': ' + content + '\r\n')
        self.wrt_log(status)

    def received(self, ip, port, content):
        """For received messages."""
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                     time.gmtime(time.time()))
        content = content.replace('\r\n', ' ')
        status = (current_time + ' Received from ' + ip + ':' + str(port) +
                  ': ' + content + '\r\n')
        self.wrt_log(status)

    def senting_rtp(self, ip, port, media):
        """For send rtp media."""
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                     time.gmtime(time.time()))
        status = (current_time + ' Senting to ' + ip + ':' + str(port) +
                  ' file: ' + media + ' by RTP\r\n')
        self.wrt_log(status)

    def conexion_refused(self, ip, port):
        """For ConnectionRefusedError."""
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                     time.gmtime(time.time()))
        status = ('Error: No server listening at ' + ip + ' port ' +
                  str(port) + '\r\n')
        self.wrt_log(status)


class XMLHandler(ContentHandler):
    """Class for extract tags of XML fich."""

    def __init__(self):
        """Create a dictionary whit config file tags."""
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
        """If tag in the dictionary copy in other dictionary."""
        if name in self.attrsDict:
            for tag in self.attrsDict[name]:
                self.config[name + '_' + tag] = attrs.get(tag, '')

    def get_tags(self):
        """Return the second dictionary."""
        return self.config


class SIPRegisterProxyHandler(socketserver.DatagramRequestHandler):
    """Echo register server class."""

    dict_Users = {}
    dict_Passwd = {}
    dict_Nonce = {}
    correct = True

    def add_user(self, sip_address, expires_time, port):
        """Add users to the dictionary."""
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                     time.gmtime(time.time()))
        self.dict_Users[sip_address] = (self.client_address[0], str(port),
                                        current_time, expires_time)
        self.register2json()
        self.wfile.write(OK)
        log.senting(self.client_address[0], self.client_address[1],
                    OK.decode())

    def del_user(self, sip_address):
        """Delete users of the dictionary."""
        del self.dict_Users[sip_address]
        self.register2json()
        self.wfile.write(OK)
        log.senting(self.client_address[0], self.client_address[1],
                    OK.decode())

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
        """If exist a json file copy the data of users in the dictionary."""
        try:
            with open(DATA_USERS, 'r') as json_file:
                self.dict_Users = json.load(json_file)
        except FileNotFoundError:
            pass

    def json2passwd(self):
        """Copy the data of passwords in the dictionary."""
        with open(DATA_PASSWD, 'r') as json_file:
            self.dict_Passwd = json.load(json_file)

    def get_digest(self, user):
        """Get the digest with the passwords of dictionary."""
        digest = 0
        nonce = str(self.dict_Nonce[user])
        if user in self.dict_Passwd:
            passwd = self.dict_Passwd[user]
            h = hashlib.sha1(bytes(passwd + '\n', 'utf-8'))
            h.update(bytes(nonce, 'utf-8'))
            digest = h.hexdigest()
        return digest

    def check_request(self, mess):
        """Check if the SIP request is correctly formed."""
        valid_characters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                            'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
                            'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                            'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                            'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', '_', '-', '.', '@']
        self.correct = True
        try:
            address = mess.split()[1]
            version = mess.split()[2]
            exp = mess.split()[3]
            float(mess.split()[4])
        except IndexError:
            self.correct = False

        if len(mess.split()) != 5 and len(mess.split()) != 8:
            self.correct = False
        if not address.startswith('sip:'):
            self.correct = False
        else:
            at = 0
            for character in address.split(':')[1]:
                if character not in valid_characters:
                    self.correct = False
                if character == '@':
                    at = at + 1
            if at != 1:
                self.correct = False
        if version != 'SIP/2.0':
            self.correct = False
        if exp != 'Expires:':
            self.correct = False

        if len(mess.split()) == 8:
            try:
                athr = mess.split()[5]
                dig = mess.split()[6]
                rspnc = mess.split()[7]
            except IndexError:
                self.correct = False

            if athr != 'Authorization:':
                self.correct = False
            if dig != 'Digest':
                self.correct = False
            if not rspnc.startswith('response="'):
                self.correct = False
            else:
                quotes = 0
                for character in rspnc.split('=')[1]:
                    if character == '"':
                        quotes = quotes + 1
                if quotes != 2:
                    self.correct = False

        return self.correct

    def re_send(self, user, mess):
        """Proxy function."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ip = self.dict_Users[user][0]
            port = self.dict_Users[user][1]
            try:
                my_socket.connect((ip, int(port)))
                my_socket.send(bytes(mess, 'utf-8'))
                log.senting(ip, port, mess)
                if not ''.join(mess).split()[0] == 'ACK':
                    data = my_socket.recv(1024)
                    response = data.decode('utf8')
                    log.received(ip, port, response)
                    self.wfile.write(data)
            except ConnectionRefusedError:
                log.conexion_refused(ip, port)

    def handle(self):
        """Handle method of the server class."""
        self.json2register()
        self.json2passwd()
        self.check_expires()
        received_mess = []
        for line in self.rfile:
            received_mess.append(line.decode('utf-8'))
        received_mess = ''.join(received_mess)
        log.received(self.client_address[0], self.client_address[1],
                     received_mess)
        if received_mess.split()[0] == 'REGISTER':
            if self.check_request(received_mess):
                clt_sip = received_mess.split()[1].split(':')[1]
                clt_port = int(received_mess.split()[1].split(':')[2])
                expires_time = float(received_mess.split()[4])
                if len(received_mess.split()) == 5:
                    if clt_sip in self.dict_Nonce:
                        nonce = self.dict_Nonce[clt_sip]
                    else:
                        nonce = random.randint(10**19, 10**20)
                        self.dict_Nonce[clt_sip] = nonce
                    mess = UNAUTHORIZED[:-2]
                    mess += b'WWW Authenticate: Digest nonce="'
                    mess += bytes(str(nonce), 'utf-8') + b'"\r\n\r\n'
                    self.wfile.write(mess)
                    log.senting(self.client_address[0], self.client_address[1],
                                mess.decode())
                elif len(received_mess.split()) == 8:
                    clt_digest = received_mess.split()[7].split('"')[1]
                    digest = self.get_digest(clt_sip)
                    if clt_digest == digest:
                        if expires_time > 0:
                            expires_time = expires_time + time.time()
                            expires_time = time.gmtime(expires_time)
                            format = '%Y-%m-%d %H:%M:%S'
                            expires_time = time.strftime(format, expires_time)
                            self.add_user(clt_sip, expires_time, clt_port)
                        elif expires_time == 0:
                            self.del_user(clt_sip)
                    else:
                        mess = UNAUTHORIZED[:-2]
                        mess += b'WWW Authenticate: Digest nonce="'
                        mess += bytes(str(nonce), 'utf-8') + b'"\r\n\r\n'
                        self.wfile.write(mess)
                        log.senting(self.client_address[0],
                                    self.client_address[1],
                                    mess.decode())
            else:
                self.wfile.write(BAD_REQUEST)
                log.senting(self.client_address[0], self.client_address[1],
                            BAD_REQUEST.decode())

        elif received_mess.split()[0] == 'INVITE' or 'BYE' or 'ACK':
            user_address = received_mess.split()[1].split(':')[1]
            if user_address in self.dict_Users:
                self.re_send(user_address, received_mess)
            else:
                self.wfile.write(NOT_FOUND)
                log.senting(self.client_address[0], self.client_address[1],
                            NOT_FOUND.decode())
        else:
            self.wfile.write(NOT_ALLOWED)
            log.senting(self.client_address[0], self.client_address[1],
                        NOT_ALLOWED.decode())


if __name__ == "__main__":

    parser = make_parser()
    cHandler = XMLHandler()
    checkIP = CheckIP()
    parser.setContentHandler(cHandler)
    # Pick config of keyboard and fich.
    # Listens at address in a port defined by the user
    # and calls the SIPRegisterProxyHandler class to manage the request
    try:
        CONFIG = sys.argv[1]
        parser.parse(open(CONFIG))
        SERVER_NAME = cHandler.config['server_name']
        server_ip = cHandler.config['server_ip']
        SERVER_PORT = int(cHandler.config['server_port'])
        DATA_USERS = cHandler.config['database_path']
        DATA_PASSWD = cHandler.config['database_passwdpath']
        FICH_LOG = cHandler.config['log_path']
        if server_ip == '' or server_ip == 'localhost':
            server_ip = '127.0.0.1'
        if not checkIP.check_ip(server_ip):
            sys.exit('Invalid IP addess in config file')
        serv = socketserver.UDPServer((server_ip, SERVER_PORT),
                                      SIPRegisterProxyHandler)
        log = WriterLog()
    except (IndexError, ValueError, FileNotFoundError):
        sys.exit('Usage: python3 proxy_registar.py config.')
    except OSError:
        sys.exit('Address already in use')

    try:
        print('Server ' + SERVER_NAME + ' listening at port ' +
              str(SERVER_PORT) + '...')
        log.starting()
        serv.serve_forever()
    except KeyboardInterrupt:
        log.finishing()
        print('  Server interrupt')
