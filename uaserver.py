#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Class (and main program) for echo register server in UDP simple."""

import socketserver
import sys
import os
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from proxy_registar import XMLHandler, WriterLog, CheckIP


TRYNING = b'SIP/2.0 100 Trying\r\n\r\n'
RING = b'SIP/2.0 180 Ring\r\n\r\n'
OK = b'SIP/2.0 200 OK\r\n\r\n'
BAD_REQUEST = b'SIP/2.0 400 Bad Request\r\n\r\n'
NOT_ALLOWED = b'SIP/2.0 405 Method Not Allowed\r\n\r\n'


class EchoHandler(socketserver.DatagramRequestHandler):
    """Echo handler server class."""

    correct = True
    dict_RTP = {}

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

        if mess.split()[0] == 'INVITE':
            try:
                user = mess.split()[1]
                sip = mess.split()[2]
                content_type = mess.split()[3]
                app = mess.split()[4]
                version = mess.split()[5]
                organizer = mess.split()[6]
                ip = mess.split()[7]
                sesion = mess.split()[8]
                time_sesion = mess.split()[9]
                mult = mess.split()[10]
                int(mess.split()[11])
                rtp = mess.split()[12]
            except (IndexError, ValueError):
                self.correct = False

            if not checkIP.check_ip(ip):
                self.correct = False
            if len(mess.split()) != 13:
                self.correct = False
            if not user.startswith('sip:'):
                    self.correct = False
            else:
                at = 0
                for character in user.split(':')[1]:
                    if character not in valid_characters:
                        self.correct = False
                    if character == '@':
                        at = at + 1
                if at != 1:
                    self.correct = False
            if sip != 'SIP/2.0':
                self.correct = False
            if content_type != 'Content-Type:':
                self.correct = False
            if app != 'application/sdp':
                self.correct = False
            if version != 'v=0':
                self.correct = False
            if not organizer.startswith('o='):
                self.correct = False
            else:
                at = 0
                for character in organizer.split('=')[1]:
                    if character not in valid_characters:
                        self.correct = False
                    if character == '@':
                        at = at + 1
                if at != 1:
                    self.correct = False
            if not sesion.startswith('s='):
                self.correct = False
            else:
                for character in sesion.split('=')[1]:
                    if character not in valid_characters:
                        self.correct = False
            if mult != 'm=audio':
                self.correct = False
            if rtp != 'RTP':
                self.correct = False

        if mess.split()[0] == ('ACK', 'BYE'):
            try:
                user = mess.split()[1]
                version = mess.split()[2]
            except IndexError:
                self.correct = False

            if len(mess.split()) != 3:
                self.correct = False
            if not user.startswith('sip:'):
                    self.correct = False
            else:
                at = 0
                for character in user.split(':')[1]:
                    if character not in valid_characters:
                        self.correct = False
                    if character == '@':
                        at = at + 1
                if at != 1:
                    self.correct = False
            if version != 'SIP/2.0':
                self.correct = False
        return self.correct

    def handle(self):
        """Handle method of the server class."""
        received_mess = []
        for line in self.rfile:
            received_mess.append(line.decode('utf-8'))
        received_mess = ''.join(received_mess)
        log.received(self.client_address[0], self.client_address[1],
                     received_mess)
        if self.check_request(received_mess):
            if received_mess.split()[0] == 'INVITE':
                    organizer_ip = received_mess.split()[7]
                    organizer_port = received_mess.split()[11]
                    self.dict_RTP['1'] = (organizer_ip, organizer_port)
                    self.wfile.write(TRYNING)
                    log.senting(self.client_address[0], self.client_address[1],
                                TRYNING.decode())
                    self.wfile.write(RING)
                    log.senting(self.client_address[0], self.client_address[1],
                                RING.decode())
                    self.wfile.write(OK)
                    log.senting(self.client_address[0], self.client_address[1],
                                OK.decode())
                    SDP = ('Content-Type: application/sdp\r\n\r\n' +
                           'v=0\r\n' + 'o=' + LOGIN + ' ' + server_ip +
                           '\r\n' + 's=avengers_assemmble\r\n' + 't=0\r\n' +
                           'm=audio ' + str(RTP_PORT) + ' RTP\r\n\r\n')
                    self.wfile.write(bytes(SDP, 'utf-8'))
                    log.senting(self.client_address[0], self.client_address[1],
                                SDP)
            elif received_mess.split()[0] == 'BYE':
                self.wfile.write(OK)
                log.senting(self.client_address[0], self.client_address[1],
                            OK.decode())
            elif received_mess.split()[0] == 'ACK':
                organizer_ip = self.dict_RTP['1'][0]
                organizer_port = self.dict_RTP['1'][1]
                ToRun = './mp32rtp -i ' + organizer_ip + ' -p '
                ToRun += organizer_port
                ToRun += ' < ' + MEDIA
                print('Running: ', ToRun)
                log.senting_rtp(organizer_ip, organizer_port, MEDIA)
                os.system(ToRun)
            else:
                self.wfile.write(NOT_ALLOWED)
                log.senting(self.client_address[0], self.client_address[1],
                            NOT_ALLOWED.decode())
        else:
            self.wfile.write(BAD_REQUEST)
            log.senting(self.client_address[0], self.client_address[1],
                        BAD_REQUEST.decode())


if __name__ == "__main__":
    parser = make_parser()
    cHandler = XMLHandler()
    checkIP = CheckIP()
    parser.setContentHandler(cHandler)
    # Pick config of keyboard and fich.
    # Listens at address in a port defined by the user
    # and calls the EchoHandler class to manage the request
    try:
        CONFIG = sys.argv[1]
        parser.parse(open(CONFIG))
        LOGIN = cHandler.config['account_username']
        server_ip = cHandler.config['uaserver_ip']
        SERVER_PORT = int(cHandler.config['uaserver_port'])
        RTP_PORT = int(cHandler.config['rtpaudio_port'])
        proxy_ip = cHandler.config['regproxy_ip']
        PROXY_PORT = int(cHandler.config['regproxy_port'])
        FICH_LOG = cHandler.config['log_path']
        MEDIA = cHandler.config['audio_path']
        if proxy_ip == '' or proxy_ip == 'localhost':
            proxy_ip = '127.0.0.1'
        if server_ip == '' or server_ip == 'localhost':
            server_ip = '127.0.0.1'
        if not checkIP.check_ip(proxy_ip):
            sys.exit('Invalid IP addess in config file')
        if not checkIP.check_ip(server_ip):
            sys.exit('Invalid IP addess in config file')
        log = WriterLog()
        serv = socketserver.UDPServer((server_ip, SERVER_PORT),
                                      EchoHandler)
    except (IndexError, ValueError):
        sys.exit('Usage: python uaserver.py config')
    except OSError:
        sys.exit('Address already in use')

    try:
        print('Listening...')
        log.starting()
        serv.serve_forever()
    except KeyboardInterrupt:
        log.finishing()
        print('  Server interrupt')
