#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Class (and main program) for echo register server in UDP simple."""

import socketserver
import sys
import os
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from proxy_registar import XMLHandler


TRYNING = b'SIP/2.0 100 Trying\r\n\r\n'
RING = b'SIP/2.0 180 Ring\r\n\r\n'
OK = b'SIP/2.0 200 OK\r\n\r\n'
BAD_REQUEST = b'SIP/2.0 400 Bad Request\r\n\r\n'
UNAUTHORIZED = b'SIP/2.0 401 Unauthorized\r\n\r\n'
NOT_FOUND = b'SIP/2.0 404 User Not Found\r\n\r\n'
NOT_ALLOWED = b'SIP/2.0 405 Method Not Allowed\r\n\r\n'


class EchoHandler(socketserver.DatagramRequestHandler):

    correct = True
    #ESTA PARTE REPASASR CUANDO ACABE PRINCIPAR
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
        for line in self.rfile:
            received_mess.append(line.decode('utf-8'))
        received_mess = ''.join(received_mess).split()
        if received_mess[0] == 'INVITE':
            if received_mess[7].startswith('o='):
                organizer = received_mess[7].split('=')[1]
                organizer_ip = received_mess[8]
                if received_mess[11] == 'm=audio':
                    organizer_port = int(received_mess[12])
                    self.wfile.write(TRYNING)
                    self.wfile.write(RING)
                    self.wfile.write(OK)
                    #este sdp es diferente?? con otro organizador y todo? no se deberia unir a esa sesion??
                    SDP = ('Content-Type: application/sdp\r\n\r\n' + 'v=0\r\n' +
                           'o=' + LOGIN + ' ' + SERVER_IP + '\r\n' +
                           's=avengers_assemmble\r\n' + 't=0\r\n' + 'm=audio ' +
                           str(RTP_PORT) + ' RTP\r\n\r\n')
                    self.wfile.write(b'SDP')
                    print(TRYNING + RING + OK + SDP)
        elif received_mess[0] == 'BYE':
            self.wfile.write(OK)
            print(OK)
        elif received_mess[0] == 'ACK':
            ToRun = 'mp32rtp -i ' + organizer_ip + ' -p' + organizer_port + ' < ' + MEDIA
            print('Running: ', ToRun)
            os.system(ToRun)
        else:
            self.wfile.write(NOT_ALLOWED)
            print(NOT_ALLOWED)


if __name__ == "__main__":
    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    try:
        CONFIG = sys.argv[1]
        parser.parse(open(CONFIG))
        LOGIN = cHandler.config['account_username']
        PASSWD = cHandler.config['account_passwd']
        SERVER_IP = cHandler.config['uaserver_ip']
        SERVER_PORT = int(cHandler.config['uaserver_port'])
        RTP_PORT = int(cHandler.config['rtpaudio_port'])
        PROXY_IP = cHandler.config['regproxy_ip']
        PROXY_PORT = int(cHandler.config['regproxy_port'])
        FICH_LOG = cHandler.config['log_path']
        MEDIA = cHandler.config['audio_path']
    except (IndexError, ValueError):
        sys.exit('Usage: python uaserver.py config')

    """Create echo server and listening."""
    #AQUI NO SE QUIEN ESCUCHA O ENVIA, DUDAS PREGUNTAR
    serv = socketserver.UDPServer((SERVER_IP, SERVER_PORT), EchoHandler)
    print('Listening...')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('  Server interrupt')
