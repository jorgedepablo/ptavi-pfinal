#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""UA Client UDP implement a socket to a register server."""

import socket
import sys
import socketserver
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from proxy_registar import XMLHandler

# UA Client UDP simple.
header = []
PSW = 'hacer aqui lo del response con el nonce'
# Content to send
def register(authentication):
    Request = 'REGISTER sip:' + LOGIN + ':' + MY_PORT  + ' SIP/2.0\r\n\r\n'
    header[0] = 'Expires: ' + OPTION + '\r\n\r\n'
    if authentication:
        header[1] = 'Authorization: Digest response="' + PSW + '"\r\n\r\n'

def invite():
    Request = 'INVITE sip:' + LOGIN + 'SIP/2.0\r\n\r\n'
    header[0] = 'Content-Type: application/sdp\r\n\r\n'
    header[1] = 'v=0\r\n\r\n'
    header[2] = 'o=' + OPTION + ' ' + PROXY_IP + '\r\n\r\n'
    header[3] = 's=misesion\r\n\r\n'
    header[4] = 't=0\r\n\r\n'
    header[5] = 'm=audio ' + PROXY_PORT + ' RTP\r\n\r\n'

def ack():
    header = [] #ESTO BORRA LA LISTA?
    Request = 'ACK sip:' + LOGIN + ' SIP/2.0\r\n\r\n'

def bye():
    Request = 'BYE sip:' + LOGIN + ' SIP/2.0\r\n\r\n'

# procedure to send messages
def send_mess(Request, header):
    print('Sending: ' + Request)
    my_socket.send(bytes(Request, 'utf-8'))
    for item in range(len(header)):
        print('Sending: ' + header[item])
        my_socket.send(bytes(header[item], 'utf-8'))


if __name__ == '__main__':
    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    # Pick config, method and option of keyboard.
    try:
        CONFIG = sys.argv[1]
        METHOD = sys.argv[2]
        OPTION = sys.argv[3]
        parser.parse(open(CONFIG))
        #LOGIN = cHandler.config
    except (IndexError, ValueError, FileNotFoundError):
        sys.exit('Usage: aclient.py config method option')

    try:
        if METHOD == 'REGISTER':
            authentication = False
            register(authentication)
        elif METHOD == 'INVITE':
            invite()
        elif METHOD == 'BYE':
            bye()
        else:
            exit('Usage: method not avaleible')
    except (IndexError, ValueError):
        exit('Usage: aclient.py config method option')

    # Create the socket, configure it and attach it to server/port
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((PROXY_IP, PROXY_PORT))
        send_mess(Request, header)

        DATA = my_socket.recv(1024)
        RESPONSE = data.decode('utf-8')
        print(RESPONSE)
        if RESPONSE.split()[1] == '401':   #probar lo de las respuestas estas de gregorio
            authentication = True
            register(authentication)
            send_mess(Request, header)
        if RESPONSE.split()[1] == '100':
            ack()
            send_mess(Request, header)
        print('Ending socket...')

    print('Socket done.')
