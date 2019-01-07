#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""UA Client UDP implement a socket to a register server."""

import socket
import sys
import os
import socketserver
import hashlib
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from proxy_registar import XMLHandler

# UA Client UDP simple.
header = []
PSW = 'hacer aqui lo del response con el nonce'

# procedure to send messages
def send_mess(Request, header):
    print('Sending: ' + Request)
    my_socket.send(bytes(Request, 'utf-8'))
    for item in range(len(header)):
        print('Sending: ' + header[item])
        my_socket.send(bytes(header[item], 'utf-8'))

def send_rtp(server_ip, server_port):
    ToRun = 'mp32rtp -i ' + server_ip + ' -p' + server_port + ' < ' + MEDIA
    print('Running: ', ToRun)
    os.system(ToRun)


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

    except (IndexError, ValueError, FileNotFoundError):
        sys.exit('Usage: uaclient.py config method option')

    LOGIN = cHandler.config['account_username']
    PASSWD = cHandler.config['account_passwd']
    MY_IP = cHandler.config['uaserver_ip']
    MY_PORT = int(cHandler.config['uaserver_port'])
    RTP_PORT = int(cHandler.config['rtpaudio_port'])
    PROXY_IP = cHandler.config['regproxy_ip']
    PROXY_PORT = int(cHandler.config['regproxy_port'])
    FICH_LOG = cHandler.config['log_path']
    MEDIA = cHandler.config['audio_path']

    #Sending first messages

    if METHOD == 'REGISTER':
        Request = 'REGISTER sip:' + LOGIN + ':' + str(MY_PORT) + ' SIP/2.0\r\n\r\n'
        header.append('Expires: ' + OPTION + '\r\n\r\n')
    elif METHOD == 'INVITE':
        Request = 'INVITE sip:' + OPTION + ' SIP/2.0\r\n\r\n'
        header.append('Content-Type: application/sdp\r\n\r\n')
        header.append('v=0\r\n')
        header.append('o=' + LOGIN + ' ' + MY_IP + '\r\n')
        header.append('s=avengers_assemmble\r\n')
        header.append('t=0\r\n')
        header.append('m=audio ' + str(RTP_PORT) + ' RTP\r\n\r\n')
    elif METHOD == 'BYE':
        Request = 'BYE sip:' + OPTION + ' SIP/2.0\r\n\r\n'
    else:
        exit('Usage: method not avaleible')

    # Create the socket, configure it and attach it to server/port
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((PROXY_IP, PROXY_PORT))
        send_mess(Request, header)

        data = my_socket.recv(1024)
        response = data.decode('utf-8')
        print(response)
        if response.split()[1] == '401':   #probar lo de las respuestas estas de gregorio
            nonce = response[6].split("=")[1]
            h = hashlib.sha1(bytes(PASSWD + '\n', 'utf-8'))
            h.update(bytes(nonce,'utf-8'))
            digest = h.hexdigest()
            header = []
            Request = 'REGISTER sip:' + LOGIN + ':' + MY_PORT + ' SIP/2.0\r\n\r\n'
            header.append('Expires: ' + OPTION + '\r\n\r\n')
            header.append('Authorization: Digest response="' + digest + '"\r\n\r\n')
            send_mess(Request, header)
        if response.split()[1] == '200':
            header = [] #ESTO BORRA LA LISTA?
            Request = 'ACK sip:' + OPTION + ' SIP/2.0\r\n\r\n'
            send_mess(Request, header)
        if response.split()[1] == '100':
            if response.split()[4] == '180':
                if response.split()[7] == '200':
                    #NO SE COMO VA EXACTAMENTE LO DEL SDP DE RESPUESTA
                    server_name = response.split()[12].split('=')[1]
                    server_ip = response.split()[13]
                    server_port = response.split()[17]
                    send_rtp(server_ip, server_port)

        print('Ending socket...')

    print('Socket done.')
