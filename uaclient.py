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
from proxy_registar import XMLHandler, WriterLog

# Procedure to send messages
def send_mess(Request):
    Request = ''.join(Request)
    my_socket.send(bytes(Request, 'utf-8'))
    log.senting(PROXY_IP, PROXY_PORT, Request)

def send_rtp(server_ip, server_port):
    ToRun = 'mp32rtp -i ' + server_ip + ' -p ' + server_port + ' < ' + MEDIA
    print('Running: ', ToRun)
    os.system(ToRun)


if __name__ == '__main__':
    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    # Pick config of keyboard and fich.
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
    Request = []
    log = WriterLog()
    log.starting()
    # Forming first request
    if METHOD == 'REGISTER':
        Request.append('REGISTER sip:' + LOGIN + ':' + str(MY_PORT) +
                       ' SIP/2.0\r\n')
        Request.append('Expires: ' + OPTION + '\r\n')
    elif METHOD == 'INVITE':
        Request.append('INVITE sip:' + OPTION + ' SIP/2.0\r\n')
        Request.append('Content-Type: application/sdp\r\n\r\n')
        Request.append('v=0\r\n')
        Request.append('o=' + LOGIN + ' ' + MY_IP + '\r\n')
        Request.append('s=avengers_assemmble\r\n')
        Request.append('t=0\r\n')
        Request.append('m=audio ' + str(RTP_PORT) + ' RTP\r\n')
    elif METHOD == 'BYE':
        Request.append('BYE sip:' + OPTION + ' SIP/2.0\r\n')
    else:
        log.finishing()
        exit('Usage: method not avaleible')

    # Create the socket, configure it and attach it to server/port
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        try:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                 1)
            my_socket.connect((PROXY_IP, PROXY_PORT))
            send_mess(Request)
        except ConnectionRefusedError:
            log.conexion_refused(PROXY_IP, PROXY_PORT)
            log.finishing()
            exit('Error: No server listening at ' + PROXY_IP +
                 ' port ' + str(PROXY_PORT))
        # Reciving response, and asking with a new response (if applicable)
        data = my_socket.recv(1024)
        response = data.decode('utf-8')
        log.received(PROXY_IP, PROXY_PORT, response)
        if response.split()[1] == '401':
            nonce = response.split('"')[1]
            h = hashlib.sha1(bytes(PASSWD + '\n', 'utf-8'))
            h.update(bytes(nonce,'utf-8'))
            digest = h.hexdigest()
            Request = []
            Request.append('REGISTER sip:' + LOGIN + ':' + str(MY_PORT) +
                           ' SIP/2.0\r\n')
            Request.append('Expires: ' + OPTION + '\r\n')
            Request.append('Authorization: Digest response="' + digest +
                           '"\r\n')
            send_mess(Request)
        elif response.split()[1] == '100':
            if response.split()[4] == '180':
                if response.split()[7] == '200':
                    Request = []
                    Request.append('ACK sip:' + OPTION + ' SIP/2.0\r\n')
                    send_mess(Request)
                    server_name = response.split()[12].split('=')[1]
                    server_ip = response.split()[13]
                    server_port = response.split()[17]
                    send_rtp(server_ip, server_port)
        print('Ending socket...')
        log.finishing()
    print('Socket done.')
