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
from proxy_registar import XMLHandler, WriterLog, CheckIP


TRYNING = 'SIP/2.0 100 Trying'
RING = 'SIP/2.0 180 Ring'
OK = 'SIP/2.0 200 OK'
UNAUTHORIZED = 'SIP/2.0 401 Unauthorized'


def send_mess(Request):
    """Procedure to send messages."""
    Request = ''.join(Request)
    my_socket.send(bytes(Request, 'utf-8'))
    log.senting(proxy_ip, PROXY_PORT, Request)


def send_rtp(server_ip, server_port):
    """Procedure to send media by RTP."""
    ToRun = './mp32rtp -i ' + server_ip + ' -p ' + server_port
    ToRun += ' < ' + MEDIA
    ToListen = 'cvlc rtp://@' + server_ip + ':' + server_port + '&'
    print('Running: ', ToRun)
    log.senting_rtp(server_ip, server_port, MEDIA)
    os.system(ToListen)
    os.system(ToRun)


if __name__ == '__main__':
    parser = make_parser()
    cHandler = XMLHandler()
    checkIP = CheckIP()
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
    my_ip = cHandler.config['uaserver_ip']
    MY_PORT = int(cHandler.config['uaserver_port'])
    RTP_PORT = int(cHandler.config['rtpaudio_port'])
    proxy_ip = cHandler.config['regproxy_ip']
    PROXY_PORT = int(cHandler.config['regproxy_port'])
    FICH_LOG = cHandler.config['log_path']
    MEDIA = cHandler.config['audio_path']
    Request = []
    if proxy_ip == '' or proxy_ip == 'localhost':
        proxy_ip = '127.0.0.1'
    if my_ip == '' or my_ip == 'localhost':
        my_ip = '127.0.0.1'
    if not checkIP.check_ip(proxy_ip) or not checkIP.check_ip(my_ip):
        sys.exit('Invalid IP addess in config file')
    log = WriterLog()
    log.starting()
    # Forming first request
    if METHOD == 'REGISTER':
        Request.append('REGISTER sip:' + LOGIN + ':' + str(MY_PORT) +
                       ' SIP/2.0\r\n')
        Request.append('Expires: ' + OPTION + '\r\n\r\n')
    elif METHOD == 'INVITE':
        Request.append('INVITE sip:' + OPTION + ' SIP/2.0\r\n')
        Request.append('Content-Type: application/sdp\r\n\r\n')
        Request.append('v=0\r\n')
        Request.append('o=' + LOGIN + ' ' + my_ip + '\r\n')
        Request.append('s=avengers_assemmble\r\n')
        Request.append('t=0\r\n')
        Request.append('m=audio ' + str(RTP_PORT) + ' RTP\r\n\r\n')
    elif METHOD == 'BYE':
        Request.append('BYE sip:' + OPTION + ' SIP/2.0\r\n\r\n')
    else:
        log.finishing()
        exit('Usage: method not avaleible')

    # Create the socket, configure it and attach it to server/port
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        try:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                 1)
            my_socket.connect((proxy_ip, PROXY_PORT))
            send_mess(Request)
        except ConnectionRefusedError:
            log.conexion_refused(proxy_ip, PROXY_PORT)
            log.finishing()
            exit('Error: No server listening at ' + proxy_ip +
                 ' port ' + str(PROXY_PORT))
        # Reciving response, and reply with a new response (if applicable)
        data = my_socket.recv(1024)
        response = data.decode('utf-8')
        log.received(proxy_ip, PROXY_PORT, response)

        if response.split('\r\n')[0] == UNAUTHORIZED:
            nonce = response.split('"')[1]
            h = hashlib.sha1(bytes(PASSWD + '\n', 'utf-8'))
            h.update(bytes(nonce, 'utf-8'))
            digest = h.hexdigest()
            Request = []
            Request.append('REGISTER sip:' + LOGIN + ':' + str(MY_PORT) +
                           ' SIP/2.0\r\n\r\n')
            Request.append('Expires: ' + OPTION + '\r\n')
            Request.append('Authorization: Digest response="' + digest +
                           '"\r\n\r\n')
            send_mess(Request)
            data = my_socket.recv(1024)
            response = data.decode('utf-8')
            log.received(proxy_ip, PROXY_PORT, response)
        elif response.split('\r\n')[0] == TRYNING:
            if response.split('\r\n')[2] == RING:
                if response.split('\r\n')[4] == OK:
                    Request = []
                    Request.append('ACK sip:' + OPTION + ' SIP/2.0\r\n\r\n')
                    send_mess(Request)
                    server_name = response.split()[12].split('=')[1]
                    organizer_ip = response.split()[13]
                    organizer_port = response.split()[17]
                    send_rtp(organizer_ip, organizer_port)
        print('Ending socket...')
    log.finishing()
    print('Socket done.')
