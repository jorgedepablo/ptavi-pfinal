#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""UA Client UDP implement a socket to a register server."""

import socket
import sys
import os
import hashlib
from xml.sax import make_parser
from proxy_registar import XMLHandler, WriterLog, CheckIP


TRYNING = 'SIP/2.0 100 Trying'
RING = 'SIP/2.0 180 Ring'
OK = 'SIP/2.0 200 OK'
UNAUTHORIZED = 'SIP/2.0 401 Unauthorized'


def send_mess(request):
    """Procedure to send messages."""
    request = ''.join(request)
    my_socket.send(bytes(request, 'utf-8'))
    LOG.senting(PROXY_IP, PROXY_PORT, request)


def send_rtp(server_ip, server_port):
    """Procedure to send media by RTP."""
    to_run = './mp32rtp -i ' + server_ip + ' -p ' + server_port
    to_run += ' < ' + MEDIA
    to_listen = 'cvlc rtp://@' + server_ip + ':' + server_port + '&'
    print('Running: ', to_run)
    LOG.senting_rtp(server_ip, server_port, MEDIA)
    os.system(to_listen)
    os.system(to_run)


if __name__ == '__main__':
    PARSER = make_parser()
    CHANDLER = XMLHandler()
    CHECKIP = CheckIP()
    PARSER.setContentHandler(CHANDLER)
    request = []
    # Pick config of keyboard and fich.
    try:
        CONFIG = sys.argv[1]
        METHOD = sys.argv[2]
        OPTION = sys.argv[3]
        PARSER.parse(open(CONFIG))
    except (IndexError, ValueError):
        sys.exit('Usage: uaclient.py config method option')

    LOGIN = CHANDLER.config['account_username']
    PASSWD = CHANDLER.config['account_passwd']
    MY_IP = CHANDLER.config['uaserver_ip']
    MY_PORT = int(CHANDLER.config['uaserver_port'])
    RTP_PORT = int(CHANDLER.config['rtpaudio_port'])
    PROXY_IP = CHANDLER.config['regproxy_ip']
    PROXY_PORT = int(CHANDLER.config['regproxy_port'])
    FICH_LOG = CHANDLER.config['log_path']
    MEDIA = CHANDLER.config['audio_path']

    if PROXY_IP == '' or PROXY_IP == 'localhost':
        PROXY_IP = '127.0.0.1'
    if MY_IP == '' or MY_IP == 'localhost':
        MY_IP = '127.0.0.1'
    if not CHECKIP.check_ip(PROXY_IP) or not CHECKIP.check_ip(MY_IP):
        sys.exit('Invalid IP addess in config file')
    LOG = WriterLog()
    LOG.starting()
    # Forming first request
    if METHOD == 'REGISTER':
        request.append('REGISTER sip:' + LOGIN + ':' + str(MY_PORT) +
                       ' SIP/2.0\r\n')
        request.append('Expires: ' + OPTION + '\r\n\r\n')
    elif METHOD == 'INVITE':
        request.append('INVITE sip:' + OPTION + ' SIP/2.0\r\n')
        request.append('Content-Type: application/sdp\r\n\r\n')
        request.append('v=0\r\n')
        request.append('o=' + LOGIN + ' ' + MY_IP + '\r\n')
        request.append('s=avengers_assemmble\r\n')
        request.append('t=0\r\n')
        request.append('m=audio ' + str(RTP_PORT) + ' RTP\r\n\r\n')
    elif METHOD == 'BYE':
        request.append('BYE sip:' + OPTION + ' SIP/2.0\r\n\r\n')
    else:
        LOG.finishing()
        exit('Usage: method not avaleible')

    # Create the socket, configure it and attach it to server/port
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        try:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                 1)
            my_socket.connect((PROXY_IP, PROXY_PORT))
            send_mess(request)
            DATA = my_socket.recv(1024)
            RESPONSE = DATA.decode('utf-8')
            LOG.received(PROXY_IP, PROXY_PORT, RESPONSE)
        except OSError:
            LOG.conexion_refused(PROXY_IP, PROXY_PORT)
            LOG.finishing()
            sys.exit('Error: No server listening at ' + PROXY_IP +
                     ' port ' + str(PROXY_PORT))
        # Reciving response, and reply with a new response (if applicable)

        if RESPONSE.split('\r\n')[0] == UNAUTHORIZED:
            NONCE = RESPONSE.split('"')[1]
            H = hashlib.sha1(bytes(PASSWD + '\n', 'utf-8'))
            H.update(bytes(NONCE, 'utf-8'))
            DIGEST = H.hexdigest()
            request = []
            request.append('REGISTER sip:' + LOGIN + ':' + str(MY_PORT) +
                           ' SIP/2.0\r\n\r\n')
            request.append('Expires: ' + OPTION + '\r\n')
            request.append('Authorization: Digest response="' + DIGEST +
                           '"\r\n\r\n')
            send_mess(request)
            DATA = my_socket.recv(1024)
            RESPONSE = DATA.decode('utf-8')
            LOG.received(PROXY_IP, PROXY_PORT, RESPONSE)
        elif RESPONSE.split('\r\n')[0] == TRYNING:
            if RESPONSE.split('\r\n')[2] == RING:
                if RESPONSE.split('\r\n')[4] == OK:
                    request = []
                    request.append('ACK sip:' + OPTION + ' SIP/2.0\r\n\r\n')
                    send_mess(request)
                    ORGANIZER_IP = RESPONSE.split()[13]
                    ORGANIZER_PORT = RESPONSE.split()[17]
                    send_rtp(ORGANIZER_IP, ORGANIZER_PORT)
        print('Ending socket...')
    LOG.finishing()
    print('Socket done.')
