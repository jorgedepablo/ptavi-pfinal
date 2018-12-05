#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""UA Client UDP implement a socket to a register server."""

import socket
import sys
import socketserver
import time

# UA Client UDP simple.

# Pick config, method and option of keyboard.
try:
    CONFIG = sys.argv[1]
    METHOD = sys.argv[2]
    OPTION = sys.argv[3]
except (IndexError, ValueError):
    sys.exit('Usage: aclient.py config method option')

header = []

def register(authentication):
    REQUEST = 'REGISTER sip:' + LOGIN + ':' + PORT  + ' SIP/2.0\r\n\r\n')
    header[0] = 'Expires: ' OPTION + '\r\n\r\n'
    if authentication:
        header[1] = 'Authorization: Digest response="' + PSW + '"\r\n\r\n'

def invite():
    print('lo del invite')

def bye():
    print('lo del bye')

# Content to send
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

def send_cosas: 
    print('Sending: ' + REQUEST)
    my_socket.send(bytes(REQUEST, 'utf-8'))
    for item in range(len(header)):
        print('Sending: ' + header[item])
        my_socket.send(bytes(header[item], 'utf-8'))

# Create the socket, configure it and attach it to server/port
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((SERVER, PORT))


    DATA = my_socket.recv(1024)
    RESPONSE = data.decode('utf-8')
    print(RESPONSE)
    if RESPONSE.split()[1] == '401':
        authentication = True
        register(authentication)
    print('Ending socket...')

print('Socket done.')
