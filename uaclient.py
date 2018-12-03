#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""UA Client UDP implement a socket to a register server."""

import socket
import sys

# UA Client UDP simple.

# Pick config, method and option of keyboard.
try:
    CONFIG = sys.argv[1]
    METHOD = sys.argv[2]
    OPTION = sys.argv[3]
except (IndexError, ValueError):
    sys.exit('Usage: aclient.py config method option')

def register():
    print('lo del register')

# Content to send
try:
    if METHOD = 'REGISTER':
        register()
    elif METHOD = 'INVITE':
        print('lo del invite')
    elif METHOD = 'BYE':
        print('lo del bye')
    else:
        exit('Usage: method not avaleible')
except (IndexError, ValueError):
    exit('Usage: aclient.py config method option')


# Create the socket, configure it and attach it to server/port
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((SERVER, PORT))

    print('Sending: ' + LINE)
    my_socket.send(bytes(LINE, 'utf-8') + b'\r\n')
    data = my_socket.recv(1024)
    response = data.decode('utf-8')
    print(response)
    if response.split()[1] == '100':
        ack = 'ACK sip:' + LOGIN + '@' + SERVER + ' SIP/2.0\r\n'
        my_socket.send(bytes(ack, 'utf-8') + b'\r\n')
        print('Sending: ' + ack)
    print('Ending socket...')

print('Socket done.')
