# client.py
import socket
import os

SOCKET_PATH = '/tmp/echo.sock'

# Create a UDS (Unix Domain Socket)
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

# Connect the socket to the address
print(f'Connecting to {SOCKET_PATH}')
sock.connect(SOCKET_PATH)

# Enable the sending of credentials
sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

# Send a message
message = b'scm_credentials'
sock.sendall(message)

# Cleanup
sock.close()
