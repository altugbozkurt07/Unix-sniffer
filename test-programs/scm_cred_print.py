##!/usr/bin/env python3

"""
Echo peercreds in connections to a UNIX domain socket
"""

import socket
import struct

def main():
    """Echo UNIX peercreds"""
    listen_sock = '/tmp/echo.sock'
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(listen_sock)
    sock.listen()

    while True:
        print('waiting for a connection')
        connection = sock.accept()[0]
        peercred = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                         struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", peercred)

        print("PID: {}, UID: {}, GID: {}".format(pid, uid, gid))

        continue

if __name__ == '__main__':
    main()
