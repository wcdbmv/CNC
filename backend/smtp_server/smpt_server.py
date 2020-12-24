#! /usr/bin/env python3

import asyncore
import socket
import sys
import time

from typing import Tuple, Union
from .smpt_stream import SmtpStream


Addr = Tuple[Union[str, int], Union[str, int]]


class SmtpServer(asyncore.dispatcher):
    stream_class = SmtpStream

    def __init__(self, local_addr: Addr, remote_addr: Addr, data_size_limit: int = SmtpStream.DATA_SIZE_DEFAULT,
                 map_=None, decode_data: bool = False):
        super().__init__(map=map_)

        self._local_addr = local_addr
        self._remote_addr = remote_addr
        self._data_size_limit = data_size_limit
        self._decode_data = decode_data

        try:
            getaddrinfo_results = socket.getaddrinfo(*local_addr, type=socket.SOCK_STREAM)
            self.create_socket(getaddrinfo_results[0][0], getaddrinfo_results[0][1])
            self.set_reuse_addr()
            self.bind(local_addr)
            self.listen(5)
        except Exception:
            self.close()
            raise
        else:
            print(f'{self.__class__.__name__} started at {time.ctime(time.time())}\n'
                  f'\tLocal addr: {local_addr}\n'
                  f'\tRemote addr:{remote_addr}',
            file=sys.stderr)

    def handle_accepted(self, conn, addr):
        print(f'Incoming connection from {repr(addr)}', file=sys.stderr)
        self.stream_class(self,
                          conn,
                          self._data_size_limit,
                          self._map,
                          self._decode_data)

    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        """Необходимо перегрузить эту функцию"""
        raise NotImplementedError
