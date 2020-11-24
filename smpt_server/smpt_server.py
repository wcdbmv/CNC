#! /usr/bin/env python3
"""An RFC 5321 smtp server with optional RFC 1870 and RFC 6531 extensions.

Options:

    --nosetuid
    -n
        This program generally tries to setuid `nobody', unless this flag is
        set.  The setuid call will fail if this program is not run as root (in
        which case, use this flag).

    --version
    -V
        Print the version number and exit.

    --class classname
    -c classname
        Use `classname' as the concrete SMTP proxy class.  Uses `PureProxy' by
        default.

    --size limit
    -s limit
        Restrict the total size of the incoming message to "limit" number of
        bytes via the RFC 1870 SIZE extension.  Defaults to 30000000 bytes.

    --smtputf8
    -u
        Enable the SMTPUTF8 extension and behave as an RFC 6531 smtp proxy.

If localhost is not given then `localhost' is used, and if localport is not
given then 8025 is used.  If remotehost is not given then `localhost' is used,
and if remoteport is not given, then 25 is used.
"""

# Overview:
#
# This file implements the minimal SMTP protocol as defined in RFC 5321.  It
# has:
#
#   SMTPServer - the base class for the backend.  Raises NotImplementedError
#   if you try to use it.

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
                 map_=None, enable_smtp_utf8: bool = False, decode_data: bool = False):
        if enable_smtp_utf8 and decode_data:
            raise ValueError("decode_data and enable_smtp_utf8 cannot be set to True at the same time")

        super().__init__(map=map_)

        self._local_addr = local_addr
        self._remote_addr = remote_addr
        self._data_size_limit = data_size_limit
        self._enable_smtp_utf8 = enable_smtp_utf8
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
            print('%s started at %s\n\tLocal addr: %s\n\tRemote addr:%s' % (
                self.__class__.__name__, time.ctime(time.time()), local_addr, remote_addr
            ), file=sys.stderr)

    def handle_accepted(self, conn, addr):
        print(f'Incoming connection from {repr(addr)}', file=sys.stderr)
        self.stream_class(self,
                          conn,
                          self._data_size_limit,
                          self._map,
                          self._enable_smtp_utf8,
                          self._decode_data)

    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        """Override this abstract method to handle messages from the client.

        peer is a tuple containing (ipaddr, port) of the client that made the
        socket connection to our smtp port.

        mailfrom is the raw address the client claims the message is coming
        from.

        rcpttos is a list of raw addresses the client wishes to deliver the
        message to.

        data is a string containing the entire full text of the message,
        headers (if supplied) and all.  It has been `de-transparencied'
        according to RFC 821, Section 4.5.2.  In other words, a line
        containing a `.' followed by other text has had the leading dot
        removed.

        kwargs is a dictionary containing additional information.  It is
        empty if decode_data=True was given as init parameter, otherwise
        it will contain the following keys:
            'mail_options': list of parameters to the mail command.  All
                            elements are uppercase strings.  Example:
                            ['BODY=8BITMIME', 'SMTPUTF8'].
            'rcpt_options': same, for the rcpt command.

        This function should return None for a normal `250 Ok' response;
        otherwise, it should return the desired response string in RFC 821
        format.

        """
        raise NotImplementedError
