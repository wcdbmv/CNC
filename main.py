#! /usr/bin/env python3
"""An RFC 5321 smtp proxy with optional RFC 1870 and RFC 6531 extensions.

Usage: %(program)s [options] [localhost:localport [remotehost:remoteport]]

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
        bytes via the RFC 1870 SIZE extension.  Defaults to 33554432 bytes.

    --smtputf8
    -u
        Enable the SMTPUTF8 extension and behave as an RFC 6531 smtp proxy.

    --help
    -h
        Print this message and exit.

Version: %(__version__)s

If localhost is not given then `localhost' is used, and if localport is not
given then 8025 is used.  If remotehost is not given then `localhost' is used,
and if remoteport is not given, then 25 is used.
"""

# Overview:
#
# This file implements the minimal SMTP protocol as defined in RFC 5321.  It
# has a hierarchy of classes which implement the backend functionality for the
# smtpd.  A number of classes are provided:
#
#   SMTPServer - the base class for the backend.  Raises NotImplementedError
#   if you try to use it.

import sys
import os
import errno
import getopt
import time
import socket
import asyncore
import asynchat
import collections
from enum import Enum
from typing import Union, Any, Optional, List, Tuple
from libemail.header_value_parser import get_addr_spec, get_angle_addr

__all__ = [
    "SmtpStream", "SMTPServer",
]

program = sys.argv[0]
__version__ = 'libsmtp v0.1'


DATA_SIZE_DEFAULT = 33554432


def print_to_stderr(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def usage(code, msg=''):
    print_to_stderr(__doc__ % globals())
    if msg:
        print_to_stderr(msg)
    sys.exit(code)


Char = Union[str, bytes, int]


class Chars:
    def __init__(self, emptystring: Char, linesep: Char, dotsep: Char, newline: Char):
        self.emptystring: Char = emptystring
        self.linesep: Char = linesep
        self.dotsep: Char = dotsep
        self.newline: Char = newline


str_chars = Chars('', '\r\n', '.', '\n')
bytes_chars = Chars(b'', b'\r\n', ord(b'.'), b'\n')


class SmtpStream(asynchat.async_chat):
    class State(Enum):
        COMMAND = 0
        DATA = 1

    command_size_limit = 512
    command_size_limits = collections.defaultdict(lambda x=command_size_limit: x)

    @property
    def max_command_size_limit(self):
        try:
            return max(self.command_size_limits.values())
        except ValueError:
            return self.command_size_limit

    def __init__(self, server: 'SMTPServer', conn: socket.socket, data_size_limit: int = DATA_SIZE_DEFAULT,
                 map_: Any = None, enable_smtp_utf8: bool = False, decode_data: bool = False) -> None:
        if enable_smtp_utf8 and decode_data:
            raise ValueError("decode_data and enable_smtp_utf8 cannot be set to True at the same time")

        super().__init__(conn, map=map_)

        self.smtp_server: SMTPServer = server
        self.conn: socket.socket = conn
        self.data_size_limit: int = data_size_limit
        self.enable_smtp_utf8: bool = enable_smtp_utf8
        self.decode_data: bool = decode_data

        self.__chars: Chars = str_chars if decode_data else bytes_chars
        self.__set_reset_state()

        self.seen_greeting: str = ''
        self.extended_smtp: bool = False
        self.command_size_limits.clear()
        self.fqdn: str = socket.getfqdn()

        try:
            self.peer: Any = conn.getpeername()
        except OSError as err:
            # Может возникнуть состояние гонки, если другой конец закрывается до того, как мы сможем получить имя узла
            self.close()
            if err.args[0] != errno.ENOTCONN:
                raise
            return
        print_to_stderr(f'Peer: {repr(self.peer)}')
        self.push(f'220 {self.fqdn} {__version__}')

    def __set_post_data_state(self) -> None:
        """Сбросить состояние переменных в их состояние после получения данных."""
        self.smtp_state: SmtpStream.State.COMMAND = SmtpStream.State.COMMAND
        self.mail_from: Optional[str] = None
        self.rcpt_tos: List[str] = []
        self.require_smtp_utf8: bool = False
        self.num_bytes: int = 0
        self.set_terminator(b'\r\n')

    def __set_reset_state(self) -> None:
        """Сбросить состояние всех переменных за исключением приветствия."""
        self.__set_post_data_state()
        self.received_data: str = ''
        self.received_lines: List[str] = []

    def push(self, msg: str) -> None:
        """Переопределяет метод базового класса для удобства."""
        super().push(bytes(msg + '\r\n', 'utf-8' if self.require_smtp_utf8 else 'ascii'))

    def collect_incoming_data(self, data: bytes) -> None:
        """Реализация абстрактного метода базового класса."""
        limit: Optional[int] = None
        if self.smtp_state == SmtpStream.State.COMMAND:
            limit = self.max_command_size_limit
        elif self.smtp_state == SmtpStream.State.DATA:
            limit = self.data_size_limit

        if limit:
            if self.num_bytes > limit:
                return
            self.num_bytes += len(data)

        self.received_lines.append(str(data, 'utf-8') if self.decode_data else data)

    def __found_terminator_in_command_state(self, line: Char) -> None:
        sz, self.num_bytes = self.num_bytes, 0
        if not line:
            return self.push('500 Syntax error')
        if not self.decode_data:
            line = str(line, 'utf-8')

        i_space = line.find(' ')
        if i_space < 0:
            command = line.upper()
            arg = None
        else:
            command = line[:i_space].upper()
            arg = line[i_space + 1:].strip()

        max_sz = self.command_size_limits[command] if self.extended_smtp else self.command_size_limit
        if sz > max_sz:
            return self.push('500 Syntax error: command line too long')
        method = getattr(self, 'smtp_' + command, None)
        if not method:
            return self.push(f'500 Command unrecognized: `{command}`')
        method(arg)

    def __found_terminator_in_data_state(self, line: Char) -> None:
        if self.data_size_limit and self.num_bytes > self.data_size_limit:
            self.push('552 Requested mail action aborted: exceeded storage allocation')
            self.num_bytes = 0
            return

        # Удаление лишних символов (RFC 5321, секция 4.5.2)
        data = []
        for text in line.split(self.__chars.linesep):
            data.append(text[1:] if text and text[0] == self.__chars.dotsep else text)
        self.received_data = self.__chars.newline.join(data)
        args = (self.peer, self.mail_from, self.rcpt_tos, self.received_data)
        kwargs = {}
        if not self.decode_data:
            kwargs = {
                'mail_options': self.mail_options,
                'rcpt_options': self.rcpt_options,
            }
        status = self.smtp_server.process_message(*args, **kwargs)
        self.__set_post_data_state()
        self.push(status if status else '250 OK')

    def found_terminator(self) -> None:
        """Реализация абстрактного метода базового класса."""
        line: Char = self.__chars.emptystring.join(self.received_lines)
        print_to_stderr(f'Data: {repr(line)}')
        self.received_lines.clear()

        if self.smtp_state == SmtpStream.State.COMMAND:
            self.__found_terminator_in_command_state(line)
        elif self.smtp_state == SmtpStream.State.DATA:
            self.__found_terminator_in_data_state(line)
        else:
            self.push('451 Requested action aborted: error in processing')
            self.num_bytes = 0

    # Синтаксис комманд (https://tools.ietf.org/html/rfc5321#section-4.5.1)
    @staticmethod
    def syntax_EHLO() -> str:
        return 'EHLO <hostname>'

    @staticmethod
    def syntax_HELO() -> str:
        return 'HELO <hostname>'

    def __syntax_extended(self) -> str:
        return ' [SP <mail-parameters>]' * self.extended_smtp

    def syntax_MAIL(self) -> str:
        return 'MAIL FROM: <address>' + self.__syntax_extended()

    def syntax_RCPT(self) -> str:
        return 'RCPT TO: <address>' + self.__syntax_extended()

    @staticmethod
    def syntax_DATA() -> str:
        return 'DATA'

    @staticmethod
    def syntax_RSET() -> str:
        return 'RSET'

    @staticmethod
    def syntax_NOOP() -> str:
        return 'NOOP'

    @staticmethod
    def syntax_QUIT() -> str:
        return 'QUIT'

    @staticmethod
    def syntax_VRFY() -> str:
        return 'VRFY <address>'

    def supported_commands(self) -> str:
        prefix_str = 'syntax_'
        prefix_len = len(prefix_str)
        return ' '.join(method[prefix_len:] for method in dir(self) if method.startswith(prefix_str))

    # комманды SMTP и ESMTP
    def smtp_HELO(self, arg: Char) -> None:
        if not arg:
            return self.push(f'501 Syntax: {SmtpStream.syntax_HELO()}')
        if self.seen_greeting:
            return self.push('503 Bad sequence of commands: duplicate HELO/EHLO')
        self.__set_reset_state()
        self.seen_greeting = arg
        self.push(f'250 {self.fqdn}')

    def smtp_EHLO(self, arg: Char) -> None:
        if not arg:
            return self.push(f'501 Syntax: {SmtpStream.syntax_EHLO()}')
        if self.seen_greeting:
            return self.push('503 Bad sequence of commands: duplicate HELO/EHLO')
        self.__set_reset_state()
        self.seen_greeting = arg
        self.extended_smtp = True
        self.push(f'250-{self.fqdn}')
        if self.data_size_limit:
            self.push(f'250-SIZE {self.data_size_limit}')
            self.command_size_limits['MAIL'] += 26
        if not self.decode_data:
            self.push('250-8BITMIME')
        if self.enable_smtp_utf8:
            self.push('250-SMTPUTF8')
            self.command_size_limits['MAIL'] += 10
        self.push('250 HELP')

    def smtp_NOOP(self, arg: Char) -> None:
        self.push(f'501 Syntax: {SmtpStream.syntax_NOOP()}' if arg else '250 OK')

    def smtp_QUIT(self, unused_arg: Char) -> None:
        self.push('221 Bye')
        self.close_when_done()

    @staticmethod
    def __strip_command_keyword(keyword: Char, arg: Char) -> Char:
        key_len = len(keyword)
        return arg[key_len:].strip() if arg[:key_len].upper() == keyword else ''

    @staticmethod
    def __get_addr(arg: Char) -> Tuple[Char, Char]:
        if not arg:
            return '', ''
        if arg.lstrip().startswith('<'):
            address, rest = get_angle_addr(arg)
        else:
            address, rest = get_addr_spec(arg)
        if not address:
            return address, rest
        return address.addr_spec, rest

    @staticmethod
    def __get_params(params) -> Optional[dict]:
        # Вернуть параметры в виде словаря, если все являются синтаксически допустимыми в соответствии с RFC 1869
        result = {}
        for param in params:
            param, eq, value = param.partition('=')
            if not param.isalnum() or eq and not value:
                return None
            result[param] = value if eq else True
        return result

    def smtp_HELP(self, arg: Char) -> None:
        if arg:
            method = getattr(self, f'syntax_{arg.upper()}', None)
            if method:
                return self.push(f'250 Syntax: {method()}')
        self.push(f'{501 if arg else 250} Supported commands: {self.supported_commands()}')

    def smtp_VRFY(self, arg: Char) -> None:
        if arg:
            address, params = self.__get_addr(arg)
            if address:
                self.push('252 Cannot VRFY user, but will accept message and attempt delivery')
            else:
                self.push(f'502 Could not VRFY {arg}')
        else:
            self.push(f'501 Syntax: {SmtpStream.syntax_VRFY()}')

    def smtp_MAIL(self, arg: Char) -> None:
        if not self.seen_greeting:
            return self.push('503 Error: send HELO first')
        print_to_stderr('===> MAIL', arg)
        syntaxerr = f'501 Syntax: {self.syntax_MAIL()}'
        if arg is None:
            return self.push(syntaxerr)
        arg = self.__strip_command_keyword('FROM:', arg)
        address, params = self.__get_addr(arg)
        if not address:
            return self.push(syntaxerr)
        if not self.extended_smtp and params:
            return self.push(syntaxerr)
        if self.mail_from:
            return self.push('503 Error: nested MAIL command')
        self.mail_options = params.upper().split()
        params = self.__get_params(self.mail_options)
        if params is None:
            return self.push(syntaxerr)
        if not self.decode_data:
            body = params.pop('BODY', '7BIT')
            if body not in ['7BIT', '8BITMIME']:
                return self.push('501 Error: BODY can only be one of 7BIT, 8BITMIME')
        if self.enable_smtp_utf8:
            smtp_utf8 = params.pop('SMTPUTF8', False)
            if smtp_utf8 is True:
                self.require_smtp_utf8 = True
            elif smtp_utf8 is not False:
                return self.push('501 Error: SMTPUTF8 takes no arguments')
        size = params.pop('SIZE', None)
        if size:
            if not size.isdigit():
                return self.push(syntaxerr)
            if self.data_size_limit and int(size) > self.data_size_limit:
                return self.push('552 Error: message size exceeds fixed maximum message size')
        if len(params.keys()) > 0:
            return self.push('555 MAIL FROM parameters not recognized or not implemented')
        self.mail_from = address
        print_to_stderr('sender:', self.mail_from)
        self.push('250 OK')

    def smtp_RCPT(self, arg: Char) -> None:
        if not self.seen_greeting:
            return self.push('503 Error: send HELO first')
        print_to_stderr('===> RCPT', arg)
        if not self.mail_from:
            return self.push('503 Error: need MAIL command')
        syntaxerr = f'501 Syntax: {self.syntax_RCPT()}'
        if arg is None:
            return self.push(syntaxerr)
        arg = self.__strip_command_keyword('TO:', arg)
        address, params = self.__get_addr(arg)
        if not address:
            return self.push(syntaxerr)
        if not self.extended_smtp and params:
            return self.push(syntaxerr)
        self.rcpt_options = params.upper().split()
        params = self.__get_params(self.rcpt_options)
        if params is None:
            return self.push(syntaxerr)
        # XXX currently there are no options we recognize.
        if len(params.keys()) > 0:
            return self.push('555 RCPT TO parameters not recognized or not implemented')
        self.rcpt_tos.append(address)
        print_to_stderr('recipes:', self.rcpt_tos)
        self.push('250 OK')

    def smtp_RSET(self, arg: Char) -> None:
        if arg:
            return self.push(f'501 Syntax: {SmtpStream.syntax_RSET()}')
        self.__set_reset_state()
        self.push('250 OK')

    def smtp_DATA(self, arg: Char) -> None:
        if not self.seen_greeting:
            return self.push('503 Error: send HELO first')
        if not self.rcpt_tos:
            return self.push('503 Error: need RCPT command')
        if arg:
            return self.push(f'501 Syntax: {self.syntax_DATA()}')
        self.smtp_state = SmtpStream.State.DATA
        self.set_terminator(b'\r\n.\r\n')
        self.push('354 End data with <CR><LF>.<CR><LF>')


class SMTPServer(asyncore.dispatcher):
    stream_class = SmtpStream

    def __init__(self, localaddr, remoteaddr,
                 data_size_limit=DATA_SIZE_DEFAULT, map=None,
                 enable_SMTPUTF8=False, decode_data=False):
        self._localaddr = localaddr
        self._remoteaddr = remoteaddr
        self.data_size_limit = data_size_limit
        self.enable_SMTPUTF8 = enable_SMTPUTF8
        self._decode_data = decode_data
        if enable_SMTPUTF8 and decode_data:
            raise ValueError("decode_data and enable_SMTPUTF8 cannot"
                             " be set to True at the same time")
        asyncore.dispatcher.__init__(self, map=map)
        try:
            gai_results = socket.getaddrinfo(*localaddr,
                                             type=socket.SOCK_STREAM)
            self.create_socket(gai_results[0][0], gai_results[0][1])
            # try to re-use a server port if possible
            self.set_reuse_addr()
            self.bind(localaddr)
            self.listen(5)
        except:
            self.close()
            raise
        else:
            print_to_stderr('%s started at %s\n\tLocal addr: %s\n\tRemote addr:%s' % (
                self.__class__.__name__, time.ctime(time.time()),
                localaddr, remoteaddr))

    def handle_accepted(self, conn, addr):
        print_to_stderr('Incoming connection from %s' % repr(addr))
        self.stream_class(self,
                          conn,
                          self.data_size_limit,
                          self._map,
                          self.enable_SMTPUTF8,
                          self._decode_data)

    # API for "doing something useful with the message"
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


class Options:
    setuid = True
    classname = 'PureProxy'
    size_limit = None
    enable_SMTPUTF8 = False


def parseargs():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], 'nVhc:s:du',
            ['class=', 'nosetuid', 'version', 'help', 'size=', 'debug',
             'smtputf8'])
    except getopt.error as e:
        usage(1, e)

    options = Options()
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(0)
        elif opt in ('-V', '--version'):
            print(__version__)
            sys.exit(0)
        elif opt in ('-n', '--nosetuid'):
            options.setuid = False
        elif opt in ('-c', '--class'):
            options.classname = arg
        elif opt in ('-u', '--smtputf8'):
            options.enable_SMTPUTF8 = True
        elif opt in ('-s', '--size'):
            try:
                int_size = int(arg)
                options.size_limit = int_size
            except:
                print_to_stderr('Invalid size: ' + arg)
                sys.exit(1)

    # parse the rest of the arguments
    if len(args) < 1:
        localspec = 'localhost:8025'
        remotespec = 'localhost:25'
    elif len(args) < 2:
        localspec = args[0]
        remotespec = 'localhost:25'
    elif len(args) < 3:
        localspec = args[0]
        remotespec = args[1]
    else:
        usage(1, 'Invalid arguments: %s' % ', '.join(args))

    # split into host/port pairs
    i = localspec.find(':')
    if i < 0:
        usage(1, 'Bad local spec: %s' % localspec)
    options.localhost = localspec[:i]
    try:
        options.localport = int(localspec[i+1:])
    except ValueError:
        usage(1, 'Bad local port: %s' % localspec)
    i = remotespec.find(':')
    if i < 0:
        usage(1, 'Bad remote spec: %s' % remotespec)
    options.remotehost = remotespec[:i]
    try:
        options.remoteport = int(remotespec[i+1:])
    except ValueError:
        usage(1, 'Bad remote port: %s' % remotespec)
    return options


if __name__ == '__main__':
    options = parseargs()
    # Become nobody
    classname = options.classname
    if "." in classname:
        lastdot = classname.rfind(".")
        mod = __import__(classname[:lastdot], globals(), locals(), [""])
        classname = classname[lastdot+1:]
    else:
        import __main__ as mod
    class_ = getattr(mod, classname)
    proxy = class_((options.localhost, options.localport),
                   (options.remotehost, options.remoteport),
                   options.size_limit, enable_SMTPUTF8=options.enable_SMTPUTF8)
    if options.setuid:
        try:
            import pwd
        except ImportError:
            print_to_stderr('Cannot import module "pwd"; try running with -n option.')
            sys.exit(1)
        nobody = pwd.getpwnam('nobody')[2]
        try:
            os.setuid(nobody)
        except PermissionError:
            print_to_stderr('Cannot setuid "nobody"; try running with -n option.')
            sys.exit(1)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass
