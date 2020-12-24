import asynchat
import collections
import errno
import socket
import sys
from enum import Enum
from typing import Union, Any, Optional, List, Tuple
from backend.libemail.header_value_parser import get_addr_spec, get_angle_addr


__version__ = 'smtp_server v1.0'


def print_to_stderr(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


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

    DATA_SIZE_DEFAULT = 30000000

    def __init__(self, server: 'SmtpServer', conn: socket.socket, data_size_limit: int = DATA_SIZE_DEFAULT,
                 map_: Any = None, enable_smtp_utf8: bool = False, decode_data: bool = False) -> None:
        if enable_smtp_utf8 and decode_data:
            raise ValueError("decode_data and enable_smtp_utf8 cannot be set to True at the same time")

        super().__init__(conn, map=map_)

        self.__smtp_server: 'SmtpServer' = server
        self.__conn: socket.socket = conn
        self.__data_size_limit: int = data_size_limit
        self.__enable_smtp_utf8: bool = enable_smtp_utf8
        self.__decode_data: bool = decode_data

        self.__chars: Chars = str_chars if decode_data else bytes_chars
        self.__set_reset_state()

        self.__seen_greeting: str = ''
        self.__extended_smtp: bool = False
        self.command_size_limits.clear()
        self.__fqdn: str = socket.getfqdn()

        try:
            self.peer: Any = conn.getpeername()
        except OSError as err:
            # Может возникнуть состояние гонки, если другой конец закрывается до того, как мы сможем получить имя узла
            self.close()
            if err.args[0] != errno.ENOTCONN:
                raise
            return
        print_to_stderr(f'Peer: {repr(self.peer)}')
        self.push(f'220 {self.__fqdn} {__version__}')

    def __set_post_data_state(self) -> None:
        """Сбросить состояние переменных в их состояние после получения данных."""
        self.__smtp_state: SmtpStream.State.COMMAND = SmtpStream.State.COMMAND
        self.__mail_from: Optional[str] = None
        self.__rcpt_tos: List[str] = []
        self.__require_smtp_utf8: bool = False
        self.__num_bytes: int = 0
        self.set_terminator(b'\r\n')

    def __set_reset_state(self) -> None:
        """Сбросить состояние всех переменных за исключением приветствия."""
        self.__set_post_data_state()
        self.__received_data: Char = ''
        self.__received_lines: List[Char] = []

    def push(self, msg: str) -> None:
        """Переопределяет метод базового класса для удобства."""
        super().push(bytes(msg + '\r\n', 'utf-8' if self.__require_smtp_utf8 else 'ascii'))

    def collect_incoming_data(self, data: bytes) -> None:
        """Реализация абстрактного метода базового класса."""
        limit: Optional[int] = None
        if self.__smtp_state == SmtpStream.State.COMMAND:
            limit = self.max_command_size_limit
        elif self.__smtp_state == SmtpStream.State.DATA:
            limit = self.__data_size_limit

        if limit:
            if self.__num_bytes > limit:
                return
            self.__num_bytes += len(data)

        self.__received_lines.append(str(data, 'utf-8') if self.__decode_data else data)

    def __found_terminator_in_command_state(self, line: Char) -> None:
        sz, self.__num_bytes = self.__num_bytes, 0
        if not line:
            return self.push('500 Syntax error')
        if not self.__decode_data:
            line = str(line, 'utf-8')

        i_space = line.find(' ')
        if i_space < 0:
            command = line.upper()
            arg = None
        else:
            command = line[:i_space].upper()
            arg = line[i_space + 1:].strip()

        max_sz = self.command_size_limits[command] if self.__extended_smtp else self.command_size_limit
        if sz > max_sz:
            return self.push('500 Syntax error: command line too long')
        method = getattr(self, 'handle_' + command, None)
        if not method:
            return self.push(f'500 Command unrecognized: `{command}`')
        method(arg)

    def __found_terminator_in_data_state(self, line: Char) -> None:
        if self.__data_size_limit and self.__num_bytes > self.__data_size_limit:
            self.push('552 Requested mail action aborted: exceeded storage allocation')
            self.__num_bytes = 0
            return

        # Удаление лишних символов (RFC 5321, секция 4.5.2)
        data = []
        for text in line.split(self.__chars.linesep):
            data.append(text[1:] if text and text[0] == self.__chars.dotsep else text)
        self.__received_data = self.__chars.newline.join(data)
        args = (self.peer, self.__mail_from, self.__rcpt_tos, self.__received_data)
        kwargs = {}
        if not self.__decode_data:
            kwargs = {
                'mail_options': self.mail_options,
                'rcpt_options': self.rcpt_options,
            }
        status = self.__smtp_server.process_message(*args, **kwargs)
        self.__set_post_data_state()
        self.push(status if status else '250 OK')

    def found_terminator(self) -> None:
        """Реализация абстрактного метода базового класса."""
        line: Char = self.__chars.emptystring.join(self.__received_lines)
        print_to_stderr(f'Data: {repr(line)}')
        self.__received_lines.clear()

        if self.__smtp_state == SmtpStream.State.COMMAND:
            self.__found_terminator_in_command_state(line)
        elif self.__smtp_state == SmtpStream.State.DATA:
            self.__found_terminator_in_data_state(line)
        else:
            self.push('451 Requested action aborted: error in processing')
            self.__num_bytes = 0

    # Синтаксис комманд (https://tools.ietf.org/html/rfc5321#section-4.5.1)
    @staticmethod
    def syntax_EHLO() -> str:
        return 'EHLO <hostname>'

    @staticmethod
    def syntax_HELO() -> str:
        return 'HELO <hostname>'

    def __syntax_extended(self) -> str:
        return ' [SP <mail-parameters>]' * self.__extended_smtp

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
    def handle_HELO(self, arg: Char) -> None:
        if not arg:
            return self.push(f'501 Syntax: {SmtpStream.syntax_HELO()}')
        if self.__seen_greeting:
            return self.push('503 Bad sequence of commands: duplicate HELO/EHLO')
        self.__set_reset_state()
        self.__seen_greeting = arg
        self.push(f'250 {self.__fqdn}')

    def handle_EHLO(self, arg: Char) -> None:
        if not arg:
            return self.push(f'501 Syntax: {SmtpStream.syntax_EHLO()}')
        if self.__seen_greeting:
            return self.push('503 Bad sequence of commands: duplicate HELO/EHLO')
        self.__set_reset_state()
        self.__seen_greeting = arg
        self.__extended_smtp = True
        self.push(f'250-{self.__fqdn}')
        if self.__data_size_limit:
            self.push(f'250-SIZE {self.__data_size_limit}')
            self.command_size_limits['MAIL'] += 26
        if not self.__decode_data:
            self.push('250-8BITMIME')
        if self.__enable_smtp_utf8:
            self.push('250-SMTPUTF8')
            self.command_size_limits['MAIL'] += 10
        self.push('250 HELP')

    def handle_NOOP(self, arg: Char) -> None:
        self.push(f'501 Syntax: {SmtpStream.syntax_NOOP()}' if arg else '250 OK')

    def handle_QUIT(self, unused_arg: Char) -> None:
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

    def handle_HELP(self, arg: Char) -> None:
        if arg:
            method = getattr(self, f'syntax_{arg.upper()}', None)
            if method:
                return self.push(f'250 Syntax: {method()}')
        self.push(f'{501 if arg else 250} Supported commands: {self.supported_commands()}')

    def handle_VRFY(self, arg: Char) -> None:
        if arg:
            address, params = self.__get_addr(arg)
            if address:
                self.push('252 Cannot VRFY user, but will accept message and attempt delivery')
            else:
                self.push(f'502 Could not VRFY {arg}')
        else:
            self.push(f'501 Syntax: {SmtpStream.syntax_VRFY()}')

    def handle_MAIL(self, arg: Char) -> None:
        if not self.__seen_greeting:
            return self.push('503 Error: send HELO first')
        print_to_stderr('===> MAIL', arg)
        syntaxerr = f'501 Syntax: {self.syntax_MAIL()}'
        if arg is None:
            return self.push(syntaxerr)
        arg = self.__strip_command_keyword('FROM:', arg)
        address, params = self.__get_addr(arg)
        if not address:
            return self.push(syntaxerr)
        if not self.__extended_smtp and params:
            return self.push(syntaxerr)
        if self.__mail_from:
            return self.push('503 Error: nested MAIL command')
        self.mail_options = params.upper().split()
        params = self.__get_params(self.mail_options)
        if params is None:
            return self.push(syntaxerr)
        if not self.__decode_data:
            body = params.pop('BODY', '7BIT')
            if body not in ['7BIT', '8BITMIME']:
                return self.push('501 Error: BODY can only be one of 7BIT, 8BITMIME')
        if self.__enable_smtp_utf8:
            smtp_utf8 = params.pop('SMTPUTF8', False)
            if smtp_utf8 is True:
                self.__require_smtp_utf8 = True
            elif smtp_utf8 is not False:
                return self.push('501 Error: SMTPUTF8 takes no arguments')
        size = params.pop('SIZE', None)
        if size:
            if not size.isdigit():
                return self.push(syntaxerr)
            if self.__data_size_limit and int(size) > self.__data_size_limit:
                return self.push('552 Error: message size exceeds fixed maximum message size')
        if len(params.keys()) > 0:
            return self.push('555 MAIL FROM parameters not recognized or not implemented')
        self.__mail_from = address
        print_to_stderr('sender:', self.__mail_from)
        self.push('250 OK')

    def handle_RCPT(self, arg: Char) -> None:
        if not self.__seen_greeting:
            return self.push('503 Error: send HELO first')
        print_to_stderr('===> RCPT', arg)
        if not self.__mail_from:
            return self.push('503 Error: need MAIL command')
        syntaxerr = f'501 Syntax: {self.syntax_RCPT()}'
        if arg is None:
            return self.push(syntaxerr)
        arg = self.__strip_command_keyword('TO:', arg)
        address, params = self.__get_addr(arg)
        if not address:
            return self.push(syntaxerr)
        if not self.__extended_smtp and params:
            return self.push(syntaxerr)
        self.rcpt_options = params.upper().split()
        params = self.__get_params(self.rcpt_options)
        if params is None:
            return self.push(syntaxerr)
        # XXX currently there are no options we recognize.
        if len(params.keys()) > 0:
            return self.push('555 RCPT TO parameters not recognized or not implemented')
        self.__rcpt_tos.append(address)
        print_to_stderr('recipes:', self.__rcpt_tos)
        self.push('250 OK')

    def handle_RSET(self, arg: Char) -> None:
        if arg:
            return self.push(f'501 Syntax: {SmtpStream.syntax_RSET()}')
        self.__set_reset_state()
        self.push('250 OK')

    def handle_DATA(self, arg: Char) -> None:
        if not self.__seen_greeting:
            return self.push('503 Error: send HELO first')
        if not self.__rcpt_tos:
            return self.push('503 Error: need RCPT command')
        if arg:
            return self.push(f'501 Syntax: {self.syntax_DATA()}')
        self.__smtp_state = SmtpStream.State.DATA
        self.set_terminator(b'\r\n.\r\n')
        self.push('354 End data with <CR><LF>.<CR><LF>')
