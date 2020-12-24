#! /usr/bin/env python3

import datetime
import email.generator
import email.message
import email.utils
import re
import socket
import sys

from typing import Optional, Tuple, Union

__all__ = ['SmtpException', 'SmtpNotSupportedError', 'SmtpServerDisconnected', 'SmtpResponseException',
           'SmtpSenderRefused', 'SmtpRecipientsRefused', 'SmtpDataError',
           'SmtpConnectError', 'SmtpHeloError', 'quote_addr', 'SmtpClient']

SMTP_PORT = 25
CRLF = '\r\n'
bCRLF = b'\r\n'
MAX_LINE = 8192  # в 8 раз больше, чем определено в RFC 5321, 4.5.3.1.6.


class SmtpException(OSError):
    """Базовый класс для всех исключений, создаваемых этим модулем."""


class SmtpNotSupportedError(SmtpException):
    """Команда или параметр не поддерживается сервером SMTP."""


class SmtpServerDisconnected(SmtpException):
    """Не подключен ни к одному SMTP-серверу."""


class SmtpResponseException(SmtpException):
    """Базовый класс для всех исключений, включающих код ошибки SMTP."""

    def __init__(self, code, msg):
        self.smtp_code = code
        self.smtp_error = msg
        self.args = (code, msg)


class SmtpSenderRefused(SmtpResponseException):
    """Адрес отправителя отклонен."""

    def __init__(self, code, msg, sender):
        self.smtp_code = code
        self.smtp_error = msg
        self.sender = sender
        self.args = (code, msg, sender)


class SmtpRecipientsRefused(SmtpException):
    """Все адреса получателей отклонены."""

    def __init__(self, recipients):
        self.recipients = recipients
        self.args = (recipients,)


class SmtpDataError(SmtpResponseException):
    """Сервер SMTP не принял данные."""


class SmtpConnectError(SmtpResponseException):
    """Ошибка при установлении соединения."""


class SmtpHeloError(SmtpResponseException):
    """Сервер отказался от нашего ответа HELO."""


def quote_addr(addr_string):
    """Оборачивает в кавычки подмножество email адресов, определённых в RFC 5321."""
    display_name, addr = email.utils.parseaddr(addr_string)
    if (display_name, addr) == ('', ''):
        return addr_string if addr_string.strip().startswith('<') else f'<{addr_string}>'
    return f'<{addr}>'


def addr_only(addr_string):
    display_name, addr = email.utils.parseaddr(addr_string)
    if (display_name, addr) == ('', ''):
        return addr_string
    return addr


def quote_periods(bin_data):
    return re.sub(br'(?m)^\.', b'../..', bin_data)


def fix_eols(data):
    return re.sub(r'(?:\r\n|\n|\r(?!\n))', CRLF, data)


SourceAddress = Tuple[str, int]


class SmtpClient:
    """Этот класс управляет подключением к серверу SMTP или ESMTP."""
    __socket = None
    __file = None
    __last_helo_response = None

    ehlo_msg = 'ehlo'
    __last_ehlo_response = None
    __is_server_supports_esmtp = 0
    default_port = SMTP_PORT

    def __init__(self, host: str = '', port: int = 0, local_hostname: Optional[str] = None, source_address: SourceAddress = None):
        self.__host = host
        self.__supported_esmtp_features = {}
        self.__command_encoding = 'ascii'
        self.__source_address = source_address

        if host:
            code, msg = self.connect(host, port)
            if code != 220:
                self.close()
                raise SmtpConnectError(code, msg)
        if local_hostname is not None:
            self.__local_hostname = local_hostname
        else:
            # Согласно RFC 2821 мы должны использовать fqdn в EHLO/HELO и
            # если не получилось — то домен
            fqdn = socket.getfqdn()
            if '.' in fqdn:
                self.__local_hostname = fqdn
            else:
                addr = '127.0.0.1'
                try:
                    addr = socket.gethostbyname(socket.gethostname())
                except socket.gaierror:
                    pass
                self.__local_hostname = f'[{addr}]'

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            code, message = self.do_command('QUIT')
            if code != 221:
                raise SmtpResponseException(code, message)
        except SmtpServerDisconnected:
            pass
        finally:
            self.close()

    @staticmethod
    def __print_debug(*args):
        print(datetime.datetime.now().time(), *args, file=sys.stderr)

    def __get_socket(self, host, port):
        self.__print_debug('connect: to', (host, port), self.__source_address)
        return socket.create_connection((host, port), source_address=self.__source_address)

    def connect(self, host='localhost', port=0, source_address=None):
        if source_address:
            self.__source_address = source_address

        if not port and (host.find(':') == host.rfind(':')):
            i = host.rfind(':')
            if i >= 0:
                host, port = host[:i], host[i + 1:]
                try:
                    port = int(port)
                except ValueError:
                    raise OSError("non numeric port")
        if not port:
            port = self.default_port
        sys.audit("SmtpClient.connect", self, host, port)
        self.__socket = self.__get_socket(host, port)
        self.__file = None
        code, msg = self.getreply()
        self.__print_debug('connect:', repr(msg))
        return code, msg

    def send(self, s):
        self.__print_debug('send:', repr(s))
        if self.__socket:
            if isinstance(s, str):
                s = s.encode(self.__command_encoding)
            sys.audit("SmtpClient.send", self, s)
            try:
                self.__socket.sendall(s)
            except OSError:
                self.close()
                raise SmtpServerDisconnected('Server not connected')
        else:
            raise SmtpServerDisconnected('please run connect() first')

    def put_command(self, cmd, args=''):
        self.send(f'{cmd}{CRLF}' if args == '' else f'{cmd} {args}{CRLF}')

    def getreply(self):
        resp = []
        if self.__file is None:
            self.__file = self.__socket.makefile('rb')
        while True:
            try:
                line = self.__file.readline(MAX_LINE + 1)
            except OSError as e:
                self.close()
                raise SmtpServerDisconnected(f'Connection unexpectedly closed: {str(e)}')
            if not line:
                self.close()
                raise SmtpServerDisconnected('Connection unexpectedly closed')
            self.__print_debug('reply:', repr(line))
            if len(line) > MAX_LINE:
                self.close()
                raise SmtpResponseException(500, 'Line too long.')
            resp.append(line[4:].strip(b' \t\r\n'))
            code = line[:3]
            try:
                errcode = int(code)
            except ValueError:
                errcode = -1
                break
            if line[3:4] != b"-":
                break

        errmsg = b'\n'.join(resp)
        self.__print_debug(f'reply: retcode ({errcode}); Msg: {errmsg}')
        return errcode, errmsg

    def do_command(self, cmd, args=""):
        self.put_command(cmd, args)
        return self.getreply()

    def helo(self, name=''):
        self.put_command('helo', name or self.__local_hostname)
        code, msg = self.getreply()
        self.__last_helo_response = msg
        return code, msg

    def ehlo(self, name=''):
        self.__supported_esmtp_features = {}
        self.put_command(self.ehlo_msg, name or self.__local_hostname)
        code, msg = self.getreply()
        if code == -1 and len(msg) == 0:
            self.close()
            raise SmtpServerDisconnected('Server not connected')
        self.__last_ehlo_response = msg
        if code != 250:
            return code, msg
        self.__is_server_supports_esmtp = 1
        assert isinstance(self.__last_ehlo_response, bytes), repr(self.__last_ehlo_response)
        resp = self.__last_ehlo_response.decode("latin-1").split('\n')
        del resp[0]
        for each in resp:
            m = re.match(r'(?P<feature>[A-Za-z0-9][A-Za-z0-9\-]*) ?', each)
            if m:
                feature = m.group('feature').lower()
                params = m.string[m.end('feature'):].strip()
                self.__supported_esmtp_features[feature] = params
        return code, msg

    def has_extn(self, opt):
        return opt.lower() in self.__supported_esmtp_features

    def help(self, args=''):
        self.put_command('help', args)
        return self.getreply()[1]

    def rset(self):
        self.__command_encoding = 'ascii'
        return self.do_command('rset')

    def __rset(self):
        try:
            self.rset()
        except SmtpServerDisconnected:
            pass

    def noop(self):
        return self.do_command("noop")

    def __mail_or_rcpt(self, command, cmd, addr, options=()):
        option_list = ''
        if options and self.__is_server_supports_esmtp:
            option_list = ' ' + ' '.join(options)
        self.put_command(command, f'{cmd}:{quote_addr(addr)}{option_list}')
        return self.getreply()

    def mail(self, sender, options=()):
        return self.__mail_or_rcpt('mail', 'FROM', sender, options)

    def rcpt(self, recipient, options=()):
        return self.__mail_or_rcpt('rcpt', 'TO', recipient, options)

    def data(self, msg):
        self.put_command('data')
        code, repl = self.getreply()
        self.__print_debug('data:', (code, repl))
        if code != 354:
            raise SmtpDataError(code, repl)
        else:
            if isinstance(msg, str):
                msg = fix_eols(msg).encode('ascii')
            q = quote_periods(msg)
            if q[-2:] != bCRLF:
                q = q + bCRLF
            q = q + b'.' + bCRLF
            self.send(q)
            code, msg = self.getreply()
            self.__print_debug('data:', (code, msg))
            return code, msg

    def vrfy(self, address):
        self.put_command('vrfy', addr_only(address))
        return self.getreply()

    def expn(self, address):
        self.put_command('expn', addr_only(address))
        return self.getreply()

    def ehlo_or_helo_if_needed(self):
        if self.__last_helo_response is None and self.__last_ehlo_response is None:
            if not (200 <= self.ehlo()[0] <= 299):
                code, resp = self.helo()
                if not (200 <= code <= 299):
                    raise SmtpHeloError(code, resp)

    def send_msg(self, from_addr, to_addrs, msg, mail_options=(), rcpt_options=()):
        self.ehlo_or_helo_if_needed()
        esmtp_opts = []
        if isinstance(msg, str):
            msg = fix_eols(msg).encode('ascii')
        if self.__is_server_supports_esmtp:
            if self.has_extn('size'):
                esmtp_opts.append(f'size={len(msg)}')
            for option in mail_options:
                esmtp_opts.append(option)
        code, resp = self.mail(from_addr, esmtp_opts)
        if code != 250:
            if code == 421:
                self.close()
            else:
                self.__rset()
            raise SmtpSenderRefused(code, resp, from_addr)
        senders = {}
        if isinstance(to_addrs, str):
            to_addrs = [to_addrs]
        for each in to_addrs:
            code, resp = self.rcpt(each, rcpt_options)
            if (code != 250) and (code != 251):
                senders[each] = (code, resp)
            if code == 421:
                self.close()
                raise SmtpRecipientsRefused(senders)
        if len(senders) == len(to_addrs):
            self.__rset()
            raise SmtpRecipientsRefused(senders)
        code, resp = self.data(msg)
        if code != 250:
            if code == 421:
                self.close()
            else:
                self.__rset()
            raise SmtpDataError(code, resp)
        return senders

    def close(self):
        try:
            file = self.__file
            self.__file = None
            if file:
                file.close()
        finally:
            sock = self.__socket
            self.__socket = None
            if sock:
                sock.close()

    def quit(self):
        res = self.do_command('quit')
        self.__last_ehlo_response = None
        self.__last_helo_response = None
        self.__supported_esmtp_features = {}
        self.__is_server_supports_esmtp = False
        self.close()
        return res
