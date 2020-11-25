#! /usr/bin/env python3
"""SMTP/ESMTP client class.

This should follow RFC 821 (SMTP), RFC 1869 (ESMTP), RFC 2554 (SMTP
Authentication) and RFC 2487 (Secure SMTP over TLS).

Notes:

Please remember, when doing ESMTP, that the names of the SMTP service
extensions are NOT the same thing as the option keywords for the RCPT
and MAIL commands!
"""


import base64
import copy
import datetime
import email.generator
import email.message
import email.utils
import hmac
import io
import re
import socket
import ssl
import sys

from typing import Optional, Tuple, Union
from libemail.base64mime import body_encode as encode_base64

__all__ = ['SmtpException', 'SmtpNotSupportedError', 'SmtpServerDisconnected', 'SmtpResponseException',
           'SmtpSenderRefused', 'SmtpRecipientsRefused', 'SmtpDataError',
           'SmtpConnectError', 'SmtpHeloError', 'SmtpAuthenticationError',
           'quote_addr', 'SmtpClient', 'SmtpSslClient']

SMTP_PORT = 25
SMTP_SSL_PORT = 465
CRLF = '\r\n'
bCRLF = b'\r\n'
MAX_LINE = 8192  # more than 8 times larger than RFC 5321, 4.5.3.1.6.

OLDSTYLE_AUTH = re.compile(r'auth=(.*)', re.I)


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


class SmtpAuthenticationError(SmtpResponseException):
    """Ошибка аутентификации."""


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
    return re.sub(br'(?m)^\.', b'..', bin_data)


def fix_eols(data):
    return re.sub(r'(?:\r\n|\n|\r(?!\n))', CRLF, data)


SourceAddress = Tuple[str, int]


class SmtpClient:
    """Этот класс управляет подключением к серверу SMTP или ESMTP."""
    sock = None
    file = None
    last_helo_response = None

    ehlo_msg = 'ehlo'
    last_ehlo_response = None
    is_server_supports_esmtp = 0
    default_port = SMTP_PORT

    def __init__(self, host: str = '', port: int = 0, local_hostname: Optional[str] =  None, source_address: SourceAddress = None):
        self._host = host
        self.supported_esmtp_features = {}
        self.command_encoding = 'ascii'
        self.source_address = source_address

        if host:
            (code, msg) = self.connect(host, port)
            if code != 220:
                self.close()
                raise SmtpConnectError(code, msg)
        if local_hostname is not None:
            self.local_hostname = local_hostname
        else:
            # RFC 2821 says we should use the fqdn in the EHLO/HELO verb, and
            # if that can't be calculated, that we should use a domain literal
            # instead (essentially an encoded IP address like [A.B.C.D]).
            fqdn = socket.getfqdn()
            if '.' in fqdn:
                self.local_hostname = fqdn
            else:
                # We can't find an fqdn hostname, so use a domain literal
                addr = '127.0.0.1'
                try:
                    addr = socket.gethostbyname(socket.gethostname())
                except socket.gaierror:
                    pass
                self.local_hostname = f'[{addr}]'

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            code, message = self.docmd("QUIT")
            if code != 221:
                raise SmtpResponseException(code, message)
        except SmtpServerDisconnected:
            pass
        finally:
            self.close()

    @staticmethod
    def _print_debug(*args):
        print(datetime.datetime.now().time(), *args, file=sys.stderr)

    def _get_socket(self, host, port):
        self._print_debug('connect: to', (host, port), self.source_address)
        return socket.create_connection((host, port), source_address=self.source_address)

    def connect(self, host='localhost', port=0, source_address=None):
        """Connect to a host on a given port.

        If the hostname ends with a colon (`:') followed by a number, and
        there is no port specified, that suffix will be stripped off and the
        number interpreted as the port number to use.

        Note: This method is automatically invoked by __init__, if a host is
        specified during instantiation.
        """

        if source_address:
            self.source_address = source_address

        if not port and (host.find(':') == host.rfind(':')):
            i = host.rfind(':')
            if i >= 0:
                host, port = host[:i], host[i + 1:]
                try:
                    port = int(port)
                except ValueError:
                    raise OSError("nonnumeric port")
        if not port:
            port = self.default_port
        sys.audit("smtplib.connect", self, host, port)
        self.sock = self._get_socket(host, port)
        self.file = None
        (code, msg) = self.getreply()
        self._print_debug('connect:', repr(msg))
        return (code, msg)

    def send(self, s):
        """Send `s' to the server."""
        self._print_debug('send:', repr(s))
        if self.sock:
            if isinstance(s, str):
                # send is used by the 'data' command, where command_encoding
                # should not be used, but 'data' needs to convert the string to
                # binary itself anyway, so that's not a problem.
                s = s.encode(self.command_encoding)
            sys.audit("smtplib.send", self, s)
            try:
                self.sock.sendall(s)
            except OSError:
                self.close()
                raise SmtpServerDisconnected('Server not connected')
        else:
            raise SmtpServerDisconnected('please run connect() first')

    def putcmd(self, cmd, args=""):
        """Send a command to the server."""
        if args == "":
            str = '%s%s' % (cmd, CRLF)
        else:
            str = '%s %s%s' % (cmd, args, CRLF)
        self.send(str)

    def getreply(self):
        """Get a reply from the server.

        Returns a tuple consisting of:

          - server response code (e.g. '250', or such, if all goes well)
            Note: returns -1 if it can't read response code.

          - server response string corresponding to response code (multiline
            responses are converted to a single, multiline string).

        Raises SMTPServerDisconnected if end-of-file is reached.
        """
        resp = []
        if self.file is None:
            self.file = self.sock.makefile('rb')
        while 1:
            try:
                line = self.file.readline(MAX_LINE + 1)
            except OSError as e:
                self.close()
                raise SmtpServerDisconnected("Connection unexpectedly closed: "
                                             + str(e))
            if not line:
                self.close()
                raise SmtpServerDisconnected("Connection unexpectedly closed")
            self._print_debug('reply:', repr(line))
            if len(line) > MAX_LINE:
                self.close()
                raise SmtpResponseException(500, "Line too long.")
            resp.append(line[4:].strip(b' \t\r\n'))
            code = line[:3]
            # Check that the error code is syntactically correct.
            # Don't attempt to read a continuation line if it is broken.
            try:
                errcode = int(code)
            except ValueError:
                errcode = -1
                break
            # Check if multiline response.
            if line[3:4] != b"-":
                break

        errmsg = b"\n".join(resp)
        self._print_debug('reply: retcode (%s); Msg: %a' % (errcode, errmsg))
        return errcode, errmsg

    def docmd(self, cmd, args=""):
        """Send a command, and return its response code."""
        self.putcmd(cmd, args)
        return self.getreply()

    # std smtp commands
    def helo(self, name=''):
        """SMTP 'helo' command.
        Hostname to send for this command defaults to the FQDN of the local
        host.
        """
        self.putcmd("helo", name or self.local_hostname)
        (code, msg) = self.getreply()
        self.last_helo_response = msg
        return (code, msg)

    def ehlo(self, name=''):
        """ SMTP 'ehlo' command.
        Hostname to send for this command defaults to the FQDN of the local
        host.
        """
        self.supported_esmtp_features = {}
        self.putcmd(self.ehlo_msg, name or self.local_hostname)
        (code, msg) = self.getreply()
        # According to RFC1869 some (badly written)
        # MTA's will disconnect on an ehlo. Toss an exception if
        # that happens -ddm
        if code == -1 and len(msg) == 0:
            self.close()
            raise SmtpServerDisconnected("Server not connected")
        self.last_ehlo_response = msg
        if code != 250:
            return (code, msg)
        self.is_server_supports_esmtp = 1
        #parse the ehlo response -ddm
        assert isinstance(self.last_ehlo_response, bytes), repr(self.last_ehlo_response)
        resp = self.last_ehlo_response.decode("latin-1").split('\n')
        del resp[0]
        for each in resp:
            # To be able to communicate with as many SMTP servers as possible,
            # we have to take the old-style auth advertisement into account,
            # because:
            # 1) Else our SMTP feature parser gets confused.
            # 2) There are some servers that only advertise the auth methods we
            #    support using the old style.
            auth_match = OLDSTYLE_AUTH.match(each)
            if auth_match:
                # This doesn't remove duplicates, but that's no problem
                self.supported_esmtp_features["auth"] = self.supported_esmtp_features.get("auth", "") \
                                                        + " " + auth_match.groups(0)[0]
                continue

            # RFC 1869 requires a space between ehlo keyword and parameters.
            # It's actually stricter, in that only spaces are allowed between
            # parameters, but were not going to check for that here.  Note
            # that the space isn't present if there are no parameters.
            m = re.match(r'(?P<feature>[A-Za-z0-9][A-Za-z0-9\-]*) ?', each)
            if m:
                feature = m.group("feature").lower()
                params = m.string[m.end("feature"):].strip()
                if feature == "auth":
                    self.supported_esmtp_features[feature] = self.supported_esmtp_features.get(feature, "") \
                                                             + " " + params
                else:
                    self.supported_esmtp_features[feature] = params
        return (code, msg)

    def has_extn(self, opt):
        """Does the server support a given SMTP service extension?"""
        return opt.lower() in self.supported_esmtp_features

    def help(self, args=''):
        """SMTP 'help' command.
        Returns help text from server."""
        self.putcmd("help", args)
        return self.getreply()[1]

    def rset(self):
        """SMTP 'rset' command -- resets session."""
        self.command_encoding = 'ascii'
        return self.docmd("rset")

    def _rset(self):
        """Internal 'rset' command which ignores any SMTPServerDisconnected error.

        Used internally in the library, since the server disconnected error
        should appear to the application when the *next* command is issued, if
        we are doing an internal "safety" reset.
        """
        try:
            self.rset()
        except SmtpServerDisconnected:
            pass

    def noop(self):
        """SMTP 'noop' command -- doesn't do anything :>"""
        return self.docmd("noop")

    def mail(self, sender, options=()):
        """SMTP 'mail' command -- begins mail xfer session.

        This method may raise the following exceptions:

         SMTPNotSupportedError  The options parameter includes 'SMTPUTF8'
                                but the SMTPUTF8 extension is not supported by
                                the server.
        """
        optionlist = ''
        if options and self.is_server_supports_esmtp:
            if any(x.lower()=='smtputf8' for x in options):
                if self.has_extn('smtputf8'):
                    self.command_encoding = 'utf-8'
                else:
                    raise SmtpNotSupportedError(
                        'SMTPUTF8 not supported by server')
            optionlist = ' ' + ' '.join(options)
        self.putcmd("mail", "FROM:%s%s" % (quote_addr(sender), optionlist))
        return self.getreply()

    def rcpt(self, recip, options=()):
        """SMTP 'rcpt' command -- indicates 1 recipient for this mail."""
        optionlist = ''
        if options and self.is_server_supports_esmtp:
            optionlist = ' ' + ' '.join(options)
        self.putcmd("rcpt", "TO:%s%s" % (quote_addr(recip), optionlist))
        return self.getreply()

    def data(self, msg):
        """SMTP 'DATA' command -- sends message data to server.

        Automatically quotes lines beginning with a period per rfc821.
        Raises SMTPDataError if there is an unexpected reply to the
        DATA command; the return value from this method is the final
        response code received when the all data is sent.  If msg
        is a string, lone '\\r' and '\\n' characters are converted to
        '\\r\\n' characters.  If msg is bytes, it is transmitted as is.
        """
        self.putcmd("data")
        (code, repl) = self.getreply()
        self._print_debug('data:', (code, repl))
        if code != 354:
            raise SmtpDataError(code, repl)
        else:
            if isinstance(msg, str):
                msg = fix_eols(msg).encode('ascii')
            q = quote_periods(msg)
            if q[-2:] != bCRLF:
                q = q + bCRLF
            q = q + b"." + bCRLF
            self.send(q)
            (code, msg) = self.getreply()
            self._print_debug('data:', (code, msg))
            return (code, msg)

    def verify(self, address):
        """SMTP 'verify' command -- checks for address validity."""
        self.putcmd("vrfy", addr_only(address))
        return self.getreply()
    # a.k.a.
    vrfy = verify

    def expn(self, address):
        """SMTP 'expn' command -- expands a mailing list."""
        self.putcmd("expn", addr_only(address))
        return self.getreply()

    # some useful methods

    def ehlo_or_helo_if_needed(self):
        """Call self.ehlo() and/or self.helo() if needed.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.

        This method may raise the following exceptions:

         SMTPHeloError            The server didn't reply properly to
                                  the helo greeting.
        """
        if self.last_helo_response is None and self.last_ehlo_response is None:
            if not (200 <= self.ehlo()[0] <= 299):
                (code, resp) = self.helo()
                if not (200 <= code <= 299):
                    raise SmtpHeloError(code, resp)

    def auth(self, mechanism, authobject, *, initial_response_ok=True):
        """Authentication command - requires response processing.

        'mechanism' specifies which authentication mechanism is to
        be used - the valid values are those listed in the 'auth'
        element of 'esmtp_features'.

        'authobject' must be a callable object taking a single argument:

                data = authobject(challenge)

        It will be called to process the server's challenge response; the
        challenge argument it is passed will be a bytes.  It should return
        an ASCII string that will be base64 encoded and sent to the server.

        Keyword arguments:
            - initial_response_ok: Allow sending the RFC 4954 initial-response
              to the AUTH command, if the authentication methods supports it.
        """
        # RFC 4954 allows auth methods to provide an initial response.  Not all
        # methods support it.  By definition, if they return something other
        # than None when challenge is None, then they do.  See issue #15014.
        mechanism = mechanism.upper()
        initial_response = (authobject() if initial_response_ok else None)
        if initial_response is not None:
            response = encode_base64(initial_response.encode('ascii'), eol='')
            (code, resp) = self.docmd("AUTH", mechanism + " " + response)
        else:
            (code, resp) = self.docmd("AUTH", mechanism)
        # If server responds with a challenge, send the response.
        if code == 334:
            challenge = base64.decodebytes(resp)
            response = encode_base64(
                authobject(challenge).encode('ascii'), eol='')
            (code, resp) = self.docmd(response)
        if code in (235, 503):
            return (code, resp)
        raise SmtpAuthenticationError(code, resp)

    def auth_cram_md5(self, challenge=None):
        """ Authobject to use with CRAM-MD5 authentication. Requires self.user
        and self.password to be set."""
        # CRAM-MD5 does not support initial-response.
        if challenge is None:
            return None
        return self.user + " " + hmac.HMAC(
            self.password.encode('ascii'), challenge, 'md5').hexdigest()

    def auth_plain(self, challenge=None):
        """ Authobject to use with PLAIN authentication. Requires self.user and
        self.password to be set."""
        return "\0%s\0%s" % (self.user, self.password)

    def auth_login(self, challenge=None):
        """ Authobject to use with LOGIN authentication. Requires self.user and
        self.password to be set."""
        if challenge is None:
            return self.user
        else:
            return self.password

    def login(self, user, password, *, initial_response_ok=True):
        """Log in on an SMTP server that requires authentication.

        The arguments are:
            - user:         The user name to authenticate with.
            - password:     The password for the authentication.

        Keyword arguments:
            - initial_response_ok: Allow sending the RFC 4954 initial-response
              to the AUTH command, if the authentication methods supports it.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.

        This method will return normally if the authentication was successful.

        This method may raise the following exceptions:

         SMTPHeloError            The server didn't reply properly to
                                  the helo greeting.
         SMTPAuthenticationError  The server didn't accept the username/
                                  password combination.
         SMTPNotSupportedError    The AUTH command is not supported by the
                                  server.
         SMTPException            No suitable authentication method was
                                  found.
        """

        self.ehlo_or_helo_if_needed()
        if not self.has_extn("auth"):
            raise SmtpNotSupportedError(
                "SMTP AUTH extension not supported by server.")

        # Authentication methods the server claims to support
        advertised_authlist = self.supported_esmtp_features["auth"].split()

        # Authentication methods we can handle in our preferred order:
        preferred_auths = ['CRAM-MD5', 'PLAIN', 'LOGIN']

        # We try the supported authentications in our preferred order, if
        # the server supports them.
        authlist = [auth for auth in preferred_auths
                    if auth in advertised_authlist]
        if not authlist:
            raise SmtpException("No suitable authentication method found.")

        # Some servers advertise authentication methods they don't really
        # support, so if authentication fails, we continue until we've tried
        # all methods.
        self.user, self.password = user, password
        for authmethod in authlist:
            method_name = 'auth_' + authmethod.lower().replace('-', '_')
            try:
                (code, resp) = self.auth(
                    authmethod, getattr(self, method_name),
                    initial_response_ok=initial_response_ok)
                # 235 == 'Authentication successful'
                # 503 == 'Error: already authenticated'
                if code in (235, 503):
                    return (code, resp)
            except SmtpAuthenticationError as e:
                last_exception = e

        # We could not login successfully.  Return result of last attempt.
        raise last_exception

    def starttls(self, keyfile=None, certfile=None, context=None):
        """Puts the connection to the SMTP server into TLS mode.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.

        If the server supports TLS, this will encrypt the rest of the SMTP
        session. If you provide the keyfile and certfile parameters,
        the identity of the SMTP server and client can be checked. This,
        however, depends on whether the socket module really checks the
        certificates.

        This method may raise the following exceptions:

         SMTPHeloError            The server didn't reply properly to
                                  the helo greeting.
        """
        self.ehlo_or_helo_if_needed()
        if not self.has_extn("starttls"):
            raise SmtpNotSupportedError(
                "STARTTLS extension not supported by server.")
        (resp, reply) = self.docmd("STARTTLS")
        if resp == 220:
            if context is not None and keyfile is not None:
                raise ValueError("context and keyfile arguments are mutually "
                                 "exclusive")
            if context is not None and certfile is not None:
                raise ValueError("context and certfile arguments are mutually "
                                 "exclusive")
            if keyfile is not None or certfile is not None:
                import warnings
                warnings.warn("keyfile and certfile are deprecated, use a "
                              "custom context instead", DeprecationWarning, 2)
            if context is None:
                context = ssl._create_stdlib_context(certfile=certfile,
                                                     keyfile=keyfile)
            self.sock = context.wrap_socket(self.sock,
                                            server_hostname=self._host)
            self.file = None
            # RFC 3207:
            # The client MUST discard any knowledge obtained from
            # the server, such as the list of SMTP service extensions,
            # which was not obtained from the TLS negotiation itself.
            self.last_helo_response = None
            self.last_ehlo_response = None
            self.supported_esmtp_features = {}
            self.is_server_supports_esmtp = 0
        else:
            # RFC 3207:
            # 501 Syntax error (no parameters allowed)
            # 454 TLS not available due to temporary reason
            raise SmtpResponseException(resp, reply)
        return (resp, reply)

    def sendmail(self, from_addr, to_addrs, msg, mail_options=(),
                 rcpt_options=()):
        """This command performs an entire mail transaction.

        The arguments are:
            - from_addr    : The address sending this mail.
            - to_addrs     : A list of addresses to send this mail to.  A bare
                             string will be treated as a list with 1 address.
            - msg          : The message to send.
            - mail_options : List of ESMTP options (such as 8bitmime) for the
                             mail command.
            - rcpt_options : List of ESMTP options (such as DSN commands) for
                             all the rcpt commands.

        msg may be a string containing characters in the ASCII range, or a byte
        string.  A string is encoded to bytes using the ascii codec, and lone
        \\r and \\n characters are converted to \\r\\n characters.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.  If the server does ESMTP, message size
        and each of the specified options will be passed to it.  If EHLO
        fails, HELO will be tried and ESMTP options suppressed.

        This method will return normally if the mail is accepted for at least
        one recipient.  It returns a dictionary, with one entry for each
        recipient that was refused.  Each entry contains a tuple of the SMTP
        error code and the accompanying error message sent by the server.

        This method may raise the following exceptions:

         SMTPHeloError          The server didn't reply properly to
                                the helo greeting.
         SMTPRecipientsRefused  The server rejected ALL recipients
                                (no mail was sent).
         SMTPSenderRefused      The server didn't accept the from_addr.
         SMTPDataError          The server replied with an unexpected
                                error code (other than a refusal of
                                a recipient).
         SMTPNotSupportedError  The mail_options parameter includes 'SMTPUTF8'
                                but the SMTPUTF8 extension is not supported by
                                the server.

        Note: the connection will be open even after an exception is raised.


        In the above example, the message was accepted for delivery to three
        of the four addresses, and one was rejected, with the error code
        550.  If all addresses are accepted, then the method will return an
        empty dictionary.

        """
        self.ehlo_or_helo_if_needed()
        esmtp_opts = []
        if isinstance(msg, str):
            msg = fix_eols(msg).encode('ascii')
        if self.is_server_supports_esmtp:
            if self.has_extn('size'):
                esmtp_opts.append("size=%d" % len(msg))
            for option in mail_options:
                esmtp_opts.append(option)
        (code, resp) = self.mail(from_addr, esmtp_opts)
        if code != 250:
            if code == 421:
                self.close()
            else:
                self._rset()
            raise SmtpSenderRefused(code, resp, from_addr)
        senderrs = {}
        if isinstance(to_addrs, str):
            to_addrs = [to_addrs]
        for each in to_addrs:
            (code, resp) = self.rcpt(each, rcpt_options)
            if (code != 250) and (code != 251):
                senderrs[each] = (code, resp)
            if code == 421:
                self.close()
                raise SmtpRecipientsRefused(senderrs)
        if len(senderrs) == len(to_addrs):
            # the server refused all our recipients
            self._rset()
            raise SmtpRecipientsRefused(senderrs)
        (code, resp) = self.data(msg)
        if code != 250:
            if code == 421:
                self.close()
            else:
                self._rset()
            raise SmtpDataError(code, resp)
        #if we got here then somebody got our mail
        return senderrs

    def send_message(self, msg, from_addr=None, to_addrs=None,
                     mail_options=(), rcpt_options=()):
        """Converts message to a bytestring and passes it to sendmail.

        The arguments are as for sendmail, except that msg is an
        email.message.Message object.  If from_addr is None or to_addrs is
        None, these arguments are taken from the headers of the Message as
        described in RFC 2822 (a ValueError is raised if there is more than
        one set of 'Resent-' headers).  Regardless of the values of from_addr and
        to_addr, any Bcc field (or Resent-Bcc field, when the Message is a
        resent) of the Message object won't be transmitted.  The Message
        object is then serialized using email.generator.BytesGenerator and
        sendmail is called to transmit the message.  If the sender or any of
        the recipient addresses contain non-ASCII and the server advertises the
        SMTPUTF8 capability, the policy is cloned with utf8 set to True for the
        serialization, and SMTPUTF8 and BODY=8BITMIME are asserted on the send.
        If the server does not support SMTPUTF8, an SMTPNotSupported error is
        raised.  Otherwise the generator is called without modifying the
        policy.

        """
        # 'Resent-Date' is a mandatory field if the Message is resent (RFC 2822
        # Section 3.6.6). In such a case, we use the 'Resent-*' fields.  However,
        # if there is more than one 'Resent-' block there's no way to
        # unambiguously determine which one is the most recent in all cases,
        # so rather than guess we raise a ValueError in that case.
        #
        # TODO implement heuristics to guess the correct Resent-* block with an
        # option allowing the user to enable the heuristics.  (It should be
        # possible to guess correctly almost all of the time.)

        self.ehlo_or_helo_if_needed()
        resent = msg.get_all('Resent-Date')
        if resent is None:
            header_prefix = ''
        elif len(resent) == 1:
            header_prefix = 'Resent-'
        else:
            raise ValueError("message has more than one 'Resent-' header block")
        if from_addr is None:
            # Prefer the sender field per RFC 2822:3.6.2.
            from_addr = (msg[header_prefix + 'Sender']
                           if (header_prefix + 'Sender') in msg
                           else msg[header_prefix + 'From'])
            from_addr = email.utils.getaddresses([from_addr])[0][1]
        if to_addrs is None:
            addr_fields = [f for f in (msg[header_prefix + 'To'],
                                       msg[header_prefix + 'Bcc'],
                                       msg[header_prefix + 'Cc'])
                           if f is not None]
            to_addrs = [a[1] for a in email.utils.getaddresses(addr_fields)]
        # Make a local copy so we can delete the bcc headers.
        msg_copy = copy.copy(msg)
        del msg_copy['Bcc']
        del msg_copy['Resent-Bcc']
        international = False
        try:
            ''.join([from_addr, *to_addrs]).encode('ascii')
        except UnicodeEncodeError:
            if not self.has_extn('smtputf8'):
                raise SmtpNotSupportedError(
                    "One or more source or delivery addresses require"
                    " internationalized email support, but the server"
                    " does not advertise the required SMTPUTF8 capability")
            international = True
        with io.BytesIO() as bytesmsg:
            if international:
                g = email.generator.BytesGenerator(
                    bytesmsg, policy=msg.policy.clone(utf8=True))
                mail_options = (*mail_options, 'SMTPUTF8', 'BODY=8BITMIME')
            else:
                g = email.generator.BytesGenerator(bytesmsg)
            g.flatten(msg_copy, linesep='\r\n')
            flatmsg = bytesmsg.getvalue()
        return self.sendmail(from_addr, to_addrs, flatmsg, mail_options,
                             rcpt_options)

    def close(self):
        """Close the connection to the SMTP server."""
        try:
            file = self.file
            self.file = None
            if file:
                file.close()
        finally:
            sock = self.sock
            self.sock = None
            if sock:
                sock.close()

    def quit(self):
        """Terminate the SMTP session."""
        res = self.docmd("quit")
        # A new EHLO is required after reconnecting with connect()
        self.last_ehlo_response = self.last_helo_response = None
        self.supported_esmtp_features = {}
        self.is_server_supports_esmtp = False
        self.close()
        return res


class SmtpSslClient(SmtpClient):
    """ This is a subclass derived from SMTP that connects over an SSL
    encrypted socket (to use this class you need a socket module that was
    compiled with SSL support). If host is not specified, '' (the local
    host) is used. If port is omitted, the standard SMTP-over-SSL port
    (465) is used.  local_hostname and source_address have the same meaning
    as they do in the SMTP class.  keyfile and certfile are also optional -
    they can contain a PEM formatted private key and certificate chain file
    for the SSL connection. context also optional, can contain a
    SSLContext, and is an alternative to keyfile and certfile; If it is
    specified both keyfile and certfile must be None.

    """

    default_port = SMTP_SSL_PORT

    def __init__(self, host='', port=0, local_hostname=None,
                 keyfile=None, certfile=None,
                 source_address=None, context=None):
        if context is not None and keyfile is not None:
            raise ValueError("context and keyfile arguments are mutually "
                             "exclusive")
        if context is not None and certfile is not None:
            raise ValueError("context and certfile arguments are mutually "
                             "exclusive")
        if keyfile is not None or certfile is not None:
            import warnings
            warnings.warn("keyfile and certfile are deprecated, use a "
                          "custom context instead", DeprecationWarning, 2)
        self.keyfile = keyfile
        self.certfile = certfile
        if context is None:
            context = ssl._create_stdlib_context(certfile=certfile,
                                                 keyfile=keyfile)
        self.context = context
        SmtpClient.__init__(self, host, port, local_hostname, source_address)

    def _get_socket(self, host, port):
        self._print_debug('connect:', (host, port))
        new_socket = super()._get_socket(host, port)
        new_socket = self.context.wrap_socket(new_socket, server_hostname=self._host)
        return new_socket
