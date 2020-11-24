#!/usr/bin/env python3

from smpt_server import SmtpServer
import asyncore
import argparse
from email.parser import Parser
import logging


log = logging.Logger(__name__)


class SmtpInboxServer(SmtpServer, object):
    def __init__(self, handler, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__handler = handler

    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        log.info('Collating message from {mailfrom}')
        subject = Parser().parsestr(data)['subject']
        log.debug(dict(to=rcpttos, sender=mailfrom, subject=subject, body=data))
        return self.__handler(to=rcpttos, sender=mailfrom, subject=subject, body=data)


class SmtpInbox(object):
    def __init__(self, port=None, address=None):
        self.port = port
        self.address = address
        self.collator = None

    def collate(self, collator):
        self.collator = collator
        return collator

    def serve(self, port=None, address=None):
        port = port or self.port
        address = address or self.address

        log.info(f'Starting SmtpServer at {address}:{port}')

        server = SmtpInboxServer(self.collator, (address, port), None, decode_data=True)

        try:
            asyncore.loop()
        except KeyboardInterrupt:
            log.info('Cleaning up')

    def dispatch(self):
        parser = argparse.ArgumentParser(description='Run an SmtpInbox server.')

        parser.add_argument('addr', metavar='addr', type=str, help='addr to bind to')
        parser.add_argument('port', metavar='port', type=int, help='port to bind to')

        args = parser.parse_args()

        self.serve(port=args.port, address=args.addr)


if __name__ == '__main__':
    inbox = SmtpInbox()

    @inbox.collate
    def handle(to, sender, subject, body):
        print(f'TO: {to}')
        print(f'SENDER: {sender}')
        print(f'SUBJECT: {subject}')
        print(f'BODY: {body}')


    inbox.serve(address='0.0.0.0', port=4467)
