#!/usr/bin/env python3

from contextlib import closing
from smpt_server import SmtpServer
import asyncore
import argparse
from email.parser import Parser
import logging
import sqlite3
import datetime

log = logging.Logger(__name__)

DATABASE = 'db.sqlite3'


def execute_statement(query):
    lastrowid = None
    with closing(sqlite3.connect(DATABASE)) as connection, connection, closing(connection.cursor()) as cursor:
        cursor.execute(query)
        lastrowid = cursor.lastrowid
    return lastrowid


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
        if subject is None:
            subject = ''
        try:
            time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message_id = execute_statement(
                f'INSERT INTO webmail_message '
                f'(from_email, to_emails, time, subject, body) '
                f'VALUES '
                f'(\"{sender}\", \"{" ".join(to)}\", \"{time}\", \"{subject}\", \"{body[10 + len(subject):]}\")'
            )
            execute_statement(
                f'INSERT INTO webmail_messagefrom'
                f'(from_email, message_id)'
                f'VALUES'
                f'(\"{sender}\", \"{message_id}\")'
            )
            for recipient in to:
                execute_statement(
                    f'INSERT INTO webmail_messageto'
                    f'(to_email, message_id)'
                    f'VALUES'
                    f'(\"{recipient}\", \"{message_id}\")'
                )
        except sqlite3.Error as e:
            print('Failed to insert data:', e)


    inbox.serve(address='0.0.0.0', port=4467)
