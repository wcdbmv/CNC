#!/usr/bin/env python3

from smpt_server import SmtpServer
import asyncore
import argparse
from email.parser import Parser
import logging
import sqlite3
import datetime

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

    try:
        connection = sqlite3.connect('backend/db.sqlite3')
        cursor = connection.cursor()
    except sqlite3.Error:
        print('Failed to connect to database')
        exit(1)


    @inbox.collate
    def handle(to, sender, subject, body):
        try:
            time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                f'INSERT INTO webmail_message '
                f'(from_email, time, subject, body) '
                f'VALUES '
                f'(\"{sender}\", \"{time}\", \"{subject}\", \"{body}\")'
            )
            message_id = cursor.lastrowid
            for recipient in to:
                cursor.execute(
                    f'INSERT INTO webmail_messageto'
                    f'(to_email, message_id)'
                    f'VALUES'
                    f'(\"{recipient}\", \"{message_id}\")'
                )
            connection.commit()
        except sqlite3.Error as e:
            print('Failed to insert data:', e)


    inbox.serve(address='0.0.0.0', port=4467)

    cursor.close()
    connection.close()
