from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from faker import Faker

from webmail.models import Message, MessageTo, MessageFrom

fake = Faker()


class Command(BaseCommand):
    help = 'Generates fake data for db'

    def add_arguments(self, parser):
        parser.add_argument('-u', '--users', type=int, default=0)
        parser.add_argument('-m', '--messages', type=int, default=0)

    @staticmethod
    def create_users(users):
        try:
            User.objects.get(username='user')
        except User.DoesNotExist:
            User.objects.create(username='user', password=make_password('user'), email='user@mail.com')

        offset_id = User.objects.count() + 1
        User.objects.bulk_create(
            [
                User(
                    username=(username := f'{fake.profile()["username"]}{offset_id + i}'),
                    password=make_password(username),
                    email=f'{username}@mail.com',
                )
                for i in range(users)
            ]
        )

    @staticmethod
    def fast_randint(mn, mx):
        return int(fake.random.random() * (mx - mn + 1)) + mn

    @staticmethod
    def create_messages(messages):
        user_emails = list(User.objects.values_list('email', flat=True))
        offset_id = Message.objects.count() + 1

        msgs = [
            {
                'emails': fake.random.sample(user_emails, Command.fast_randint(2, 4)),
                'subject': fake.sentence()[:-1],
                'body': fake.paragraph(15),
            }
            for _ in range(messages)
        ]

        Message.objects.bulk_create(
            [
                Message(
                    from_email=msgs[i]['emails'][0],
                    to_emails=' '.join(msgs[i]['emails'][1:]),
                    subject=msgs[i]['subject'],
                    body=msgs[i]['body'],
                )
                for i in range(messages)
            ]
        )

        MessageFrom.objects.bulk_create(
            [
                MessageFrom(
                    message_id=offset_id + i,
                    from_email=msgs[i]['emails'][0],
                )
                for i in range(messages)
            ]
        )

        message_tos = []
        for i, msg in enumerate(msgs):
            message_tos += [
                MessageTo(
                    message_id=offset_id + i,
                    to_email=email,
                )
                for email in msg['emails'][1:]
            ]

        MessageTo.objects.bulk_create(message_tos)

    def handle(self, *args, **options):
        if (users := options['users']) > 0:
            print(f'Generate {users} users')
            self.create_users(users)
        if (messages := options['messages']) > 0:
            print(f'Generate {messages} messages')
            self.create_messages(messages)
