# Generated by Django 3.1.4 on 2020-12-19 20:31

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('from_email', models.CharField(max_length=254)),
                ('time', models.DateTimeField()),
                ('subject', models.TextField()),
                ('body', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='MessageTo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('to_email', models.CharField(max_length=254)),
                ('message', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='recipient', to='webmail.message')),
            ],
        ),
    ]
