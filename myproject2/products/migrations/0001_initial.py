# Generated by Django 5.0.1 on 2024-01-18 04:07

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.IntegerField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255, unique=True)),
                ('describe', models.CharField(max_length=255)),
                ('time_created', models.DateTimeField(default=datetime.datetime(2024, 1, 18, 11, 7, 44, 341042))),
            ],
        ),
    ]