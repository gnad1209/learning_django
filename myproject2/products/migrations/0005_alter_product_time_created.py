# Generated by Django 5.0.1 on 2024-01-18 07:27

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('products', '0004_alter_product_time_created'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='time_created',
            field=models.DateTimeField(default=datetime.datetime(2024, 1, 18, 14, 27, 12, 311600)),
        ),
    ]