# Generated by Django 5.0.1 on 2024-01-19 02:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0003_customuser_address_alter_customuser_is_active_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='phone_number',
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
    ]