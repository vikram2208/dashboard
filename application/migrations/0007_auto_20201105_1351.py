# Generated by Django 3.1.3 on 2020-11-05 13:51

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('application', '0006_auto_20201105_1348'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='created',
            field=models.DateField(default=django.utils.timezone.now),
        ),
    ]
