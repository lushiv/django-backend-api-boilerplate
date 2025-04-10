# Generated by Django 3.1.2 on 2021-05-09 08:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='supportticket',
            name='category',
            field=models.CharField(choices=[('kyc', 'KYC issue'), ('transaction_1', 'Balance Receive'), ('transaction_2', 'Balance Forward'), ('user_security', 'Password and account access'), ('operational', 'Business Solutions')], max_length=256),
        ),
        migrations.AlterField(
            model_name='supportticket',
            name='uuid',
            field=models.UUIDField(default='c39f68c2864c49ac94a2a6a9de268497', editable=False, unique=True),
        ),
    ]
