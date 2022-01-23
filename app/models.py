import uuid

from django.db import models

# Create your models here.

TICKET_STATUS = (
    ('pending', 'pending'),
    ('resolve', 'resolve'),
    ('reopen', 'reopen'),
)


SUPPORT_TICKET_CATEGORY = (
    ('kyc', 'KYC issue'),  # (DB VAL , LABEL)
    ('transaction_1', 'Balance Receive'),
    ('transaction_2', 'Balance Forward'),
    ('user_security', 'Password and account access'),
    ('operational', 'Business Solutions')
)


class SupportTicket(models.Model):
    id = models.AutoField(primary_key=True)
    uuid = models.CharField(max_length=50, null=False, blank=False)
    category = models.CharField(max_length=256, choices=SUPPORT_TICKET_CATEGORY)
    subject = models.CharField(max_length=256)
    message = models.TextField()
    status = models.CharField(max_length=16, choices=TICKET_STATUS, default='pending')
    user_id = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=256, null=True, blank=True)
    modified_at = models.DateTimeField(blank=True, null=True)
    modified_by = models.CharField(max_length=256, null=True, blank=True)
    deleted_by = models.CharField(max_length=256, null=True, blank=True)
    deleted_at = models.DateTimeField(blank=True, null=True)
    deleted = models.BooleanField(null=True, default=0)


class TicketMessage(models.Model):
    ticket_id = models.CharField(max_length=256, null=True, blank=True)
    message = models.CharField(max_length=1200)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_user_message = models.BooleanField(default=0)
    is_admin_message = models.BooleanField(default=0)

    def __str__(self):
        return self.message

    class Meta:
        ordering = ('timestamp', )


KYC_STATUS = (
    ('reject', 'Reject'),
    ('approve', 'Approve'),
    ('pending', 'Pending')
)


KYC_DOCUMENT_TYPE = (
    ('passport', 'Passport'),
    ('liscense', 'Liscense')
)


class KYCManagement(models.Model):
    user_id = models.CharField(max_length=256, blank=True)
    first_name = models.CharField(max_length=256,  blank=True)
    last_name = models.CharField(max_length=256,  blank=True)
    resident = models.CharField(max_length=40,  blank=True)
    verification_type = models.CharField(max_length=40, choices=KYC_DOCUMENT_TYPE, blank=True)
    id_number = models.CharField(max_length=40,  blank=True)
    identification_verification_front = models.TextField()
    identification_verification_back = models.TextField()
    hand_held_identification = models.TextField()
    status = models.CharField(max_length=8, choices=KYC_STATUS, default='pending')
    rejected = models.BooleanField(default=False, blank=True)
    reject_reason= models.CharField(max_length=256, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    deleted = models.BooleanField(null=True, default=0)


    class Meta:
        ordering = ('timestamp', )


NOTIFICATION_CHOICES = (
    ('KYC', 'KYC'),
    ('SUPPORT_TICKET', 'SUPPORT_TICKET'),
    ('CHAT', 'CHAT'),
    ('', '')
)


class Notification(models.Model):
    notification = models.CharField(max_length=255)
    user_id = models.CharField(max_length=256, blank=True)
    is_read = models.BooleanField(default=False)
    ticket = models.CharField(max_length=255, blank=True, null=True)
    username = models.CharField(max_length=255, blank=True, null=True)
    url = models.CharField(max_length=255, blank=True, null=True)
    event = models.CharField(max_length=24, choices=NOTIFICATION_CHOICES, default='')
    kyc_id = models.IntegerField(blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-timestamp', )
