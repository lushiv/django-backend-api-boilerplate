from rest_framework import serializers
from app.models import SupportTicket, TicketMessage, KYCManagement, Notification


class SupportTicketModelSerializer(serializers.ModelSerializer):

    class Meta:
        model = SupportTicket
        fields = "__all__"
        read_only_fields = ['created_at', 'deleted_at']


class GetSupportTicketModelSerializer(serializers.ModelSerializer):
    ticket_id = serializers.SerializerMethodField('get_ticket_id')

    def get_ticket_id(self, obj):
        return obj.uuid

    class Meta:
        model = SupportTicket
        fields = ['category', 'subject', 'message', 'status', 'user_id', 'created_at', 'ticket_id']


class TicketMessageModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = TicketMessage
        fields = '__all__'


class KYCManagementModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = KYCManagement
        fields = '__all__'


class NotificationsModelSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notification
        exclude = ('user_id', 'url')
