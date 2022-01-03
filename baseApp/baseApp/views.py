import sys
from rest_framework import status
from rest_framework.response import Response
import django.utils.timezone as tz
import boto3
from django.conf import settings
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger


def login(request, **kwargs):
    """
    Login
    :param request: email, password
    :return: status, msg, role
    """
    if request.method == 'POST':
        pass