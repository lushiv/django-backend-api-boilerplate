import sys
from rest_framework import status
from rest_framework.response import Response
import django.utils.timezone as tz
import boto3
from django.conf import settings
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

import common_util.common_util
from . import util
from common_util import custom_exceptions, ref_strings, models
from django.views.decorators.csrf import csrf_exempt
import json
from . import form_validation as forms
from rest_framework.decorators import api_view
import requests
from rest_framework.response import Response

user_decorators = [csrf_exempt,  util.obj_common.who_is_hitting, util.obj_common.validate_request([ 'customer'])]


@api_view(['POST'])
@csrf_exempt
@util.obj_common.who_is_hitting
def login(request, **kwargs):
    """
    Login
    :param request: email, password
    :return: status, msg, role
    """
    if request.method == 'POST':
        try:

            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)
            email = post_data.get('email', '')
            password = post_data.get('password', '')

            # Server Side Checks
            util.obj_common.check_if_present(email, password)

            # Login
            params = util.login(email, password)
            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

        except custom_exceptions.UserException as e:
            return util.obj_common.error_response({'msg': str(e), 'request_id': kwargs.get('request_id')}, 400)

        except Exception as e:
            error = util.common_util.get_error_traceback(sys, e)
            util.obj_common.logger.error_logger('login : %s' % error)
            return util.obj_common.error_response({'msg': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST'])
@csrf_exempt
@util.obj_common.who_is_hitting
def signup(request, **kwargs):
    if request.method == 'POST':
        try:

            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)
            email = post_data.get('email', '')
            password = post_data.get('password', '')
            username = post_data.get('username', '')

            # Server Side Checks
            util.obj_common.check_if_present(email, password, username)

            # signup the user
            params = util.signup(email, password, username)
            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

        except custom_exceptions.UserException as e:
            return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

        except Exception as e:
            error = util.common_util.get_error_traceback(sys, e)
            util.obj_common.logger.error_logger('signup : %s' % error)
            return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['DELETE'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer'])
def logout(request, **kwargs):
    try:
        return util.obj_common.success_response({})

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'msg': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('login : %s' % error)
        return util.obj_common.error_response({'msg': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST', 'GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer'])
def enable_2fa(request, **kwargs):
    if request.method == 'POST':
        try:
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)
            email = post_data.get('email', '')
            reenable = post_data.get('reenable', False)  # in case re enable

            # Server Side Checks
            util.obj_common.check_if_present(email)

            # Login
            params = util.enable_2fa(email, reenable)
            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

        except custom_exceptions.UserException as e:
            return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

        except Exception as e:
            error = util.common_util.get_error_traceback(sys, e)
            util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
            return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST', 'GET'])
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer'])
def verify_otp(request, **kwargs):
    if request.method == 'POST':
        try:

            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)
            email = post_data.get('email', '')
            otp = post_data.get('otp', '')

            # Server Side Checks
            util.obj_common.check_if_present(email, otp)

            # Login
            params = util.verify_otp(email, otp)
            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

        except custom_exceptions.UserException as e:
            return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

        except Exception as e:
            error = util.common_util.get_error_traceback(sys, e)
            util.obj_common.logger.error_logger('verify otp : %s' % error)
            return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST', 'GET'])
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer','admin','manager'])
def disable_2fa(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)
            email = post_data.get('email', '')
            otp = post_data.get('otp', '')

            util.obj_common.check_if_present(email, otp)

            params = util.disable_2fa(email, otp)

            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST', 'GET'])
@util.obj_common.who_is_hitting
def multifactor_login(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)
            email = post_data.get('email', '')
            otp = post_data.get('otp', '')
            adminCall = post_data.get('is_admin', False)

            util.obj_common.check_if_present(email, otp)

            params = util.multifactor_login(email, otp, adminCall)

            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST', 'GET'])
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer', 'admin', 'manager'])
def get_general_info(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)
            email = post_data.get('email', '')
            is_admin = post_data.get('is_admin', False)

            util.obj_common.check_if_present(email)

            params = util.get_general_info(email, is_admin)

            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST'])
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer'])
def changepassword(request, **kwargs):
    try:
        util.obj_common.create_logger()

        post_data = json.loads(request.body)

        email = post_data.get('email', '')
        oldpassword = post_data.get('old_password', '')
        newpassword = post_data.get('new_password', '')

        # Server Side Checks
        util.obj_common.check_if_present(email, oldpassword, newpassword)

        # server side django validation
        form = forms.PasswordForm(post_data)
        valid = form.is_valid()
        if not valid:
            msg = {'message': ref_strings.Common.invalid_form_data}
            for key, value in form.errors.items():
                msg[key] = value[0]
            return util.obj_common.error_response(msg)

        params = util.changepw(email, oldpassword, newpassword)
        params['request_id'] = kwargs['request_id']
        return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('change password : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id' : kwargs.get('request_id')})



@csrf_exempt
@api_view(['POST'])
@util.obj_common.who_is_hitting
def email_verify(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)
            token = request.GET.get('token')
            event_name = request.GET.get('event_name')

            util.obj_common.check_if_present(token)

            params = util.email_verification(token)

            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id' : kwargs.get('request_id')})




@csrf_exempt
@api_view(['POST'])
@util.obj_common.who_is_hitting
def forget_password_request(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)
            email = post_data.get('email', '')

            util.obj_common.check_if_present(email)

            params = util.forget_password(email)

            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id' : kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST'])
@util.obj_common.who_is_hitting
def reset_password(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)

            token = post_data.get('token')
            new_password = post_data.get('new_password')
            cofirm_password = post_data.get('confirm_password')

            util.obj_common.check_if_present(token, new_password, cofirm_password)

            params = util.reset_password(token, new_password, cofirm_password)

            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('reset_password : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id' : kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST'])
@util.obj_common.who_is_hitting
def token_validation(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)

            token = request.GET.get('token')

            util.obj_common.check_if_present(token)

            params = util.token_validation(token)

            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id' : kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST'])
@util.obj_common.who_is_hitting
def contact_us(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)

            name = post_data.get('name', '')
            email = post_data.get('email')
            subject = post_data.get('subject')
            message = post_data.get('message')

            util.obj_common.check_if_present(email,subject,message)

            params = util.contact_us(name, email, subject, message)

            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id' : kwargs.get('request_id')})



@api_view(["POST"])
@csrf_exempt
@util.obj_common.who_is_hitting
def resend_email(request, **kwargs):
    try:
        util.obj_common.create_logger()

        post_data = json.loads(request.body)

        email = post_data.get('email')
        event_name = post_data.get('event_name')

        util.obj_common.check_if_present(email,  event_name)

        params = util.resend_email(email,  event_name)

        params['request_id'] = kwargs['request_id']
        return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id' : kwargs.get('request_id')})