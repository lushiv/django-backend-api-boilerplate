import requests
from rest_framework import status
from rest_framework.response import Response
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

from customer_app.util import add_notification, get_all_notifications
from . import util
import json
import sys
from common_util import custom_exceptions, ref_strings, models
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from . import form_validator as forms
import common_util.common_util

util.obj_admin.create_logger()

@api_view(['POST'])
@csrf_exempt
@util.obj_admin.who_is_hitting
def login_view(request, **kwargs):
    try:
        # Create Logger
        util.obj_admin.create_logger()

        post_data = json.loads(request.body)
        email = post_data.get('email', '')
        password = post_data.get('password', '')

        # Server Side Checks
        util.obj_admin.check_if_present(email, password)

        # Login
        params = util.admin_login(email, password)
        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'msg': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'msg': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request([])
def create_new_admin(request, **kwargs):
    try:
        # Create Logger
        util.obj_admin.create_logger()

        post_data = json.loads(request.body)
        print ("Inside create admin")
        new_user_email = post_data.get('new_user_email', '')
        password = post_data.get('password', '')
        password_confirm = post_data.get('password_confirm', '')
        first_name = post_data.get('first_name', '')
        last_name = post_data.get('last_name', '')
        role = int(post_data.get('role', 0))
        print(role)
        if role not in [2, 3]:
            raise custom_exceptions.UserException(ref_strings.Common.role_not_defined)
        if not password == password_confirm:
            raise custom_exceptions.UserException(ref_strings.Common.pasword_not_matching)
        # Server Side Checks
        # util.obj_admin.check_if_present(new_user_email, password, password_confirm, first_name, last_name, str(role))

        # Login
        params = util.create_new_admin(new_user_email, password,
                                       password_confirm, first_name, last_name, role)
        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('create_new_admin : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST'])
@util.obj_admin.who_is_hitting
def admin_email_verify(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_admin.create_logger()

            post_data = json.loads(request.body)
            token = request.GET.get('token')

            util.obj_admin.check_if_present(token)

            params = util.admin_email_verification(token)

            params['request_id'] = kwargs['request_id']
            return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST'])
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin'])  ##managers not allowd to cahnge pw
def changepassword(request, **kwargs):
    try:

        post_data = json.loads(request.body)

        uuid = kwargs.get('user_id', '')
        oldpassword = post_data.get('old_password', '')
        newpassword = post_data.get('new_password', '')
        confirm_password = post_data.get('confirm_password', '')

        # Server Side Checks
        util.obj_admin.check_if_present(uuid, oldpassword, newpassword, confirm_password)

        # server side django validation
        form = forms.PasswordForm(post_data)
        valid = form.is_valid()
        if not valid:
            msg = {'message': ref_strings.Common.invalid_form_data}
            for key, value in form.errors.items():
                msg[key] = value[0]
            return util.obj_admin.error_response(msg)

        params = util.changepw(uuid, oldpassword, newpassword, confirm_password)
        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('change password : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def list_all_customer(request, **kwargs):
    try:
        current_page = int(request.GET.get('currentpage', 1))
        per_page = int(request.GET.get('perpage', 10))
        email = request.GET.get('email', None)
        sort = request.GET.get('sort', 'asc')
        order = request.GET.get('order', 'timestamp')
        filters = {
            'email': email
        }
        order_dict = {
            'sort_item': sort,
            'order_item': order
        }
        pagination = {
            'current_page': current_page,
            'per_page': per_page
        }

        params = util.list_all_customer(filters, order_dict, pagination)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.new_success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request([])
def list_all_admins(request, **kwargs):
    try:
        current_page = int(request.GET.get('currentpage', 1))
        per_page = int(request.GET.get('perpage', 10))
        email = request.GET.get('email', None)
        sort = request.GET.get('sort', 'asc')
        order = request.GET.get('order', 'created_at')
        filters = {
            'email': email
        }
        order_dict = {
            'sort_item': sort,
            'order_item': order
        }
        pagination = {
            'current_page': current_page,
            'per_page': per_page
        }

        params = util.list_all_admin(filters, order_dict, pagination)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.new_success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request([])
def delete_admin(request, **kwargs):
    try:
        post_data = json.loads(request.body)

        uuid = post_data.get('id', '')
        # Server Side Checks
        util.obj_admin.check_if_present(uuid)

        # server side django validation
        params = util.delete_admin(uuid)
        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def get_customer_detail(request, **kwargs):
    try:
        uuid = request.GET.get('id', None)
        util.obj_admin.check_if_present(uuid)
        params = util.get_customer_detail(uuid)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.new_success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def customer_status_list(request, **kwargs):
    try:
        params = util.customer_status_list()
        params['request_id'] = kwargs['request_id']
        return util.obj_admin.new_success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin'])
def customer_status_change(request, **kwargs):
    try:
        post_data = json.loads(request.body)
        status = post_data.get('status')

        uuid = post_data.get('uuid')

        util.obj_admin.check_if_present(uuid, status)

        params = util.customer_status_change(uuid, status)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request([])
def delete_customer(request, **kwargs):
    try:
        post_data = json.loads(request.body)

        uuid = post_data.get('id', '')
        # Server Side Checks
        util.obj_admin.check_if_present(uuid)

        # server side django validation
        params = util.delete_customer(uuid)
        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})



@api_view(['POST'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def disble_user_2fa(request, **kwargs):
    try:
        from customer_app.util import disable_2fa
        post_data = json.loads(request.body)
        email = post_data.get('email', '')
        util.obj_admin.check_if_present(email)
        params = disable_2fa(email=email, admin_call=True)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})




@api_view(['GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def get_contact_us_detail(request, **kwargs):
    try:
        current_page = int(request.GET.get('currentpage', 1))
        per_page = int(request.GET.get('perpage', 10))
        email = request.GET.get('email', None)
        resolved_status = request.GET.get('resolved_status', None)
        sort = request.GET.get('sort', 'asc')
        order = request.GET.get('order', 'created_at')
        filters = {
            'email': email,
            'resolved_status': resolved_status
        }
        order_dict = {
            'sort_by': sort,  ## key
            'order': order  ## asc dsc
        }
        pagination = {
            'current_page': current_page,
            'per_page': per_page
        }

        params = util.get_contact_us_detail(filters, order_dict, pagination)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.new_success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST', 'DELETE'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def contact_us_status_change(request, **kwargs):
    try:
        post_data = json.loads(request.body)
        uuid = post_data.get('id')
        resolved_status = post_data.get('resolved')

        if request.method == 'DELETE':
            params = util.contact_us_status_change(uuid, resolved_status, delete=True)
        else:
            util.obj_admin.check_if_present(uuid, resolved_status)
            params = util.contact_us_status_change(uuid, resolved_status)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})