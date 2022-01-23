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




@api_view(['POST','DELETE'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def import_watch_address(request, **kwargs):
    try:
        if request.method == 'POST':
            from bitcoin_wallet.btc_util import import_watch_only_address

            post_data = json.loads(request.body)

            email = post_data.get('email', '')
            address = post_data.get('address', '')
            label = post_data.get('label', '')
            # Server Side Checks
            util.obj_admin.check_if_present(email, address, label)
            params = import_watch_only_address(email, label, address)

        if request.method == 'DELETE':
            if kwargs.get('role') in ['admin', 'manager']:
                return Response({'message': 'Unauthorized User'}, status=status.HTTP_401_UNAUTHORIZED)
            from bitcoin_wallet.btc_util import archive_address
            post_data = json.loads(request.body)
            email = post_data.get('email', '')
            address = post_data.get('address', '')
            util.obj_admin.check_if_present(email, address)
            params = archive_address(email, address)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['PUT', 'GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin'])
def deleted_address(requests, **kwargs):
    try:
        if requests.method == 'GET':

            current_page = int(requests.GET.get('currentPage', 1))
            per_page = int(requests.GET.get('perPage', 10))
            sort = requests.GET.get('sort', 'desc')
            address = requests.GET.get('address', False)
            email = requests.GET.get('email', False)
            filters = {
                'address': address,
                'email' : email
            }
            order_dict = {
                'sort_item': sort
            }
            pagination = {
                'current_page': current_page,
                'per_page': per_page
            }

            params = util.get_deleted_addresses(filters, order_dict, pagination)


            params['request_id'] = kwargs['request_id']
            return util.obj_admin.new_success_response(params)
        if requests.method == 'PUT':
            address = requests.GET.get('address', False)
            if not address:
                raise custom_exceptions.UserException(ref_strings.Common.missing_input_params)
            
            params = util.restore_deleted_addresses(address)
            return util.obj_admin.new_success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['PUT'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin'])
def update_address_balance(requests, **kwargs):
    try:
        from bitcoin_wallet.btc_util import update_address_balance
        address = requests.GET.get('address', False)
        if not address:
            raise custom_exceptions.UserException(ref_strings.Common.missing_input_params)
        params = update_address_balance(address)
        balance= (params.get('balance_data')).get('balance')
        message = 'Balance Updated to  {} btc'.format(balance)
        params['message'] = message
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


@api_view(['POST', 'GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def admin_support_ticket(request, **kwargs):
    try:

        if request.method == 'GET':
            tickets = SupportTicket.objects.all()
            tickets = tickets.filter(deleted=0)

            # find on basis of status
            if request.query_params.get('status', None):
                tickets = tickets.filter(status=request.query_params.get('status', None)) # ticekt status : pending resolved reopen

            # find on basis of email
            if request.query_params.get('email', None):
                user_data= util.get_user_id_by_email(request.query_params.get('email', None))
                tickets = tickets.filter(user_id=user_data.get('uuid'))

            # find on basis of id
            if request.query_params.get('id', None):
                tickets = tickets.filter(uuid=request.query_params.get('id', None))

            if request.query_params.get('sort', None) == 'aes': ##on basis of created_at and staus
                tickets = tickets.order_by('-created_at')
            elif request.query_params.get('sort', None) == 'desc':
                tickets = tickets.order_by('created_at')
            elif request.query_params.get('sort', None) == 'status':
                tickets = tickets.order_by('status')
            else:
                tickets = tickets.order_by('-created_at')

            pagination_data = {}
            current_page = int(request.query_params.get('currentPage', 1))
            per_page = int(request.query_params.get('perPage', 10))
            paginator = Paginator(tickets, per_page)
            try:
                tickets = paginator.page(current_page)
            except PageNotAnInteger:
                tickets = paginator.page(1)
            except EmptyPage:
                tickets = paginator.page(paginator.num_pages)
            pagination_data['current_page'] = current_page
            pagination_data['per_page'] = per_page
            pagination_data['total_count'] = paginator.count


            serializer = GetSupportTicketModelSerializer(tickets, many=True)
            support_ticket_ordered_list = serializer.data

            data_list = []

            for single_support_ticekt in support_ticket_ordered_list:
                try:
                    user_info = util.get_user_info_using_uuid(single_support_ticekt.get('user_id'))
                    single_support_ticekt.update(user_info)
                    data_list.append(single_support_ticekt)
                except Exception as e:
                    pass
            
            return_data = {
                'data': data_list,
                'pagination_data': pagination_data
            }
            

            return Response( return_data, status=status.HTTP_200_OK)


        if request.method == 'POST': ## for delete
            SupportTicket.objects.filter(uuid=request.data['ticket_id']).update(deleted=1, deleted_by=kwargs['user_id'])

            return Response({"status": status.HTTP_200_OK}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def create_support_ticket(request, **kwargs):
    try:
        request.data['user_id'] = request.data.get('user_id', None)
        request.data['uuid'] = common_util.common_util.get_uuid()
        serializer = SupportTicketModelSerializer(data=request.data)
        if not serializer.is_valid():
            raise custom_exceptions.UserException('Data validation Error ')
        serializer.save()
        notification = 'Admin has created new ticket.'
        add_notification(request.data['user_id'], notification, event='SUPPORT_TICKET',
                         ticket=serializer.data.get('uuid'))
        params = {'message': ref_strings.Common.support_ticket_sucess, 'ticket_id': serializer.data.get('uuid'),
                  'request_id': kwargs['request_id']}

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
def get_kyc_detail(request, **kwargs):
    try:
        kyc = KYCManagement.objects.all()
        if request.query_params.get('kyc_id', None):
            try:
                kyc = kyc.get(id=request.query_params.get('kyc_id'), deleted=False)
            except :
                return_data = {
                    'data': [],
                    'message': 'Data Not found'
                }
                return Response(return_data, status=status.HTTP_200_OK)

            user_info = util.get_kyc_detail(request.query_params.get('kyc_id'))
            serializer = KYCManagementModelSerializer(kyc)
            return_data = serializer.data
            return_data.update(user_info)
            return Response(return_data, status=status.HTTP_200_OK)

        if request.query_params.get('email', None):
            user_data= util.get_user_id_by_email(request.query_params.get('email', None))            
            try:
                kyc = kyc.filter(user_id=user_data.get('uuid'), deleted =False)
            except:
                return_data = {
                    'data': [],
                    'message': 'Data Not found'
                }
                return Response(return_data, status=status.HTTP_200_OK)

        kyc = kyc.filter(deleted=False)

        if request.query_params.get('status', None):
            kyc = kyc.filter(status=request.query_params.get('status', None))

        if request.query_params.get('sort', None) == 'aes':
            kyc = kyc.order_by('timestamp')
        elif request.query_params.get('sort', None) == 'desc':
            kyc = kyc.order_by('-timestamp')
        elif request.query_params.get('sort', None) == 'status':
            kyc = kyc.order_by('status')
        else:
            kyc = kyc.order_by('-timestamp')

        # kyc = kyc.get(deleted=False)

        pagination_data = {}
        current_page = int(request.query_params.get('currentPage')) if request.query_params.get('currentPage') != '' else 1
        per_page = int(request.query_params.get('perPage')) if request.query_params.get('perPage') != '' else 10
        paginator = Paginator(kyc, per_page)
        try:
            kyc = paginator.page(current_page)
        except PageNotAnInteger:
            kyc = paginator.page(1)
        except EmptyPage:
            kyc = paginator.page(paginator.num_pages)            
        pagination_data['current_page'] = current_page
        pagination_data['per_page'] = per_page
        pagination_data['total_count'] = paginator.count


        serializer = KYCManagementModelSerializer(kyc, many=True)
        return_data = {
            'data': serializer.data,
            'pagination_data': pagination_data
        }
        return Response(return_data, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('support_ticket_category : %s' % error)
        return util.obj_admin.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST', 'GET','DELETE'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def change_kyc_status(request, **kwargs):
    try:
        post_data = json.loads(request.body)
        notification=''
        kyc_id = post_data.get('kyc_id', None)
        kyc_status = post_data.get('status', None)

        if request.method == 'DELETE':
            if kwargs.get('role') in ['admin', 'manager']:
                return Response({'message': 'Unauthorized User'}, status=status.HTTP_401_UNAUTHORIZED)
            KYCManagement.objects.filter(id=kyc_id).update(deleted=True)
            return Response({'message': 'Kyc Deleted Successfully'}, status=status.HTTP_200_OK)

        kyc = KYCManagement.objects.filter(id=kyc_id, rejected = False)
        if not kyc.count() > 0:
            raise custom_exceptions.UserException(ref_strings.Common.cannot_change_kyc_status)
        user_id = kyc[0].user_id
        update_field ={
            'status' : kyc_status
        }
        if kyc_status == 'reject':
            notification = 'Admin has rejected your kyc.'
            reject_reason = post_data.get('reason', 'N/A')
            util.obj_admin.check_if_present(kyc_id, kyc_status, reject_reason)
            update_field.update({
                'rejected' : True,
                'reject_reason' : reject_reason,
            })
    
        kyc.update(**update_field)
        if kyc_status == 'approve':
            notification = 'Admin has approved your kyc.'
            util.approve_user_kyc(user_id=user_id, status=1)
        add_notification(user_id, notification, event='KYC')
        return Response({'message': 'Kyc status Updated'}, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('change_kyc_status : %s' % error)
        return util.obj_admin.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def get_admin_notifications(request, **kwargs):
    try:
        context = get_all_notifications(request=request)

        return Response(context, status=status.HTTP_200_OK)
    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('admin_notifications : %s' % error)
        return util.obj_admin.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


#@add new investment plans 
@api_view(['POST'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def add_new_investment_plan(request, **kwargs):
    try:
        # Create Logger
        util.obj_admin.create_logger()

        post_data = json.loads(request.body)
        print ("adding new investment plan")

        plan_name = post_data.get('plan_name', '')
        #check the plan name is alreday exist or not
        check_plan_name = util.check_investment_plan_exist_or_not(plan_name)


        #input requested data
        payload = {
            "plan_name" : plan_name,
            "minimum_investment" : post_data.get('minimum_investment', ''),
            "maximum_investment" : post_data.get('maximum_investment', ''),
            "profit" : post_data.get('profit', ''),
            "Instant_withdrawal" : post_data.get('Instant_withdrawal', ''),
            "capital_security" : post_data.get('capital_security', '')
        }
        
        # instert into investment_plans tbl
        params = util.add_new_investment_plans(payload)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('add_new_investment_plan : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})

#@get all investment plans list
@api_view(['GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def get_investment_plans_list(request, **kwargs):
    try:
        #@pagination request
        current_page = int(request.GET.get('currentpage', 1))
        per_page = int(request.GET.get('perpage', 10))

        #@shorting and ordering request
        sort = request.GET.get('sort', 'asc')
        order = request.GET.get('order', 'created_at')

        #@filter and search request
        plan_name = request.GET.get('plan_name', None)
        minimum_investment = request.GET.get('minimum_investment', None)

        filters = {
            'plan_name': plan_name,
            'minimum_investment': minimum_investment
        }

        order_dict = {
            'sort_by': sort,  ## key
            'order': order  ## asc dsc
        }
        pagination = {
            'current_page': current_page,
            'per_page': per_page
        }

        params = util.get_investment_plans_list(filters, order_dict, pagination)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.new_success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})

#@investment plans details api
@api_view(['GET'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def view_investment_plan_details(request, **kwargs):
    try:
        uuid = request.GET.get('id', None)
        util.obj_admin.check_if_present(uuid)
        params = util.view_investment_plan_details(
            logger=util.obj_admin.logger,
            uuid=uuid
        )

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.new_success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})

#@ update and edit the invesyment plans details api
@api_view(['PUT'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def edit_investment_plan(requests, **kwargs):
    try:
        #Create Logger
        util.obj_admin.create_logger()

        post_data = json.loads(requests.body)
        print ("editing investment plan details")
        uuid = post_data.get('uuid', '')

        #input requested data
        payload = {
            "plan_name" : post_data.get('plan_name', ''),
            "minimum_investment" : post_data.get('minimum_investment', ''),
            "maximum_investment" : post_data.get('maximum_investment', ''),
            "profit" : post_data.get('profit', ''),
            "Instant_withdrawal" : post_data.get('Instant_withdrawal', ''),
            "capital_security" : post_data.get('capital_security', ''),
            "status" : post_data.get('status', '')

        }
        # update into investment_plans tbl
        params = util.update_investment_plan(uuid,payload)

        params['request_id'] = kwargs['request_id']
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('edit_investment_plan : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


#@delete investment plan
@api_view(['POST'])
@csrf_exempt
@util.obj_admin.who_is_hitting
@util.obj_admin.validate_request(['admin', 'manager'])
def delete_investment_plan(request, **kwargs):
    try:
        post_data = json.loads(request.body)

        uuid = post_data.get('id', '')
        # Server Side Checks
        util.obj_admin.check_if_present(uuid)
        # server side django validation
        params = util.delete_investment_plan(uuid)
        params['request_id'] = kwargs['request_id']
        params['message'] = ref_strings.Common.investment_deleted
        return util.obj_admin.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_admin.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_admin.logger.error_logger('login : %s' % error)
        return util.obj_admin.error_response(
            {'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})