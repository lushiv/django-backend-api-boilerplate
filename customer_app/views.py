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

from .util import add_notification, check_message_is_read, get_all_notifications

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
            referral_token = post_data.get('referral_token', '')

            # Server Side Checks
            util.obj_common.check_if_present(email, password, username)

            # Login
            params = util.signup(email, password, username, referral_token)
            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

        except custom_exceptions.UserException as e:
            return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

        except Exception as e:
            error = util.common_util.get_error_traceback(sys, e)
            util.obj_common.logger.error_logger('login : %s' % error)
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
def kyc_storage(request, **kwargs):
    try:
        if request.method == 'POST':
            # create a logger
            util.obj_common.create_logger()

            post_data = json.loads(json.dumps(request.POST))

            dob_year = post_data.get("dob_year", '')
            dob_month = post_data.get("dob_month", '')
            dob_date = post_data.get("dob_date", '')

            util.obj_common.check_if_present(dob_year, dob_month, dob_date)

            date_of_birth = util.changetodate(dob_year, dob_month, dob_date)
            post_data["dob"] = date_of_birth

            kyc_file_obj = request.FILES.get('file')
            # server side validation
            form = forms.KYCForm(post_data)

            if not form.is_valid():
                raise custom_exceptions.UserException(form.errors)

            kyc_data = form.cleaned_data
            kyc_data["dob"] = date_of_birth

            params = util.set_kyc(kyc_data, kyc_file_obj)
            params['request_id'] = kwargs['request_id']
            return util.obj_common.success_response(params)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('kyc storage : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@csrf_exempt
@api_view(['POST'])
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer'])
def get_kyc_data(request, **kwargs):
    try:
        util.obj_common.create_logger()

        post_data = json.loads(request.body)
        email = post_data.get('email')
        kyc_data = util.get_kyc(email)

        kyc_data['request_id'] = kwargs['request_id']
        return util.obj_common.success_response(kyc_data)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')})

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('kyc storage : %s' % error)
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


@api_view(['GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer'])
def support_ticket_category(request, **kwargs):
    try:
        from app.models import SUPPORT_TICKET_CATEGORY
        data = [{category[1]: category[0]} for category in SUPPORT_TICKET_CATEGORY]
        return Response({'data': data, 'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('support_ticket_category : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})




@api_view(['POST', 'GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer'])
def support_ticket(request, ticket_id=None, **kwargs):
    try:
        if request.method == 'POST':
            request.data['user_id'] = kwargs['user_id']
            request.data['uuid'] = common_util.common_util.get_uuid()
            serializer = SupportTicketModelSerializer(data=request.data)
            if not serializer.is_valid():
                raise custom_exceptions.UserException('Data validation Error ')
            print(serializer.validated_data)
            serializer.save()
            notification = 'User has created new ticket.'
            username = util.get_user_info_using_uuid(kwargs.get('user_id', None))
            add_notification('', notification, event='SUPPORT_TICKET', ticket=serializer.data.get('uuid'), username=username)
            params = {'message': ref_strings.Common.support_ticket_sucess, 'ticket_id': serializer.data.get('uuid'),
                      'request_id': kwargs['request_id']}

            return util.obj_common.success_response(params)

        if request.method == 'GET':
            if ticket_id: #single ticket
                tickets = SupportTicket.objects.get(uuid=ticket_id, user_id=kwargs['user_id'], deleted=0)
                serializer = GetSupportTicketModelSerializer(tickets)

            else: #all ticeket
                tickets = SupportTicket.objects.filter(user_id=kwargs['user_id'], deleted=0)
                tickets = tickets.order_by('-created_at')

                if request.query_params.get('status', None):
                    tickets = tickets.filter(status=request.query_params.get('status', None))


                pagination_data = {}
                current_page = int(request.query_params.get('currentPage')) if request.query_params.get('currentPage') != '' else 1
                per_page = int(request.query_params.get('perPage')) if request.query_params.get('perPage') != '' else 10
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

                return_data = {
                    'data': serializer.data,
                    'pagination_data': pagination_data                    
                }

            return Response(return_data, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('support_ticket_category : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST', 'GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer'])
def ticket_messages(request, ticket_id=None, **kwargs):
    if request.method == 'POST':
        message = TicketMessage.objects.create(**request.data)
        serializer = TicketMessageModelSerializer(message)

        if kwargs['role'] == 'admin':
            try:
                notification = 'admin has sent you a message.'
                ticket = SupportTicket.objects.get(uuid=message.ticket_id)
                is_already_mess = check_message_is_read(ticket.uuid, ticket.user_id)
                if not is_already_mess:
                    add_notification(ticket.user_id, notification, ticket.uuid, event='CHAT')
            except SupportTicket.DoesNotExist:
                pass
        if kwargs['role'] == 'customer':
            notification = 'customer has sent you a message.'
            ticket = SupportTicket.objects.get(uuid=message.ticket_id)
            is_already_mess = check_message_is_read(ticket.uuid, '')
            if not is_already_mess:
                username = util.get_user_info_using_uuid(kwargs.get('user_id', None))
                add_notification('', notification, event='CHAT', ticket=serializer.data['ticket_id'], username=username)

        return Response({'data': serializer.data}, status=status.HTTP_201_CREATED)

    if request.method == 'GET':
        messages = TicketMessage.objects.filter(ticket_id=ticket_id)
        serializer = TicketMessageModelSerializer(messages, many=True)
        return Response({'data': serializer.data}, status=status.HTTP_200_OK)


@api_view(['GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer'])
def get_new_ticket_messages(request, **kwargs):
    messages = TicketMessage.objects.filter(id__gt=request.query_params.get('message_id', None), ticket_id=request.query_params.get('ticket_id', None))
    serializer = TicketMessageModelSerializer(messages, many=True)
    return Response({'data': serializer.data}, status=status.HTTP_200_OK)


@api_view(['POST'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer'])
def delete_ticket_message(request, ticket_id, **kwargs):
    try:
        TicketMessage.objects.filter(uuid=ticket_id).delete()
        return Response({'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('change_ticket_status : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST', 'DELETE'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer', 'manager'])
def change_ticket_status(request, ticket_id=None, **kwargs):
    try:
        if request.method == 'DELETE':
            if kwargs.get('role') in ['admin', 'manager']:
                raise custom_exceptions.UserException(ref_strings.Common.invalid_user)                
            valid_ticket = SupportTicket.objects.filter(uuid=ticket_id, deleted=0).count()
            if not valid_ticket > 0:
                raise custom_exceptions.UserException(ref_strings.Common.ticket_not_found)
            deleted= SupportTicket.objects.filter(uuid=ticket_id, deleted=0).update(
                deleted=1, deleted_by=kwargs['user_id'], deleted_at=tz.localtime())

            if not deleted:
                raise custom_exceptions.UserException(ref_strings.Common.cannot_delete_ticket)


            return Response({'status': status.HTTP_200_OK, 'message': ref_strings.Common.ticket_deleted}, status=status.HTTP_200_OK)

        if request.method == 'POST':
            valid_ticket = SupportTicket.objects.filter(uuid=request.data.get('ticket_id', None), deleted=0).count()
            if not valid_ticket > 0:
                raise custom_exceptions.UserException(ref_strings.Common.ticket_not_found)

            SupportTicket.objects.filter(uuid=request.data.get('ticket_id', None)).update(status=request.data.get('status', None), modified_at=tz.localtime(), modified_by=kwargs['user_id'])

            return Response({'status': status.HTTP_200_OK, 'message': ref_strings.Common.ticket_status_update}, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('change_ticket_status : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
def ticket_status_options(request, **kwargs):
    try:
        from app.models import TICKET_STATUS
        data = [{category[1]: category[0]} for category in TICKET_STATUS]
        return Response({'data': data, 'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('support_ticket_category : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
def kyc_docs_type(requests,  **kwargs):
    try:
        from app.models import KYC_DOCUMENT_TYPE
        data = [{category[1]: category[0]} for category in KYC_DOCUMENT_TYPE]
        return Response({'data': data, 'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('support_ticket_category : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})



@api_view(['GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
def kyc_status(requests,  **kwargs):
    try:
        from app.models import KYC_STATUS
        data = [{category[1]: category[0]} for category in KYC_STATUS]
        return Response({'data': data, 'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('support_ticket_category : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['POST'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer'])
def upload_kyc(request,  **kwargs):
    try:

        util.obj_common.logger.msg_logger('kwargs :: {}'.format(kwargs))

        kyc = KYCManagement.objects.filter(user_id=kwargs.get('user_id'), rejected= False)
        if kyc:
            # if (kyc.filter(status='approve') or kyc.filter(status='pending')):
            raise custom_exceptions.UserException(ref_strings.Common.kyc_already_done)
        data = {x: request.POST.get(x) for x in request.POST.keys()}
        data['user_id'] = kwargs.get('user_id')

        for key in request.FILES.keys():
            img = request.FILES[key]
            data[key] = util.upload_kyc_file_bucket(img=img, digital_ocean=True)

        util.obj_common.logger.msg_logger('kyc data : {}'.format(data))
        kyc = KYCManagement.objects.create(**data)
        serializer = KYCManagementModelSerializer(kyc)
        notification = 'User has uploaded new kyc.'
        username = util.get_user_info_using_uuid(kwargs.get('user_id', None))
        add_notification('', notification, event='KYC', kyc_id=kyc.id, username=username)
        return Response({'status': status.HTTP_201_CREATED, 'data': serializer.data, 'message': ref_strings.Common.kyc_success},
                        status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('support_ticket_category : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer'])
def get_user_kyc(request,  **kwargs):
    try:
        try:
            kyc = KYCManagement.objects.get(user_id=kwargs.get('user_id'), rejected=False)
        except KYCManagement.DoesNotExist:
            raise custom_exceptions.UserException(ref_strings.Common.no_kyc_data)

        # kyc = KYCManagement.objects.get(user_id=kwargs.get('user_id'))
        serializer = KYCManagementModelSerializer(kyc)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('support_ticket_category : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(['GET'])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer'])
def get_customer_notifications(request, **kwargs):
    try:
        context = get_all_notifications(user_id=kwargs['user_id'], request=request)
        return Response(context, status=status.HTTP_200_OK)
    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('customer_notifications: %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(["POST"])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer'])
def notification_mark_as_read(request, **kwargs):
    try:
        notification = Notification.objects.get(id=request.data['id'])
        notification.is_read = True
        notification.save()
        return Response({'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)
    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('notification_mark_as_read : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


@api_view(["POST"])
@csrf_exempt
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['admin', 'customer'])
def notification_delete(request, **kwargs):
    try:
        notification = Notification.objects.get(id=request.data['id'])
        notification.is_deleted = True
        notification.save()
        return Response({'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)
    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('notification_is_deleted : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


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


@api_view(["GET"])
@csrf_exempt
def get_coins_list(request):
    try:
        responseData = {
            'data':[],
            'currency':[],
            'category': [],
        }
        current_page = str(request.query_params.get('currentpage', 1))
        per_page = str(request.query_params.get('perpage', 10))
        currency = request.query_params.get('currency', 'usd')
        order = request.query_params.get('order', 'market_cap_desc')
        price_change_percentage = request.query_params.get('pricechangepercentage', '1h')
        baseApiUrl = 'https://api.coingecko.com/api/v3/'
        pagination = {
            'currentPage' : current_page,
            'perPage' : per_page,
            'totalItems' : '250'
        }
        url = baseApiUrl+'coins/markets?vs_currency='+currency+'&order=market_cap_desc&per_page='+per_page+'&page='+current_page+'&price_change_percentage=1h'
        data = requests.get(url)
        if (data.status_code == 200):
            responseData['data'] = json.loads(data.text)
           
            url = baseApiUrl+'coins/categories/list'
            categoryData = requests.get(url)
            if categoryData.status_code == 200:
                responseData['category'] = json.loads(categoryData.text)
           
            url = baseApiUrl+'simple/supported_vs_currencies'
            vsCurrency = requests.get(url)
            if (vsCurrency.status_code == 200):
                responseData['currency']= json.loads(vsCurrency.text)
        
        responseData['pagination']= pagination
        responseData['status'] = 200
        responseData['sucess'] = True

        return Response(responseData, status=status.HTTP_200_OK)


    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('otp_qrcode : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id' : kwargs.get('request_id')})

    

# Investment Plans List API:-
@csrf_exempt
@api_view(['POST', 'GET'])
@util.obj_common.who_is_hitting
def get_investments_plans(request, **kwargs):
    try:

        if request.method == 'GET':
            # Create Logger
            util.obj_common.create_logger()

            #@pagination request
            current_page = int(request.GET.get('currentpage', 1))
            per_page = int(request.GET.get('perpage', 10))

            #@shorting and ordering request
            sort = request.GET.get('sort', 'asc')
            order = request.GET.get('order', 'created_at')

            order_dict = {
            'sort_by': sort,  ## key
            'order': order  ## asc dsc
            }
            pagination = {
                'current_page': current_page,
                'per_page': per_page
            }

            params = util.get_investment_plans_list(order_dict, pagination)
            return Response(params, status=status.HTTP_200_OK)
    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('get_investments_plans : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})

#@ Customer Select the Plans by uuid
@csrf_exempt
@api_view(['POST'])
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer'])
def select_plan(request, **kwargs):
    try:
        if request.method == 'POST':
            # Create Logger
            util.obj_common.create_logger()

            post_data = json.loads(request.body)

            plan_uuid = post_data.get('plan_id', '')

            #Check details of plan id
            util.obj_common.check_if_present(plan_uuid)

            #get id from uuid
            plan_id = util.check_paln_id_details(plan_uuid)

            #find user id from auth token
            user_id = kwargs['user_id']

            #check check_plan_is_exis_or not
            check_plans = util.check_plan_is_exis(user_id)

            if check_plans !=0:
                raise custom_exceptions.UserException(ref_strings.Common.plan_is_already)


            params = util.update_plan_id(user_id,plan_id)
            # params['request_id'] = kwargs['request_id']
            return Response(params, status=status.HTTP_200_OK)

    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id' : kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('select_plan : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id' : kwargs.get('request_id')})


# Investment get my plan details
@csrf_exempt
@api_view(['POST', 'GET'])
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer'])
def get_my_plan(request, **kwargs):
    try:

        if request.method == 'GET':
            # Create Logger
            util.obj_common.create_logger()

            #find user id from auth token
            user_id = kwargs['user_id']

            #check check_plan_is_exis_or not
            check_plans = util.check_plan_is_exis(user_id)
            print('**************', check_plans)

            if check_plans==0:
               raise custom_exceptions.UserException(ref_strings.Common.plan_is_not_selected)

            params = util.get_investment_my_plan_details(user_id)
            return Response(params, status=status.HTTP_200_OK)
    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('get_my_plan : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})


# Get Referral Link 
@csrf_exempt
@api_view(['POST', 'GET'])
@util.obj_common.who_is_hitting
@util.obj_common.validate_request(['customer'])
def generate_referral_token(request, **kwargs):
    try:
        if request.method == 'GET':
            # Create Logger
            util.obj_common.create_logger()

            #find user id from auth token and create refferal token
            user_id = kwargs['user_id']
            if user_id:
                params = util.generate_referral_token(user_id)

            return Response(params, status=status.HTTP_200_OK)
    except custom_exceptions.UserException as e:
        return util.obj_common.error_response({'message': str(e), 'request_id': kwargs.get('request_id')}, 400)

    except Exception as e:
        error = util.common_util.get_error_traceback(sys, e)
        util.obj_common.logger.error_logger('generate_referral_token : %s' % error)
        return util.obj_common.error_response({'message': ref_strings.Common.bad_request, 'request_id': kwargs.get('request_id')})