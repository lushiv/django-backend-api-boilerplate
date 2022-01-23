from . import logger, ref_strings, models, custom_exceptions, redis_helper
import configparser, requests, json, jwt, uuid, os, sys
import json
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework import status
import time
from random import randint

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
conf_file_path = BASE_DIR + '/configuration.ini'

config = configparser.RawConfigParser()
config.read(conf_file_path)


def generate_otp(len):
    range_start = 10 ** (len - 1)
    range_end = (10 ** len) - 1
    return randint(range_start, range_end)


def get_uuid():
    return str(uuid.uuid4().hex)


def get_unix_time():
    return int(time.time())


def get_config():
    return config


def get_jwt_key(user_id, email):
    return "%s_%s" % (user_id, email)


def get_error_traceback(sys, e):
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    return "%s || %s || %s || %s" % (exc_type, fname, exc_tb.tb_lineno, e)


def lowrcase(text_):
    """
    For Lower Case Email
    :param email: any email
    :return: lower case of email
    """
    return text_.lower()


class CommonUtil:

    def __init__(self, log):
        self.logger = None
        self.log = log if not (log == 'webhook_logs') else 'webhook_logs'
        self.config = config
        self.jwt_secret = config.get('jwt', 'jwt_secret')
        self.jwt_algorithm = config.get('jwt', 'jwt_algorithm')
        self.logs_directory = config.get(self.log, 'path')
        self.category = config.get(self.log, 'category')

    def create_logger(self):
        self.logs_directory, self.category = config.get(self.log, 'path'), config.get(self.log, 'category')
        self.logger = logger.MyLogger(self.logs_directory, self.category)

    @staticmethod
    def new_success_response(params={}):
        return_data = {}
        return_data['status'] = 200
        return_data['sucess'] = True
        return_data['message'] = params.get('message', '')
        return_data.update(params)
        return Response(return_data, status=status.HTTP_200_OK)

    @staticmethod
    def success_response(params={}):
        return_data = {}
        return_data['status'] = 200
        return_data['sucess'] = True
        return_data['message'] = params.get('message', '')
        return_data['data'] = params
        return Response(return_data, status=status.HTTP_200_OK)

    @staticmethod
    def error_response(params={}, status_code=None):
        params['sucess'] = False
        if not status_code:
            params['status'] = 500
            return Response(params, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            params['status'] = status_code
            return Response(params, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def check_if_present(*args, **kwargs):
        """
        For Server Side Checks
        """
        # print (args)
        if not all(arg for arg in args):
            raise custom_exceptions.UserException(ref_strings.Common.missing_input_params)

        if not all(val for key, val in kwargs.items()):
            raise custom_exceptions.UserException(ref_strings.Common.missing_input_params)

    def get_client_ip(self, request):
        """
        To Get Client IP
        """
        try:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')
            return ip
        except Exception as e:
            self.logger.error_logger('get_client_ip : %s' % e)

    def who_is_hitting(self, func):
        """
        Decorator : To check who is hitting the end points
        """

        def who(*args, **kwargs):
            try:
                request_id = str(get_uuid())
                kwargs['request_id'] = request_id
                # Create Logger
                self.create_logger()

                # Before
                request = args[0]
                ip = self.get_client_ip(request)
                url = request.build_absolute_uri()

                type = request.method
                header = request.META.get('HTTP_AUTHORIZATION', '')
                body = ''

                if request.method == 'POST':

                    # To handle json and form data request
                    if request.content_type == 'multipart/form-data' or (request.content_type.split(';'))[
                        0] == 'multipart/form-data':
                        for key, value in request.POST.items():
                            body += key + " = " + str(value) + ", "
                    else:
                        post_data = json.loads(request.body)

                        for key, value in post_data.items():
                            body += key + " = " + str(value) + ", "

                elif request.method == 'GET':

                    # To handle json and form data request
                    if request.content_type == 'multipart/form-data' or (request.content_type.split(';'))[
                        0] == 'multipart/form-data':
                        for key, value in request.GET.items():
                            body += key + " = " + str(value) + ", "
                    else:
                        get_data = request.query_params
                        get_data = dict(get_data.items())
                        for key, value in get_data.items():
                            body += key + " = " + str(value) + ", "

                # body = body[:500]
                self.logger.msg_logger('REQUEST >>>>>>>>>>>>>>>>> \n%s' % body)

                # Main
                response_data = func(*args, **kwargs)
                if not request.method == 'GET':
                    response_data_str = str(response_data.data)
                    self.logger.msg_logger('RESPONSE >>>>>>>>>>>>>>>>> \n%s' % response_data_str)
                else:
                    self.logger.msg_logger('RESPONSE >>>>>>>>>>>>>>>>> \n%s' % response_data)

                return response_data
            except Exception as e:
                error = get_error_traceback(sys, e)
                self.logger.error_logger('who_is_hitting : %s' % error)
                return self.error_response({'msg': ref_strings.Common.bad_request, 'request_id': 'N/A'})

        return who

    def validate_request(self, roles):
        """
        Decorator : Validate user
        :param func:
        :return:
        """

        def validate_user_1(func):

            def validate_user_2(*args, **kwargs):
                try:

                    # Create Logger
                    self.create_logger()

                    request = args[0]
                    request_jwt = request.META.get('HTTP_AUTHORIZATION', '')

                    try:
                        decoded_token = self.decode_jwt(request_jwt)

                    except:
                        raise custom_exceptions.UserException(ref_strings.Common.invalid_jwt)

                    if request.content_type == 'multipart/form-data' or (request.content_type.split(';'))[
                        0] == 'multipart/form-data':
                        if request.method == 'POST':
                            pass
                        else:
                            pass
                    else:
                        if request.method == 'POST':
                            post_data = json.loads(request.body)
                            # email = post_data.get('email','')
                        if request.method == 'DELETE' and 'logout' in request._request.path.split('/'):
                            email = decoded_token.get('email', 'NA')
                            flush_token = redis_helper.del_key(request_jwt)
                            if not flush_token:
                                raise custom_exceptions.UserException(ref_strings.Common.redis_error)
                            return CommonUtil.success_response({})

                    kwargs['email'] = decoded_token.get('email')
                    kwargs['user_id'] = decoded_token.get('user_id')
                    kwargs['role'] = decoded_token.get('role')

                    # Server Side Checks
                    self.check_if_present(request_jwt)

                    # get jwt from Redis
                    # jwt_key = get_jwt_key(email)
                    jwt_valid = redis_helper.get_key(self.logger, request_jwt)

                    if not jwt_valid:
                        return Response({'msg': ref_strings.Common.invalid_user}, status=status.HTTP_401_UNAUTHORIZED)

                    decoded_token = jwt.decode(request_jwt, self.jwt_secret, algorithm=[self.jwt_algorithm])

                    # # Get User Role from JWT
                    user_role_jwt = decoded_token.get('role')
                    user_sub_role_jwt = decoded_token.get('sub_role', False)  # TODO :  implement subrole function

                    # Check Roles
                    if user_role_jwt in roles or user_role_jwt == 'superadmin':
                        valid_role = True
                    else:
                        valid_role = False

                    # JWT Validation
                    if request_jwt and valid_role:
                        # Reset JWT Time Out
                        redis_helper.setex(self.logger, request_jwt, str(decoded_token),
                                           get_config().get('jwt', 'timeout'))
                        return func(*args, **kwargs)
                    else:
                        return Response({'message': ref_strings.Common.invalid_user},
                                        status=status.HTTP_401_UNAUTHORIZED)


                except custom_exceptions.UserException as e:
                    return self.error_response({'message': str(e)}, 400)

                except Exception as e:
                    error = get_error_traceback(sys, e)
                    self.logger.error_logger('validate_user : %s' % error)
                    return self.error_response({'message': ref_strings.Common.internal_server_error})

            return validate_user_2

        return validate_user_1

    def decode_jwt(self, request_jwt):
        return jwt.decode(request_jwt, self.jwt_secret, algorithm=[self.jwt_algorithm])
