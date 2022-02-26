import sys, datetime , jwt, time

from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage

from common_util import common_util, ref_strings, custom_exceptions, models, redis_helper, logger, redis_helper, encryption
from . import common_helper, models as custom_model
from django.core.files.storage import FileSystemStorage 
from common_util import email_verification, jwt_operation
import boto3

obj_common = common_util.CommonUtil(log='common_logs')


def get_jwt_token(logger, email):
    try:
        data = redis_helper.get_key(logger, email)
        return data
    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise        


def get_jwt_info(logger, email):
    jwt = get_jwt_token(email =email)
    decoded_token = jwt.decode(request_jwt, self.jwt_secret, algorithm=[self.jwt_algorithm])
    print (decoded_token)


def make_jwt_operation(email, user_role, user_id):
    try: 
        jwt_payload = {
            'email' : email,
            'role' : user_role,
            'user_id' : user_id
        }
        headers = {'timestamp': str(datetime.datetime.now())}
        encoded_jwt = jwt.encode(
            jwt_payload,
            obj_common.jwt_secret,
            algorithm= obj_common.jwt_algorithm,
            headers= headers
        )
        encoded_jwt = encoded_jwt.decode("utf-8")
        redis_status = redis_helper.setex(
            obj_common.logger,
            email,
            encoded_jwt,
            common_util.config.get('jwt', 'timeout')
        )
        if not redis_status:
            raise custom_exceptions.UserException(ref_strings.Common.bad_request)

        return encoded_jwt

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise


def login(email, password):
    try:
        obj_common.create_logger()

        data = {
            'email': email,
            'password': encryption.get_hash(password),
            'deleted': 0
        }

        db_check = models.find_sql(obj_common.logger, ref_strings.Tables.user_master, data)
        if not db_check:
            raise custom_exceptions.UserException(ref_strings.Common.invalid_credentials)

        db_check = db_check[0] 
        if not db_check.get('verified') == 1:
            raise custom_exceptions.UserException(ref_strings.Common.verify_email)

        user_id = db_check.get('uuid')
        obj_common.logger.msg_logger('Creating session for: user :{}, full data :{} '.format(user_id, db_check))
        role = models.find_sql(obj_common.logger, ref_strings.Tables.role, {'id': db_check.get('role_id')})
        if not role:
            raise custom_exceptions.UserException(ref_strings.Common.role_not_defined)
       
        user_role = role[0].get('role')

        jwt_payload = {
            'email': email,
            'role': user_role,
            'user_id': user_id
        }
        headers = {'timestamp': str(datetime.datetime.now())}
        encoded_jwt = jwt.encode(
            jwt_payload,
            obj_common.jwt_secret,
            algorithm= obj_common.jwt_algorithm,
            headers= headers
        )
        encoded_jwt = encoded_jwt.decode("utf-8")
        redis_status = redis_helper.setex(
            obj_common.logger,
            encoded_jwt,
            jwt_payload,
            common_util.get_config().get('jwt', 'timeout')
        )
        if not redis_status:
            raise custom_exceptions.UserException(ref_strings.Common.bad_request)

        multi_factor_auth_status = models.find_sql(obj_common.logger, ref_strings.Tables.otp_detail, {'email': email, 'otp_status': True})
        
        multi_factor_auth_status = True if multi_factor_auth_status or len(multi_factor_auth_status) > 0 else False

        return_data = {
            'token' : encoded_jwt,
            'userInfo' : {
            'email' : email,
            'multi_factor_auth_enable' : multi_factor_auth_status,
            'user_id' : user_id,
            'role' : user_role, 
            'user_name' : db_check.get('username', 'NA')
            },
            'message' : ref_strings.Common.login_sucess
        }
        return return_data

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise


def signup(email, password, username):
    try:
        obj_common.create_logger()

        # check if email exisit
        email_exist = models.find_sql(
            obj_common.logger, 
            ref_strings.Tables.user_master,
            {'email' : email}
        )
        if email_exist:
            raise custom_exceptions.UserException(ref_strings.Common.duplicate_login)


        user_id = common_util.get_uuid()
        insert_data = {
            'email' : email,
            'password' : encryption.get_hash(password),
            'role_id' : ref_strings.RoleId.customer,
            'uuid' : user_id,
            'username' : username
        }

        db_status = models.insert_sql(
            obj_common.logger,
            ref_strings.Tables.user_master,
            insert_data
        )
        if not db_status:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

        return create_email_verification(user_id, email, username)

 
    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise



def create_email_verification(user_id, email, name):
    try:
        obj_common.create_logger()

        data_exist = models.find_sql(
            obj_common.logger,
            table_name=ref_strings.Tables.token_verification, 
            filters={
                'user_id': user_id,
                'used': 0,
                'event': ref_strings.TokenValidationRefString.account_verification,
                'deleted' : 0
            }
        )
        if data_exist:
            db_data = models.update_sql(
                obj_common.logger,
                table_name=ref_strings.Tables.token_verification,
                update_data={
                    'deleted' : 1,
                    'used': 1
                },
                condition= {
                    'user_id' : user_id, 
                    'token' : data_exist[0].get('token')
                }
            )
            if not db_data: 
                raise custom_exceptions.UserException(ref_strings.Common.unable_to_validate_email)


        db_data = {
            'uuid' : common_util.get_uuid(),
            'user_id' : user_id,
            'token' : common_util.get_uuid(),
            'otp' : common_util.generate_otp(int(common_util.config.get('common_settings','otp_len'))) ,
            'expiry_time' : common_util.get_unix_time() + int(common_util.config.get('common_settings','token_expiry_time_hr'))* 60 * 60,
            'event': ref_strings.TokenValidationRefString.account_verification
        }
        db_status = models.insert_sql(
            obj_common.logger,
            table_name=ref_strings.Tables.token_verification,
            insert_data= db_data
        )
        if not db_status:
            raise custom_exceptions.UserException(ref_strings.Common.unable_to_validate_email)

        # link = common_util.config.get('email_service','email_confirmation_link')+ db_data.get('token')

        # send_signup_email(email, name , link)
        # return {}
        return {}

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise
        

def send_signup_email(email, name, link):
    try: 
        import requests

        url = common_util.config.get('email_service','email_link')
        payload = {
            "sender": {
                "email": common_util.config.get('email_service','sender_email')
            },
            "to": [
                {
                    "name": name,
                    "email": email
                }
            ],
            "templateId": 6,
            "params" : {
                "email" : email,
                "Link" : link
            },
            "replyTo": {
                "email": common_util.config.get('email_service','replyEmail'),
                "name": ""
            }
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "api-key": common_util.config.get('email_service', 'access_key')
        }

        response = requests.request("POST", url, json=payload, headers=headers)

        print(response.text)

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise



def logout(email):
    try:
        obj_common.create_logger()

        logout_status = redis_helper.del_key(email)

        if not logout_status:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)
        
        return {}

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise


def enable_2fa(email, reenable=False):
    try:
        obj_common.create_logger()

        otp_exist = models.find_sql(
            obj_common.logger,
            ref_strings.Tables.otp_detail,
            {'email' : email}
        )
        
        if len(otp_exist) > 0:
            otp_exist = otp_exist[0]
            return {'email' : email, 'otp_url': otp_exist.get('otp_url'), 'message' : ref_strings.Common.otp_reenalbe}

        otp_url, otp_secret = common_helper.generate_otp_url(email)
                
        if reenable:
            db_status = models.update_sql(
                obj_common.logger,
                ref_strings.Tables.otp_detail,
                update_data = {
                    'otp_secret' : otp_secret,
                    'otp_status' : True,
                    'otp_url' : otp_url
                },
                condition= {
                    'email': email,
                    'otp_status' : False
                }
            )
        else:
            db_status = models.insert_sql(
                obj_common.logger,
                ref_strings.Tables.otp_detail,
                insert_data = {
                    'email' : email,
                    'otp_secret' : otp_secret,
                    'otp_status' : False,
                    'otp_url' : otp_url
                }
            )

        if not db_status:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)
        
        return {'email': email, 'otp_url' : otp_url, 'message': ref_strings.Common.two_fa_sucess}

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise


def verify_otp(email, otp):
    try:
        obj_common.create_logger()

        otp_status_check = models.find_sql(
            obj_common.logger,
            ref_strings.Tables.otp_detail,
            {'email' : email}
        )
        if not otp_status_check:
            raise custom_exceptions.UserException(ref_strings.Common.two_fa_not_activated)
        
        otp_secret = otp_status_check[0].get('otp_secret')
        
        valid_otp = common_helper.verify_otp(otp_secret, otp)

        if(not valid_otp):
            raise custom_exceptions.UserException(ref_strings.Common.two_fa_invalid)

        otp_status = otp_status_check[0]
        otp_status = otp_status.get('otp_status')

        if otp_status == 0:    
            update_otp_status = models.update_sql(obj_common.logger, ref_strings.Tables.otp_detail,
                    {
                        'otp_status': True
                    },
                    {
                        'email': email,
                        'otp_status': False
                    }
                )
            if not update_otp_status:
                raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)
            
        return {'otp_status': True}

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise


def disable_2fa(email, otp=None, admin_call=None):
    try:
        obj_common.create_logger()

        if not admin_call:  # if admin is not disabling than its user who is doing so , so verify otp
            if not otp:
                raise custom_exceptions.UserException(ref_strings.Common.enter_otp)
            verify_otp(email, otp)

        db_update = models.update_sql(
            obj_common.logger, 
            ref_strings.Tables.otp_detail, 
            update_data= {
                'otp_status': False
            },
            condition={
                'email': email
            }
        )
        if not db_update:
            raise custom_exceptions.UserException(ref_strings.Common.two_fa_invalid)
        
        return {'message' : 'Otp Disabled'}
    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise


def get_role(email):
    try:
        user_detail = models.find_sql(obj_common.logger, ref_strings.Tables.user_master, {'email': email})[0]

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise


def multifactor_login(email, otp, is_admin):
    try:
        obj_common.create_logger()

        verify_otp(email, otp)

        user_info = custom_model.get_multifactor_login_details(obj_common.logger,  email, is_admin)[0]
        user_info.update({
            'multi_factor_auth_enable': True
        })
        obj_common.logger.error_logger(user_info)

        encoded_jwt = jwt_operation.make_jwt_operation(
            logger=obj_common.logger,
            email=email,
            user_role=user_info.get('role'),
            user_id=user_info.get('uuid')
        )

        return_data = {
            'userInfo' : user_info,
            'message' : ref_strings.Common.login_sucess,
            'token': encoded_jwt
        }

        return return_data
    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise
 


def changetodate(db_year, db_month, db_date):
    return db_year+"-"+db_month+"-"+db_date


def changepw(email, oldpassword, newpassword):
    try:
        obj_common.create_logger()
        
        data = {
            'email': email,
            'password': encryption.get_hash(oldpassword)
        }

        db_check = models.find_sql(obj_common.logger, ref_strings.Tables.user_master, data)
        if not db_check:
            raise custom_exceptions.UserException(ref_strings.Common.invalid_credentials)
        
        updated_data = {
            'email': email,
            'password': encryption.get_hash(newpassword)
        }

        db_status = models.update_sql(
            logger = obj_common.logger, 
            table_name = ref_strings.Tables.user_master, 
            update_data = updated_data, 
            condition = data
            )
        if not db_status:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

        returnData={
            'userInfo' : {
                'email' : email
                },
            'message':ref_strings.Common.password_changed
        }
        return returnData

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger('changepw %s' %error)
        raise



def email_verification(token):
    try:
        obj_common.create_logger()
        token_status = models.find_sql(
            logger = obj_common.logger,
            table_name= ref_strings.Tables.token_verification, 
            filters={
                'token' : token, 
                'used' : 0, 
                'deleted' : 0
            }
        )
        if not token_status:
            raise custom_exceptions.UserException(ref_strings.Common.invalid_token)



        delete_token_status = models.update_sql(
                logger=obj_common.logger, 
                table_name=ref_strings.Tables.token_verification, 
                update_data={
                    'used' : 1,
                    'deleted' : 1
                }, 
                condition={
                    'token' : token
                }
            )

        if not (token_status[0].get('event') ==  ref_strings.TokenValidationRefString.account_verification):
            raise custom_exceptions.UserException(ref_strings.Common.invalid_token)

        if (token_status[0].get('expiry_time') < common_util.get_unix_time()):
            raise custom_exceptions.UserException(ref_strings.Common.token_expired)

        user_id = token_status[0].get('user_id')

        #make user email verifeid in user master
        verified_status = models.update_sql(
            logger= obj_common.logger,
            table_name=ref_strings.Tables.user_master,
            update_data={
                "verified" : True
            },
            condition={
                "uuid" : user_id
            }
        )
        if not verified_status:
            raise custom_exceptions.UserException(ref_strings.Common.unable_to_verify_email)
        
        user_detail = models.find_sql(
            logger = obj_common.logger,
            table_name= ref_strings.Tables.user_master, 
            filters={
                'uuid' : user_id
            }
        )
        if not user_detail: 
            raise custom_exceptions.UserException(ref_strings.Common.invalid_user)
        user_email = user_detail[0].get('email')
        role = models.find_sql(obj_common.logger, ref_strings.Tables.role, {'id' : user_detail[0].get('role_id')})
        if not role:
            raise custom_exceptions.UserException(ref_strings.Common.role_not_defined)
       
        user_role =  role[0].get('role')
        encoded_jwt = make_jwt_operation(user_email, user_role, user_id)
        
        multi_factor_auth_status = models.find_sql(obj_common.logger, ref_strings.Tables.otp_detail, {'email': user_email, 'otp_status': True})
        
        multi_factor_auth_status = True if multi_factor_auth_status or len(multi_factor_auth_status) > 0 else False

        return_data = {
            'token' : encoded_jwt,
            'userInfo' : {
            'email' : user_email,
            'multi_factor_auth_enable' : multi_factor_auth_status,
            'user_id' : user_id,
            'role' : user_role
            },
            'message' : ref_strings.Common.login_sucess
        }
        return return_data
        

    except custom_exceptions.UserException:
        raise 
    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger('email_verification %s' %error)
        raise


def forget_password(email):
    try:
        obj_common.create_logger()
        
        email_exist = models.find_sql(
            logger=obj_common.logger,
            table_name=ref_strings.Tables.user_master,
            filters={
                'email': email,
                'deleted': 0
            }
        )
        if not email_exist:
            raise custom_exceptions.UserException(ref_strings.Common.invalid_email)
        
        email_exist = email_exist[0]
    
        token_validation_obj = common_helper.TokenValidation(
            logger = obj_common.logger, 
            event_name = ref_strings.TokenValidationRefString.forgot_password,
            user_id = email_exist.get('uuid')
        )

        otp, token = token_validation_obj.create_token_validation_object()
        if not token:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

        #email process
        payload, headers = common_helper.EmailTemplates.forgot_password_email(token, email_exist.get('email'))        
        email_obj= common_helper.EmailTemplates(obj_common.logger)
        email_obj.send_email(payload, headers)

        return {
            'message' : ref_strings.Common.forgot_password_email
        }

    except custom_exceptions.UserException:
        raise 
    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger('email_verification %s' %error)
        raise


def reset_password(token, new_password, confirm_password):
    try:

        valid_token = common_helper.TokenValidation.validate_token(obj_common.logger, token, validate_uuid=True)

        event_name= valid_token.get('event')
        user_id = valid_token.get('user_id')

        if event_name != ref_strings.TokenValidationRefString.forgot_password: 
            raise custom_exceptions.UserException(ref_strings.Common.invalid_token)

        if not new_password == confirm_password:
            raise custom_exceptions.UserException(ref_strings.Common.password_mismatch)

        token_validation_obj = common_helper.TokenValidation(obj_common.logger, event_name)
        token_validation_obj.reset_valid_token(token = token, reset_uuid=True)

        password = encryption.get_hash(new_password)

        update_pw = models.update_sql(
            logger=obj_common.logger, 
            table_name=ref_strings.Tables.user_master,
            update_data={
                'password' : password, 
                'modified_at' : common_util.get_unix_time()
            },
            condition={
                'uuid': user_id
            }
        )
        if not update_pw:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)
        return {
            'message' : ref_strings.Common.password_rest_sucessfully
        }

    except custom_exceptions.UserException:
        raise 
    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger('reset password %s' %error)
        raise
 

def token_validation(token):
    try:
        obj_common.create_logger()
        
        valid_token = common_helper.TokenValidation.validate_token(obj_common.logger, token)

        if not valid_token:
            raise custom_exceptions.UserException(ref_strings.Common.invalid_token)

        token_event= valid_token.get('event')
        uuid = valid_token.get('uuid')


        return {
            'new_token' : uuid,
            'event' : token_event
        }

    except custom_exceptions.UserException:
        raise 
    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger('token_validation %s' %error)
        raise




def contact_us(name, email, subject, message):
    try:
        obj_common.create_logger()

        db_insert = models.insert_sql(
            logger= obj_common.logger,
            table_name=ref_strings.Tables.contact_us,
            insert_data={
                'uuid' : common_util.get_uuid(),
                'email' : email,
                'name' : name,
                'subject' : subject,
                'message' : message
            }
        )
        if not db_insert:
            raise custom_exceptions.UserException(ref_strings.Common.operation_failed)

        return {'message' : ref_strings.Common.contact_us_sucess}


    except custom_exceptions.UserException:
        raise 
    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger('contact us %s' %error)
        raise


def get_user_info_using_uuid(uuid):
    try:
        obj_common.create_logger()

        user_info = models.find_sql(
            logger=obj_common.logger,
            table_name=ref_strings.Tables.user_master,
            filters={
                'uuid': uuid,

            }
        )
        if not user_info:
            raise custom_exceptions.UserException(ref_strings.Common.user_not_found)

        user_info = user_info[0]

        return user_info['username']

    except custom_exceptions.UserException:
        raise
    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger('get_user_info_using_uuid %s' % error)
        print(error)
        raise


def resend_email(email, event_name):
    try:
        obj_common.create_logger()

        email_exist = models.find_sql(
            logger=obj_common.logger,
            table_name=ref_strings.Tables.user_master,
            filters={
                'email': email,
                'deleted': 0
            }
        )
        if not email_exist:
            raise custom_exceptions.UserException(ref_strings.Common.invalid_email)

        email_exist = email_exist[0]

        token_validation_obj = common_helper.TokenValidation(
            logger=obj_common.logger,
            event_name=event_name,
            user_id=email_exist.get('uuid')
        )

        otp, token = token_validation_obj.create_token_validation_object()
        if not token:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

        #email process
        if event_name == ref_strings.TokenValidationRefString.account_verification:
            payload, headers = common_helper.EmailTemplates.account_verification(token, email_exist.get('email'))
        elif event_name == ref_strings.TokenValidationRefString.forgot_password:
            payload, headers = common_helper.EmailTemplates.forgot_password_email(token, email_exist.get('email'))
        email_obj=common_helper.EmailTemplates(obj_common.logger)
        email_obj.send_email(payload, headers)

        return {
            'message': ref_strings.Common.email_sent_successfully
        }


    except custom_exceptions.UserException:
        raise
    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger('resend_email %s' % error)
        print(error)
        raise