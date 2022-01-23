import sys, os
import pyotp
import time
from common_util import custom_exceptions, ref_strings, models , common_util
from . import models as custom_model


def get_unix_time():  # gives time in sec
    return int(time.time())


#for 2fa
def generate_otp_url(email):
    try:
        otp_secret = pyotp.random_base32()
        qr_code_str = pyotp.TOTP(otp_secret).provisioning_uri(email, issuer_name="B.I.S crypto wallet")
        return qr_code_str, otp_secret
    except Exception as e:
        raise


def verify_otp(otp_secret, user_otp):
    try:
        current_otp = pyotp.TOTP(otp_secret)
        print (current_otp.now())
        return current_otp.verify(user_otp)

    except Exception as e:
        raise


def changetodate(post_data={}):
    return (post_data.get("db_year")+"-"+post_data.get("db_month")+"-"+post_data.get("db_date"))


class TokenValidation:
    def __init__(self, logger, event_name=None, user_id=None):
        self.logger = logger
        self.event_name = event_name
        self.user_id = user_id
        self.table_name = ref_strings.Tables.token_verification
        self.otp = None
        self.token = None

    def generate_otp(self):
        valid = False
        otp = None
        while not valid:
            otp = common_util.generate_otp(int(common_util.config.get('common_settings','otp_len')))
            exist = models.find_sql(
                logger=self.logger, 
                table_name=self.table_name, 
                filters={
                    'otp' : otp
                }
            )
            if not exist:
                valid = True
        self.otp = otp
        return otp


    def generate_token(self):
        valid = False
        token = None
        while not valid:
            token = common_util.get_uuid()
            exist = models.find_sql(
                logger=self.logger, 
                table_name=self.table_name, 
                filters={
                    'token' : token
                }
            )
            if not exist:
                valid = True
        self.token = token
        return token


    def check_prior_request(self):
        try:
            query = '''SELECT * from token_verification where user_id = %s AND used = 0 AND deleted = 0 AND  expiry_time >= %s AND event = %s'''
            data_tuple = (self.user_id, common_util.get_unix_time(), self.event_name)

            prior_record = custom_model.execute_raw_query(self.logger, query, data_tuple)
            if not  prior_record:
                return False
            return True

        except Exception as e:
            error = common_util.get_error_traceback(sys, e)
            self.logger.error_logger('TokenValidation :check_prior_request : %s || %s'%(error, query))
            raise e


    def reset_prior_request(self):
        try:
            reset_status = models.update_sql(
                logger = self.logger, 
                table_name= self.table_name,
                update_data={
                    'deleted' : 1,
                }, 
                condition={
                    'user_id' : self.user_id, 
                    'event' : self.event_name
                }

            )
            if not reset_status: 
                raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

            return reset_status

        except custom_exceptions.UserException:
            raise 
        except Exception as e:
            error = common_util.get_error_traceback(sys, e)
            self.logger.error_logger('TokenValidation :check_prior_request : %s || %s'%(error, query))
            raise e


    def reset_valid_token(self,token, reset_uuid = False):
        try:
            reset_condition = {}
            if reset_uuid: 
                reset_condition = {
                    'uuid' : token
                }
            else: 
                reset_condition = {
                    'token' : token
                }                

            reset_status = models.update_sql(
                logger = self.logger, 
                table_name= self.table_name,
                update_data={
                    'used' : 1,
                }, 
                condition= reset_condition

            )
            if not reset_status: 
                raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

            return reset_status
            
        except custom_exceptions.UserException:
            raise 
        except Exception as e:
            error = common_util.get_error_traceback(sys, e)
            self.logger.error_logger('reset_valid_token :: %s >>'%(error))
            raise e

    def create_token_validation_object(self):
        try:
            prior_request = self.check_prior_request()
            if prior_request:
                self.reset_prior_request()
            db_status = models.insert_sql(
                logger = self.logger, 
                table_name=ref_strings.Tables.token_verification, 
                insert_data={
                    'uuid' : common_util.get_uuid(),
                    'user_id' : self.user_id,
                    'token' : self.generate_token(),
                    'otp' : self.generate_otp(),
                    'expiry_time' : common_util.get_unix_time() + float(common_util.config.get('common_settings','token_expiry_time_hr'))* 60 * 60,
                    'created_on' : common_util.get_unix_time(),
                    'event': self.event_name
                }
            )
            if not db_status: 
                raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

            return self.otp, self.token
            
        except custom_exceptions.UserException:
            raise 
        except Exception as e:
            error = common_util.get_error_traceback(sys, e)
            self.logger.error_logger('TokenValidation :check_prior_request : %s '%(error))
            raise e


    @classmethod
    def validate_token(cls, logger, token, validate_uuid=False):
        try:
            query = ''
            if validate_uuid:
                query = '''SELECT * from token_verification where uuid = %s AND used = 0 AND deleted = 0 AND  expiry_time >= %s '''
            else: 
                query = '''SELECT * from token_verification where token = %s AND used = 0 AND deleted = 0 AND  expiry_time >= %s '''
            
            data_tuple = (token, common_util.get_unix_time())

            valid_token = custom_model.execute_raw_query(logger, query, data_tuple)
            if not valid_token: 
                raise custom_exceptions.UserException(ref_strings.Common.invalid_token)
            token_info = valid_token[0]
            
            return token_info

        except custom_exceptions.UserException:
            raise 
        except Exception as e:
            error = common_util.get_error_traceback(sys, e)
            logger.error_logger('TokenValidation :check_prior_request : %s '%(error))
            raise e



class EmailTemplates:

    def __init__(self, logger): 
        self.email_url = common_util.config.get('email_service','email_link') ##sendin blue
        self.logger = logger

    @staticmethod
    def get_sendInBlue_payload(reciver_email, template_id, params_dict):
        reply_email= common_util.config.get('email_service','replyEmail')
        sender_email = common_util.config.get('email_service','sender_email')
        api_key = common_util.config.get('email_service', 'access_key')

        payload = {
            "sender": {
                "email": sender_email
            },
            "to": [
                {
                    "email": reciver_email
                }
            ],
            "templateId": template_id,
            "params" : params_dict,
            "replyTo": {
                "email": reply_email,
                "name": "BTC wallet Admin"
            }
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "api-key": api_key
        }
        return payload, headers

    @classmethod
    def forgot_password_email(cls, token, user_email):
        template_id = 7
        reset_link = common_util.config.get('email_service','forgot_password_link')+token
        params_dict = {
            'email' : user_email, 
            'Link' : reset_link
        }
        payload, header = cls.get_sendInBlue_payload(user_email, template_id, params_dict)
        return payload, header

    @classmethod
    def account_verification(cls, token, user_email):
        template_id = 6
        reset_link = common_util.config.get('email_service','email_confirmation_link')+token
        params_dict = {
            'email': user_email,
            'Link': reset_link
        }
        payload, header = cls.get_sendInBlue_payload(user_email, template_id, params_dict)
        return payload, header


    def send_email(self, payload, headers):
        try:
            import requests
            response = requests.request("POST", self.email_url, json=payload, headers=headers)
            print (response.text)
            if not response.status_code == 201: 
                raise custom_exceptions.UserException(ref_strings.Common.forgot_password_fail_email)

        except custom_exceptions.UserException:
            raise 
        except Exception as e:
            error = common_util.get_error_traceback(sys, e)
            self.logger.error_logger('EmailTemplates :send_email : %s '%(error))
            raise e

